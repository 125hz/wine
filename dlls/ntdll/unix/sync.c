/*
 * Process synchronisation
 *
 * Copyright 1996, 1997, 1998 Marcus Meissner
 * Copyright 1997, 1999 Alexandre Julliard
 * Copyright 1999, 2000 Juergen Schmied
 * Copyright 2003 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#include <sys/time.h>
#include <poll.h>
#include <unistd.h>
#ifdef HAVE_SCHED_H
# include <sched.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
# include <mach/mach_time.h>
# include <mach/mach.h>
# include <mach/mach_vm.h>
#endif
#ifdef HAVE_KQUEUE
# include <sys/event.h>
#endif
#ifdef HAVE_LINUX_NTSYNC_H
# include <linux/ntsync.h>
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/server.h"
#include "wine/debug.h"
#include "unix_private.h"

/* iOS-Madeira ml950: the [srv-stats] counter block (build/ntdll-unix/shims).
 * Everything it declares is a relaxed atomic add on a plain array; on any
 * other target the calls compile to nothing at all. */
#ifdef WINE_IOS
# include "ios_srv_stats.h"
/* ml970: the spin governor's streak / time-to-progress histogram, printed
 * by [srv-stats] in build/ntdll-unix/server_ios.c. */
# include "ios_spin_hist.h"
/* ml1050: the [frame] critical-path instrument.  This file is one of its two
 * producers: it is the only place that knows how long the PRESENTING thread
 * was blocked and on what.  Everything it contributes is gated behind the
 * inline ios_frame_tracking() predicate, which is a register read and a
 * compare on every other thread. */
# include "ios_frame_stats.h"
#else
# define ios_srv_nt_count(which) ((void)0)
# define ios_frame_tracking() 0
# define ios_frame_wait_add(kind, ns) ((void)0)
# define IOS_FRAME_WAIT_FAST 0
# define IOS_FRAME_WAIT_SLEEP 0
# define IOS_SPIN_HIST_N 16
struct ios_spin_snapshot
{
    unsigned int calls[IOS_SPIN_HIST_N], us[IOS_SPIN_HIST_N];
    unsigned int streaks, gov_sleep0, gov_yield, sys_yield, sys_park;
    unsigned int us_p50, us_p80, warm_hits;
};
#endif

WINE_DEFAULT_DEBUG_CHANNEL(sync);

HANDLE keyed_event = 0;
int inproc_device_fd = -1;

static const char *debugstr_timeout( const LARGE_INTEGER *timeout )
{
    if (!timeout) return "(infinite)";
    return wine_dbg_sprintf( "%lld.%07ld", (long long)(timeout->QuadPart / TICKSPERSEC),
                             (long)(timeout->QuadPart % TICKSPERSEC) );
}


/* return a monotonic time counter, in Win32 ticks */
static inline ULONGLONG monotonic_counter(void)
{
    struct timeval now;
#ifdef __APPLE__
    static mach_timebase_info_data_t timebase;

    if (!timebase.denom) mach_timebase_info( &timebase );
    return mach_continuous_time() * timebase.numer / timebase.denom / 100;
#elif defined(HAVE_CLOCK_GETTIME)
    struct timespec ts;
#ifdef CLOCK_BOOTTIME
    if (!clock_gettime( CLOCK_BOOTTIME, &ts ))
        return ts.tv_sec * (ULONGLONG)TICKSPERSEC + ts.tv_nsec / 100;
#endif
    if (!clock_gettime( CLOCK_MONOTONIC, &ts ))
        return ts.tv_sec * (ULONGLONG)TICKSPERSEC + ts.tv_nsec / 100;
#endif
    gettimeofday( &now, 0 );
    return ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10 - server_start_time;
}

#ifdef __linux__

#define USE_FUTEX

#include <linux/futex.h>

static inline int futex_wait( const LONG *addr, int val, struct timespec *timeout )
{
#if (defined(__i386__) || defined(__arm__)) && _TIME_BITS==64
    if (timeout && sizeof(*timeout) != 8)
    {
        struct {
            long tv_sec;
            long tv_nsec;
        } timeout32 = { timeout->tv_sec, timeout->tv_nsec };

        return syscall( __NR_futex, addr, FUTEX_WAIT_PRIVATE, val, &timeout32, 0, 0 );
    }
#endif
    return syscall( __NR_futex, addr, FUTEX_WAIT_PRIVATE, val, timeout, 0, 0 );
}

static inline int futex_wake_one( const LONG *addr )
{
    return syscall( __NR_futex, addr, FUTEX_WAKE_PRIVATE, 1, NULL, 0, 0 );
}

#elif defined(__APPLE__)

#define USE_FUTEX

#include <AvailabilityMacros.h>

#ifdef MAC_OS_VERSION_14_4
#include <os/os_sync_wait_on_address.h>
#endif

#define UL_COMPARE_AND_WAIT 1

extern int __ulock_wait( uint32_t operation, void *addr, uint64_t value, uint32_t timeout );

extern int __ulock_wake( uint32_t operation, void *addr, uint64_t wake_value );

static inline int futex_wait( const LONG *addr, int val, struct timespec *timeout )
{
#ifdef MAC_OS_VERSION_14_4
    if (__builtin_available( macOS 14.4, * ))
    {
        /* 18446744073 seconds could overflow a uint64_t in nanoseconds */
        if (timeout && timeout->tv_sec < 18446744073)
        {
            uint64_t ns_timeout = (timeout->tv_sec * 1000000000) + timeout->tv_nsec;

            if (!ns_timeout)
            {
                errno = ETIMEDOUT;
                return -1;
            }
            return os_sync_wait_on_address_with_timeout( (void *)addr, (uint64_t)val, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                                         OS_CLOCK_MACH_ABSOLUTE_TIME, ns_timeout );
        }

        return os_sync_wait_on_address( (void *)addr, (uint64_t)val, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE );
    }
#endif

    /* 4294 seconds could overflow a uint32_t in microseconds */
    if (timeout && timeout->tv_sec < 4294)
    {
        uint32_t us_timeout = ((uint32_t)timeout->tv_sec * 1000000) + ((uint32_t)timeout->tv_nsec / 1000);

        if (!us_timeout)
        {
            errno = ETIMEDOUT;
            return -1;
        }
        return __ulock_wait( UL_COMPARE_AND_WAIT, (void *)addr, (uint64_t)val, us_timeout );
    }

    return __ulock_wait( UL_COMPARE_AND_WAIT, (void *)addr, (uint64_t)val, 0 );
}

static inline int futex_wake_one( const LONG *addr )
{
#ifdef MAC_OS_VERSION_14_4
    if (__builtin_available( macOS 14.4, * ))
        return os_sync_wake_by_address_any( (void *)addr, 4, OS_SYNC_WAKE_BY_ADDRESS_NONE );
#endif
    return __ulock_wake( UL_COMPARE_AND_WAIT, (void *)addr, 0 );
}

#endif /* __APPLE__ */


/***********************************************************************
 *   iOS-Madeira ml952: the in-process event fast path ("fastsync")
 *
 * The wineserver is a thread in this same Mach task, so every event_op and
 * every single-object wait is a socket write, two scheduler hops and a socket
 * write back: [srv-stats] on log 41 measured 50 us per request, 2900 event ops
 * and 900 single-object waits a second, all of it between the 32-bit title's
 * main thread and its render/worker threads -- about 150 us of latency on each
 * handoff between the two threads that pace the frame.
 *
 * Upstream already has the shape of the fix: the inproc_set_event() /
 * inproc_wait() hooks above, which on Linux push the operation into
 * /dev/ntsync and never reach the server.  They are dead here
 * (inproc_device_fd < 0).  This is the iOS substitute, and it exploits the one
 * thing this port has that upstream does not: the server's own object state is
 * at an address this thread can read.  Each handle-reachable event gets a cell
 * (build/ntdll-unix/shims/ios_fastsync.h) whose state word IS the event state
 * -- the server's event_sync_signaled()/_satisfied() read and clear the same
 * word -- so a set or a wait can be a compare-and-swap plus, at most, one
 * os_sync_wake_by_address.
 *
 * What is deliberately NOT fast-pathed, because the server is still the only
 * thing that can do it correctly:
 *   - alertable waits, wait-all, and any wait on more than one handle;
 *   - NtSignalAndWaitForSingleObject and keyed events;
 *   - PulseEvent, which takes its event out of the fast path for good;
 *   - a set on an event that has a server-side waiter, which still issues the
 *     event_op request so the server wakes its own queue (the cell update
 *     happens first either way, so the request's reply is ignored).
 * And a fast wait is capped at ~2 ms and then falls through to the real
 * server_wait, so APCs, alerts, suspension and thread termination are never
 * delayed by more than that cap.
 ***********************************************************************/

#ifdef WINE_IOS

#include "ios_fastsync.h"
#include "ios_late_wake.h"

#define MADEIRA_FAST_CACHE_SIZE  2048          /* power of two, direct mapped   */
#define MADEIRA_FAST_SPIN        96            /* isb ladder before parking     */
#define MADEIRA_FAST_CAP_NS      2000000ull    /* 2 ms default, then the server */

/* ml1050: THE ADAPTIVE SPIN, AND WHY 96 ISBs WAS THE WRONG SHAPE.
 *
 * MADEIRA_FAST_SPIN is an ITERATION count with no clock in it, so what it
 * actually buys depends on the core it lands on and on nothing else.  On a
 * P-core 96 `isb`s is a few microseconds; the kprev5 gameplay capture shows
 * `__ulock_wait2<-madeira_fast_wait` at 4.5 % of all CPU with busy=1.37 of
 * six cores, i.e. a job system handing work between cores thousands of times
 * a frame on a machine that is four fifths idle, paying a park and a wake for
 * handoffs that were often microseconds away.  A park costs two syscalls, a
 * context switch out and a scheduler wake-up in; on an idle machine spinning
 * for tens of microseconds is unambiguously cheaper, and on a busy one it is
 * unambiguously worse.  So the budget cannot be a constant -- it has to be a
 * function of whether spinning has been paying.
 *
 * The controller is deliberately the simplest thing that self-limits:
 *   credit starts at MAX and the budget is spin_ns * credit / MAX;
 *   a timed spin that was SATISFIED adds MADEIRA_SPIN_CREDIT_UP,
 *   a timed spin that had to park subtracts one.
 * Steady state: the timed spin survives as long as at least 1 in
 * (UP + 1) = 1 in 3 of them pay off, and decays to nothing -- one clock read
 * per wait -- when they do not.  That is the "are there spare cores" question
 * answered by measurement instead of by sampling host_statistics(), which
 * would cost a syscall to learn something the payoff rate already implies.
 *
 * The budget is additionally clamped to the caller's own remaining timeout by
 * the same rule the park already uses, so a 30 us WaitForSingleObject can
 * never be turned into a 60 us one.
 *
 * MADEIRA_FASTSYNC_SPIN_US=0 removes the timed phase entirely and restores
 * exactly the pre-ml1050 ladder. */
#define MADEIRA_FAST_SPIN_NS     40000ull      /* 40 us ceiling, adaptive below */
#define MADEIRA_SPIN_CREDIT_MAX  64
#define MADEIRA_SPIN_CREDIT_UP   2

/* Handle -> cell, learnt lazily with one get_inproc_sync_fd request and then
 * answered from here.  Direct-mapped on the handle index; collisions simply
 * re-learn, which is also what keeps this correct across pseudo-processes:
 * every guest process in this task shares this array, so the owning process id
 * is part of the key and a colliding handle value from another process misses
 * rather than aliasing.  `cell == -1' is the negative answer ("this handle is
 * not a fast event"), which is what stops a wait on a file or a mutex from
 * paying the learn request more than once.
 *
 * Entries are published with a seqlock: writers (always on a cache miss, never
 * on the hot path) serialise on madeira_fast_mutex and bump `seq' to odd,
 * store, then to even; readers take seq, read, take seq again and retry on any
 * change.  A stale entry that survives all of that is still caught by the
 * generation check against the cell itself. */
struct madeira_fast_entry
{
    unsigned int seq;      /* seqlock, odd while being written */
    unsigned int handle;   /* obj_handle_t value, 0 = empty     */
    unsigned int pid;      /* owning guest process              */
    unsigned int access;   /* handle access rights              */
    unsigned int gen;      /* cell generation when learnt       */
    unsigned int manual;   /* manual-reset event                */
    int          cell;     /* cell index, -1 = "no cell"        */
};

static BOOL is_pseudo_handle( HANDLE handle );   /* defined with the inproc cache below */

static struct madeira_fast_entry madeira_fast_cache[MADEIRA_FAST_CACHE_SIZE];
static pthread_mutex_t madeira_fast_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ml982: the four modes, parsed once (see the table at the head of
 * ios_fastsync.h).  `madeira_fast_mode' selects the ladder and never changes
 * again; `madeira_fast_on' is the CLIENT WAKE PATH and is the only thing the
 * auto rule flips at runtime, always 0 -> 1 and never back. */
enum
{
    MADEIRA_FS_MODE_OFF   = 0,   /* no cells at all: the pre-ml952 port       */
    MADEIRA_FS_MODE_CELLS = 1,   /* server cells + the read-only poll peek    */
    MADEIRA_FS_MODE_AUTO  = 2,   /* ... and arm the wake path on real traffic */
    MADEIRA_FS_MODE_ON    = 3    /* ... armed from the first call             */
};

static int madeira_fast_mode  = -1;   /* MADEIRA_FS_MODE_*, -1 = not parsed   */
static int madeira_fast_on    = -1;   /* client wake path active              */
static int madeira_fast_peek  = 1;    /* MADEIRA_FS_POLLPEEK, default ON      */
static int madeira_fast_sem   = 0;    /* ml1160 semaphore cells are opt-in   */
static int madeira_fast_ready = 0;    /* the parse has happened               */

/* How many event/select operations in one 10 s [srv-stats] window arm the wake
 * path in "auto" mode.  The measurement this whole mechanism exists for showed
 * 338 k requests per 10 s; a launcher or a helper process does not come close,
 * which is the point -- the three programs that died on the ml952 device
 * snapshot were all quiet ones. */
#define MADEIRA_FS_AUTO_REQS_DEFAULT  20000u
static unsigned int madeira_fast_auto_reqs = MADEIRA_FS_AUTO_REQS_DEFAULT;

/* ml982: one in every MADEIRA_FS_PEEK_EVERY zero-timeout waits is sent to the
 * server even when the cell could have answered it.  Two reasons, and they are
 * the whole safety argument for the peek:
 *
 *  - a zero-timeout wait is the one server call a thread in a polling loop may
 *    be making AT ALL, and the server is what delivers a pending system APC
 *    (STATUS_KERNEL_APC).  Answering every poll locally would let a thread
 *    that does nothing else starve one indefinitely; answering 15 of 16 bounds
 *    the delay at 16 poll iterations.
 *  - it makes the peek SELF-CORRECTING.  If a cache entry ever resolved to the
 *    wrong cell the peek would answer "not signaled" for an object that is
 *    signaled -- a spin, not a lost wakeup, and one that the next server poll
 *    ends.  A wrong answer can therefore never outlive 16 iterations of the
 *    caller's own loop.
 *
 * Must be a power of two. */
#define MADEIRA_FS_PEEK_EVERY     16u

/* ... and one in this many peeked polls yields, which is what server_wait's
 * own poll-streak rule (IOS_SRV_YIELD_EVERY, server_ios.c) used to do for
 * these calls before the peek took them off the server. */
#define MADEIRA_FS_PEEK_YIELD     64u

/* How long a fast wait may park before it gives the wait back to the server.
 * This is the one number that trades handoff latency against how late a system
 * APC, a suspend or a thread termination can be noticed by a thread that is
 * parked on a cell, so it is reachable from a device run without a rebuild:
 * MADEIRA_FASTSYNC_CAP_US, clamped to [50 us, 50 ms].  If the next [srv-stats]
 * still shows a large `w1 inf', the handoffs are simply longer than the cap
 * and this is the knob to raise. */
static unsigned long long madeira_fast_cap_ns = MADEIRA_FAST_CAP_NS;
/* ml1050: adaptive spin budget ceiling and its payoff credit.  See the block
 * comment next to MADEIRA_FAST_SPIN_NS.  `credit' is a plain int touched with
 * relaxed adds from every waiting thread: it is a shared estimate of whether
 * spinning is currently worth it, and a lost update costs one wait's worth of
 * fidelity, never correctness. */
static unsigned long long madeira_fast_spin_ns = MADEIRA_FAST_SPIN_NS;
static int madeira_fast_spin_credit = MADEIRA_SPIN_CREDIT_MAX;

/* ml1100: credit==0 WAS ABSORBING, AND THE HISTOGRAM SAYS IT SHOULD NOT HAVE BEEN.
 *
 * The ml1050 controller only scores a spin it actually RAN: a hit adds
 * MADEIRA_SPIN_CREDIT_UP, a miss subtracts one, and a zero budget skips the whole
 * phase.  So once credit reaches 0 nothing spins, nothing is scored, and credit can
 * never rise again -- an absorbing state, not a decay.  A 32-minute device session
 * shows exactly that: `handoff: spin hit=0 miss=0 credit=0' in every window from the
 * first one on, with 36,996 parks in ten seconds underneath it.
 *
 * And it was wrong to be off.  That session's own park-to-satisfied histogram --
 * `us: 0=618 1=692 2=621 4=3096 8=4376 16=5476 32=5341 64=4755 128=4154 256=3251
 * 512=2319 1024=2051 2048=246' -- puts 20,220 of 36,996 parks (54.7%) at or below
 * 32 us and 67.5% at or below 64 us.  The ceiling is 40 us.  So the workload sat in
 * the payoff region the whole time (the controller's own break-even is one in three)
 * while the controller was switched off, and the histogram is also why 40 us is the
 * right ceiling rather than 10 or 200: at 8 us only a quarter of parks would be
 * caught, and past 128 us the marginal park costs more spin than it saves.
 *
 * THE PROBE.  One park in MADEIRA_SPIN_PROBE_EVERY spins anyway, on a budget of the
 * ceiling shifted down, and is scored by the ordinary hit/miss path.  A single hit
 * lifts credit off 0 and the existing controller takes over; a run of misses leaves
 * it at 0 because the decrement is clamped there.  Cost at the measured park rate is
 * ~580 probes per ten seconds at 5 us each -- under 3 ms of spin spread across every
 * thread in the process, against 37,000 parks.  MADEIRA_FASTSYNC_SPIN_PROBE=0 turns
 * the probe off and restores the absorbing ml1050 behaviour exactly. */
#define MADEIRA_SPIN_PROBE_EVERY  64u   /* power of two */
#define MADEIRA_SPIN_PROBE_SHIFT  3u    /* probe budget = ceiling >> this */

/* ml1100: AND THE RAMP BACK UP WAS BROKEN TOO, which a probe alone would not have
 * fixed.  MADEIRA_SPIN_CREDIT_UP is +2 out of 64, so a credit that has reached 0
 * buys a budget of 40 us * 2/64 = 1.25 us on its next attempt -- shorter than
 * almost every handoff in the measured histogram (only 3.5% of parks complete
 * inside 2 us), so it misses, decays straight back to 0, and the controller is
 * stuck again one wait later.  A probe that PAYS is evidence about the workload,
 * not about one wait, so it re-arms the controller to a credit that buys a real
 * trial (a quarter of the ceiling = 10 us, which the histogram puts above a third
 * of all parks) and lets the ordinary +2/-1 rule take it from there. */
#define MADEIRA_SPIN_CREDIT_REARM (MADEIRA_SPIN_CREDIT_MAX / 4)

static unsigned int madeira_fast_spin_probe_seq;   /* the 1-in-N sequencer */
static unsigned int madeira_fast_spin_probes;      /* probes run, drained by the reporter */

static int madeira_fast_spin_probe_on( void )
{
    static int cached = -1;

    if (cached < 0)
    {
        const char *e = getenv( "MADEIRA_FASTSYNC_SPIN_PROBE" );
        cached = !(e && e[0] == '0');
    }
    return cached;
}

static inline unsigned long long madeira_fast_spin_budget_ns( const LARGE_INTEGER *timeout,
                                                              int *is_probe )
{
    int credit;
    unsigned long long ns;

    *is_probe = 0;
    if (!madeira_fast_spin_ns) return 0;
    credit = __atomic_load_n( &madeira_fast_spin_credit, __ATOMIC_RELAXED );
    if (credit <= 0)
    {
        unsigned seq;

        if (!madeira_fast_spin_probe_on()) return 0;
        seq = __atomic_fetch_add( &madeira_fast_spin_probe_seq, 1, __ATOMIC_RELAXED );
        if (seq & (MADEIRA_SPIN_PROBE_EVERY - 1)) return 0;
        ns = madeira_fast_spin_ns >> MADEIRA_SPIN_PROBE_SHIFT;
        if (!ns) return 0;
        __atomic_fetch_add( &madeira_fast_spin_probes, 1, __ATOMIC_RELAXED );
        *is_probe = 1;
        /* Falls through to the caller-timeout clamp below, exactly as a
         * credited budget does -- a probe must not outlive its own wait. */
        goto clamp;
    }
    if (credit > MADEIRA_SPIN_CREDIT_MAX) credit = MADEIRA_SPIN_CREDIT_MAX;
    ns = madeira_fast_spin_ns * (unsigned)credit / MADEIRA_SPIN_CREDIT_MAX;
clamp:
    /* Never spin past the caller's own relative timeout -- the same rule the
     * park below applies to its 2 ms cap, for the same reason. */
    if (timeout && timeout->QuadPart < 0 &&
        (unsigned long long)(-timeout->QuadPart) * 100 < ns)
        ns = (unsigned long long)(-timeout->QuadPart) * 100;
    return ns;
}

/* ml1050: log2-microsecond buckets of the park-to-satisfied interval, read and
 * zeroed once per report window by madeira_fast_park_hist_snapshot().  16
 * buckets covers 1 us .. >=32 ms, which spans "the signaller was already
 * running" to "this wait was going to the server anyway". */
#define MADEIRA_PARK_HIST_N 16
static unsigned int madeira_fast_park_hist[MADEIRA_PARK_HIST_N];

static inline void madeira_fast_park_hist_add( unsigned long long ns )
{
    unsigned long long us = ns / 1000;
    unsigned idx = us ? (unsigned)(63 - __builtin_clzll( us )) + 1 : 0;
    if (idx >= MADEIRA_PARK_HIST_N) idx = MADEIRA_PARK_HIST_N - 1;
    __atomic_fetch_add( &madeira_fast_park_hist[idx], 1, __ATOMIC_RELAXED );
}

/* The adaptive spin's payoff, counted here rather than read back out of
 * ios_srv_nt_counts[]: that array is exchanged to zero by
 * ios_srv_stats_report(), and in a MADEIRA_DIAG build both reporters run in
 * the same window, so a second reader of it would get whatever the first one
 * left behind.  These are drained by exactly one reader. */
static unsigned int madeira_fast_spin_hits, madeira_fast_spin_misses;

/* Exported for the reporter in build/ntdll-unix/server_ios.c (a different
 * translation unit); fills `out' with the window and zeroes the source. */
void madeira_fast_park_hist_snapshot( unsigned int *out, unsigned n,
                                      unsigned int *spin_hit, unsigned int *spin_miss,
                                      int *credit, unsigned int *spin_probe )
{
    unsigned i;
    for (i = 0; i < n; i++)
        out[i] = i < MADEIRA_PARK_HIST_N
               ? __atomic_exchange_n( &madeira_fast_park_hist[i], 0, __ATOMIC_RELAXED ) : 0;
    *spin_hit  = __atomic_exchange_n( &madeira_fast_spin_hits, 0, __ATOMIC_RELAXED );
    *spin_miss = __atomic_exchange_n( &madeira_fast_spin_misses, 0, __ATOMIC_RELAXED );
    *credit    = __atomic_load_n( &madeira_fast_spin_credit, __ATOMIC_RELAXED );
    /* ml1100: probes run this window. `hit=0 miss=0 probe=0' now means the spin is
     * OFF by configuration; `probe=N miss=N' means the probe ran and the workload
     * genuinely does not pay off; `probe=N' with hit>0 means it recovered. */
    *spin_probe = __atomic_exchange_n( &madeira_fast_spin_probes, 0, __ATOMIC_RELAXED );
}

static inline void madeira_fast_spin_credit_add( int delta )
{
    int c = __atomic_add_fetch( &madeira_fast_spin_credit, delta, __ATOMIC_RELAXED );
    if (c > MADEIRA_SPIN_CREDIT_MAX)
        __atomic_store_n( &madeira_fast_spin_credit, MADEIRA_SPIN_CREDIT_MAX, __ATOMIC_RELAXED );
    else if (c < 0)
        __atomic_store_n( &madeira_fast_spin_credit, 0, __ATOMIC_RELAXED );
}

enum madeira_fast_result
{
    MADEIRA_FAST_MISS,    /* not handled at all, run the original path      */
    MADEIRA_FAST_DONE,    /* handled completely, no server round trip       */
    MADEIRA_FAST_SERVER   /* cell updated, but the server call is still due */
};

/* ml982: parse MADEIRA_FASTSYNC / MADEIRA_FS_POLLPEEK / MADEIRA_FASTSYNC_CAP_US
 * / MADEIRA_FS_AUTO_REQS once.  Running it twice on a race is harmless (the
 * inputs are immutable and the outputs are identical), so there is no lock
 * here; `madeira_fast_ready' only stops the getenv work happening on the hot
 * path, it is not a mutual-exclusion flag.
 *
 * ml990: THE DEFAULT IS NOW "auto" -- cells on, and the client WAKE path armed
 * the first time this task's own [srv-stats] window shows more than
 * MADEIRA_FS_AUTO_REQS event+select operations in 10 s.  The history that kept
 * it at the middle rung: ml952 shipped the wake path on unconditionally and
 * three unrelated programs died the same way on the first device snapshot;
 * ml962 inverted the opt-in; ml972 fixed four defects and was never run on a
 * device; ml982 audited it, shipped the read-only peek on, and named two
 * reasons not to arm the wake path by default.  Both are now answered:
 *
 *  - the lost-wakeup vector (a state CAS that was not atomic with the
 *    generation check) is gone -- the generation is INSIDE the word the CAS
 *    compares, see ios_fastsync.h;
 *  - it has now run on a device.  Log y104 armed it through a 32-bit
 *    job-system title ("[fastsync] AUTO-ENABLED after 181468 event/select ops
 *    in 10000ms") and reported desync=0, stale_gen=0 and relearn=0 in every
 *    window, with total server traffic falling from 15296/s to ~5200/s.
 *
 * The arm is deliberately still conditional rather than unconditional: a quiet
 * process (a launcher, an installer, a helper) never reaches the threshold and
 * therefore never exercises the wake semantics at all, which keeps the class of
 * program that died on the ml952 snapshot on the path it survives.
 * MADEIRA_FASTSYNC=0 forces everything off, cells included.
 */
static void madeira_fast_parse_env(void)
{
    const char *e = getenv( "MADEIRA_FASTSYNC" );
    int mode = MADEIRA_FS_MODE_AUTO, peek, sem;

    if (e)
    {
        if (!strcmp( e, "0" ) || !strcmp( e, "off" ) || !strcmp( e, "no" ))
            mode = MADEIRA_FS_MODE_OFF;
        else if (!strcmp( e, "1" ) || !strcmp( e, "on" ))
            mode = MADEIRA_FS_MODE_ON;
        else if (!strcmp( e, "auto" ))
            mode = MADEIRA_FS_MODE_AUTO;
        else if (!strcmp( e, "cells" ))
            mode = MADEIRA_FS_MODE_CELLS;   /* ml990: the old default, still reachable */
    }

    /* the peek needs a cell to read, so "off" turns it off whatever it says */
    e = getenv( "MADEIRA_FS_POLLPEEK" );
    peek = (e && (!strcmp( e, "0" ) || !strcmp( e, "off" ) || !strcmp( e, "no" ))) ? 0 : 1;
    if (mode == MADEIRA_FS_MODE_OFF) peek = 0;

    /* ml1010: the SEMAPHORE path has a knob of its own so it can be turned off
     * without giving up the event path, which has already shipped and run on a
     * device with desync=0.  The server parses the identical name and then
     * allocates no cell for a semaphore at all, so "off" is the pre-ml1010
     * behaviour on both sides rather than a client-only opt-out. */
    e = getenv( "MADEIRA_FASTSYNC_SEM" );
    sem = e && (!strcmp( e, "1" ) || !strcmp( e, "on" ) || !strcmp( e, "yes" ));
    if (mode == MADEIRA_FS_MODE_OFF) sem = 0;
    ERR( "[semaphore-policy] ml1160 cells=%s (opt-in via MADEIRA_FASTSYNC_SEM=1); event fastsync unchanged\n",
         sem ? "on" : "off" );

    if ((e = getenv( "MADEIRA_FASTSYNC_CAP_US" )))
    {
        unsigned long us = strtoul( e, NULL, 10 );
        if (us < 50) us = 50;
        if (us > 50000) us = 50000;
        madeira_fast_cap_ns = (unsigned long long)us * 1000;
    }
    if ((e = getenv( "MADEIRA_FS_AUTO_REQS" )))
    {
        unsigned long n = strtoul( e, NULL, 10 );
        if (n < 1000) n = 1000;
        madeira_fast_auto_reqs = (unsigned int)n;
    }
    /* ml1050: the adaptive spin budget.  See madeira_fast_spin_budget_ns(). */
    if ((e = getenv( "MADEIRA_FASTSYNC_SPIN_US" )))
    {
        unsigned long us = strtoul( e, NULL, 10 );
        if (us > 1000) us = 1000;
        madeira_fast_spin_ns = (unsigned long long)us * 1000;
    }

    __atomic_store_n( &madeira_fast_peek, peek, __ATOMIC_RELAXED );
    __atomic_store_n( &madeira_fast_sem, sem, __ATOMIC_RELAXED );
    __atomic_store_n( &madeira_fast_on, mode == MADEIRA_FS_MODE_ON ? 1 : 0, __ATOMIC_RELAXED );
    __atomic_store_n( &madeira_fast_mode, mode, __ATOMIC_RELAXED );
    if (__atomic_exchange_n( &madeira_fast_ready, 1, __ATOMIC_RELEASE )) return;   /* announce once */

    ERR( "[fastsync] rev=ml1060 mode=%s peek=%s sem=%s cells=%u cache=%u spin=%u cap=%uus auto=%u/10s"
         " gen-packed watch=alertable+plain - MADEIRA_FASTSYNC=0|cells|auto|1 selects"
         " (auto is the default); MADEIRA_FS_POLLPEEK=0 disables the read-only zero-timeout"
         " answer; MADEIRA_FASTSYNC_SEM=0 disables the semaphore path only\n",
         mode == MADEIRA_FS_MODE_OFF   ? "off (pre-ml952)" :
         mode == MADEIRA_FS_MODE_CELLS ? "cells (wake path OFF)" :
         mode == MADEIRA_FS_MODE_AUTO  ? "auto (wake path armed on traffic)" : "on",
         peek ? "on" : "off", sem ? "on" : "off",
         (unsigned int)MADEIRA_SYNC_CELLS, (unsigned int)MADEIRA_FAST_CACHE_SIZE,
         (unsigned int)MADEIRA_FAST_SPIN, (unsigned int)(madeira_fast_cap_ns / 1000),
         madeira_fast_auto_reqs );
    ERR( "[fastsync] ml1100 adaptive spin: isb x%u then up to %lluus of timed spin, budget scaled "
         "by a payoff credit in [0,%u] (+%d on a spin that was paid, -1 on one that had to park); "
         "credit 0 is no longer absorbing — 1 park in %u spins anyway on a %lluus probe and a probe "
         "that pays re-arms the credit to %d; MADEIRA_FASTSYNC_SPIN_PROBE=0 restores the ml1050 "
         "behaviour and MADEIRA_FASTSYNC_SPIN_US=0 the fixed %u-iteration ladder\n",
         (unsigned int)MADEIRA_FAST_SPIN, madeira_fast_spin_ns / 1000,
         (unsigned int)MADEIRA_SPIN_CREDIT_MAX, MADEIRA_SPIN_CREDIT_UP,
         MADEIRA_SPIN_PROBE_EVERY, (madeira_fast_spin_ns >> MADEIRA_SPIN_PROBE_SHIFT) / 1000,
         MADEIRA_SPIN_CREDIT_REARM, (unsigned int)MADEIRA_FAST_SPIN );
}

static inline void madeira_fast_init(void)
{
    if (!__atomic_load_n( &madeira_fast_ready, __ATOMIC_ACQUIRE )) madeira_fast_parse_env();
}

/* Called by the iOS session launcher only after the previous server has
 * joined and before its replacement or any guest thread starts. Preserve
 * cells/generations: resetting the table would make old handles alias. The
 * next guest-side init reparses its policy with a valid TEB; doing that here
 * on the Swift launch worker would run Wine diagnostics without a TEB. */
void madeira_fast_reload_session(void)
{
    __atomic_store_n( &madeira_fast_ready, 0, __ATOMIC_RELEASE );
}

/* "may this call take a token, park, or publish a wake" -- the client half. */
static inline int madeira_fastsync_enabled(void)
{
    madeira_fast_init();
    return __atomic_load_n( &madeira_fast_on, __ATOMIC_RELAXED );
}

/* "does the server keep event state in a cell we may READ" -- true for every
 * mode above "off", including the default. */
static inline int madeira_fast_cells_enabled(void)
{
    madeira_fast_init();
    return __atomic_load_n( &madeira_fast_mode, __ATOMIC_RELAXED ) > MADEIRA_FS_MODE_OFF;
}

/* ml1010: "may this call touch a SEMAPHORE cell at all".  Every semaphore site
 * tests this in addition to the mode test that applies to events. */
static inline int madeira_fast_sem_enabled(void)
{
    madeira_fast_init();
    return __atomic_load_n( &madeira_fast_sem, __ATOMIC_RELAXED );
}

/* ml982: the "auto" rule.  Called once per [srv-stats] window from
 * build/ntdll-unix/server_ios.c, which is the only thing in this image that
 * already knows the task's request rate, so the rule costs nothing of its own.
 *
 * Scope: this image is ONE Mach task and `madeira_fast_on' is one word in it,
 * so the arm is task-wide rather than per-pseudo-process -- the counters it
 * reads are task-wide too.  In practice the task IS the title: the quiet
 * helper processes that this rule is meant to spare are separate Madeira
 * launches, not threads of this one.
 *
 * One way only.  There is no disarm: a fast waiter parked on a cell would have
 * to be told, and "turn it off underneath a parked thread" is exactly the kind
 * of state change this mechanism is bad at.  A DESYNC demotes the one object
 * instead (see madeira_fast_watchdog_check). */
void madeira_fastsync_auto_arm( unsigned int ops, unsigned long long window_ns )
{
    if (__atomic_load_n( &madeira_fast_mode, __ATOMIC_RELAXED ) != MADEIRA_FS_MODE_AUTO) return;
    if (__atomic_load_n( &madeira_fast_on, __ATOMIC_RELAXED )) return;
    if (ops < madeira_fast_auto_reqs) return;
    if (__atomic_exchange_n( &madeira_fast_on, 1, __ATOMIC_RELAXED )) return;

    ERR( "[fastsync] AUTO-ENABLED after %u event/select ops in %llums (%llu/s, threshold %u)"
         " - the in-process wake path is now live; MADEIRA_FASTSYNC=0 forces it off\n",
         ops, window_ns / 1000000ull,
         window_ns ? (unsigned long long)ops * 1000000000ull / window_ns : 0ull,
         madeira_fast_auto_reqs );
}

static inline unsigned int madeira_fast_pid(void)
{
    TEB *teb = NtCurrentTeb();
    return teb ? (unsigned int)(ULONG_PTR)teb->ClientId.UniqueProcess : 0;
}

/* ml972 DEFECT 1, HALF A: THE BUDGET CLOCK MUST BE THE PARK CLOCK.
 *
 * madeira_fast_park() parks with OS_CLOCK_MACH_ABSOLUTE_TIME (and, on the
 * pre-17.4 ladder, __ulock_wait, which is the same time base).  That clock is
 * mach_absolute_time(): it does NOT advance while the system is asleep.
 *
 * ml962 measured the same interval with clock_gettime_nsec_np(
 * CLOCK_MONOTONIC_RAW), and CLOCK_MONOTONIC_RAW is documented to be the one
 * that DOES keep incrementing while the system is asleep (CLOCK_UPTIME_RAW is
 * "the same as CLOCK_MONOTONIC_RAW but does not increment while the system is
 * asleep").  So the two clocks measure the park differently by exactly the
 * amount of time the AP spent asleep inside it, and the fall-through
 * arithmetic below charged that sleep to the CALLER's timeout: a 300 ms
 * WaitForSingleObject could hand server_wait a remainder of zero and come
 * straight back with STATUS_TIMEOUT.  Use the clock the park actually counts.
 *
 * CLOCK_UPTIME_RAW == mach_absolute_time() converted to ns; the mach fallback
 * below exists because clock_gettime_nsec_np() reports failure by returning 0,
 * and a 0 here would poison every interval it is subtracted from. */
static inline unsigned long long madeira_now_ns(void)
{
    unsigned long long ns = clock_gettime_nsec_np( CLOCK_UPTIME_RAW );

    if (ns) return ns;
    {
        static mach_timebase_info_data_t tb;
        if (!tb.denom) mach_timebase_info( &tb );
        return mach_absolute_time() * tb.numer / tb.denom;
    }
}

/***********************************************************************
 *   ml1110: THE LATE-WAKE CENSUS -- see build/ntdll-unix/shims/ios_late_wake.h
 *
 * The counters and the one branch on the release path.  Everything that reads
 * them lives at the bottom of this block, next to the reporter's entry points.
 ***********************************************************************/

static int madeira_late_on = -1;          /* MADEIRA_LATEWAKE, default ON     */

static unsigned int madeira_late_counts[7];   /* indexed by MADEIRA_LATE_*    */
static unsigned int madeira_late_age[IOS_LATE_AGE_N];

#define MADEIRA_LATE_TMO_FIN    0
#define MADEIRA_LATE_SEM        1
#define MADEIRA_LATE_EVENT      2
#define MADEIRA_LATE_NOSTAMP    3
#define MADEIRA_LATE_HB         4
#define MADEIRA_LATE_HB_LATE    5
#define MADEIRA_LATE_RESCUED    6

/* The hot-object sketch.  Fixed slots, racy by design: two threads charging
 * the same cell can both install it, which costs a duplicated row in a
 * diagnostic and nothing else.  A slot is claimed by the first late expiry on
 * a cell and is never evicted within a window, because the window is zeroed
 * whole by the snapshot. */
static unsigned int madeira_late_hot_cell[IOS_LATE_HOT_N];
static unsigned int madeira_late_hot_kind[IOS_LATE_HOT_N];
static unsigned int madeira_late_hot_n[IOS_LATE_HOT_N];

static inline int madeira_late_enabled(void)
{
    int on = __atomic_load_n( &madeira_late_on, __ATOMIC_RELAXED );

    if (on < 0)
    {
        const char *e = getenv( "MADEIRA_LATEWAKE" );

        on = (e && (!strcmp( e, "0" ) || !strcmp( e, "off" ) || !strcmp( e, "no" ))) ? 0 : 1;
        __atomic_store_n( &madeira_late_on, on, __ATOMIC_RELAXED );
    }
    return on;
}

/* The release path's whole contribution: one clock read (a commpage read on
 * this OS, not a syscall) and one relaxed store, and only while the census is
 * on.  Called from the two CLIENT fast paths that can raise a cell without
 * the server knowing about it -- see ios_fastsync.h for why the server's own
 * releases are not stamped. */
static inline void madeira_late_stamp( struct madeira_sync_cell *cell )
{
    if (!madeira_late_enabled()) return;
    madeira_cell_note_release( cell, madeira_now_ns() );
}

/* ml962: the seqlock WRITE side, corrected.
 *
 * The ml952 version was
 *
 *     __atomic_store_n( &e->seq, s + 1, __ATOMIC_RELEASE );   // odd
 *     e->handle = handle; e->pid = pid; e->cell = cell; ...   // plain stores
 *     __atomic_thread_fence( __ATOMIC_RELEASE );
 *     __atomic_store_n( &e->seq, s + 2, __ATOMIC_RELEASE );   // even
 *
 * and that is NOT a seqlock.  A release store is a one-way barrier: it orders
 * everything BEFORE it, and places no constraint at all on the stores that
 * come AFTER it.  Both the compiler and an arm64 core may therefore publish
 * `e->handle' (a plain STR) before the STLR that marks the entry as being
 * written -- so a concurrent reader can see
 *
 *     seq   = s      (even: "stable", the odd marker has not landed yet)
 *     handle= NEW    (already landed)
 *     pid   = NEW
 *     cell/gen = OLD (have not landed yet)
 *
 * take the second seq read as s again, conclude the entry is consistent, and
 * use ANOTHER EVENT'S CELL for this handle.  The generation check does not
 * catch it: the old cell is a perfectly live cell belonging to a perfectly
 * live event, so its gen still matches the old gen that was read with it.
 *
 * The consequence is exactly the reported failure signature: NtWaitForSingle-
 * Object( B ) returns STATUS_SUCCESS the moment some unrelated event A is set
 * (and NtSetEvent( B ) sets A), so the waiter runs before its producer has
 * published anything and reads a pointer that is still NULL.  It needs no
 * pathological program -- just two threads, one learning a handle into a slot
 * while another looks the same slot up, which is what "a worker starts a new
 * thread and both touch the same events" does.
 *
 * The fix is the standard C11 seqlock write side: a RELEASE FENCE between the
 * odd marker and the data, which is what actually forbids the data stores from
 * floating above the marker. */
static void madeira_fast_publish( struct madeira_fast_entry *e, unsigned int handle,
                                  unsigned int pid, int cell, unsigned int gen,
                                  unsigned int access, unsigned int manual )
{
    sigset_t sigset;
    unsigned int s;

    server_enter_uninterrupted_section( &madeira_fast_mutex, &sigset );
    s = __atomic_load_n( &e->seq, __ATOMIC_RELAXED );
    __atomic_store_n( &e->seq, s + 1, __ATOMIC_RELAXED );   /* odd: writing */
    __atomic_thread_fence( __ATOMIC_RELEASE );              /* ... and it lands FIRST */
    /* relaxed atomics rather than plain stores so the compiler cannot sink
     * them past the fences either */
    __atomic_store_n( &e->handle, handle, __ATOMIC_RELAXED );
    __atomic_store_n( &e->pid,    pid,    __ATOMIC_RELAXED );
    __atomic_store_n( &e->cell,   cell,   __ATOMIC_RELAXED );
    __atomic_store_n( &e->gen,    gen,    __ATOMIC_RELAXED );
    __atomic_store_n( &e->access, access, __ATOMIC_RELAXED );
    __atomic_store_n( &e->manual, manual, __ATOMIC_RELAXED );
    __atomic_thread_fence( __ATOMIC_RELEASE );
    __atomic_store_n( &e->seq, s + 2, __ATOMIC_RELAXED );   /* even: readable */
    server_leave_uninterrupted_section( &madeira_fast_mutex, &sigset );
}

/* Drop a handle from the cache.  Called from NtClose and from the
 * DUPLICATE_CLOSE_SOURCE half of NtDuplicateObject, next to the existing
 * close_inproc_sync(), and deliberately ignoring the pid: a close of a
 * colliding handle value in another pseudo-process only forces a re-learn.
 *
 * ml962: the "is this slot even mine" test now happens INSIDE the section, so
 * it cannot race a publish into the same slot and decide not to evict an entry
 * that was installed a nanosecond later. */
/* The eviction itself; the caller owns madeira_fast_mutex. */
static void madeira_fast_evict_locked( struct madeira_fast_entry *e )
{
    unsigned int s = __atomic_load_n( &e->seq, __ATOMIC_RELAXED );

    __atomic_store_n( &e->seq, s + 1, __ATOMIC_RELAXED );
    __atomic_thread_fence( __ATOMIC_RELEASE );
    __atomic_store_n( &e->handle, 0u, __ATOMIC_RELAXED );
    __atomic_store_n( &e->pid,    0u, __ATOMIC_RELAXED );
    __atomic_store_n( &e->cell,   -1, __ATOMIC_RELAXED );
    __atomic_store_n( &e->gen,    0u, __ATOMIC_RELAXED );
    __atomic_store_n( &e->access, 0u, __ATOMIC_RELAXED );
    __atomic_store_n( &e->manual, 0u, __ATOMIC_RELAXED );
    __atomic_thread_fence( __ATOMIC_RELEASE );
    __atomic_store_n( &e->seq, s + 2, __ATOMIC_RELAXED );
    ios_srv_nt_count( IOS_FS_EVICT );
}

void madeira_fast_close( HANDLE handle )
{
    unsigned int h = wine_server_obj_handle( handle );
    struct madeira_fast_entry *e;
    sigset_t sigset;

    /* ml982: the guard is the MODE, not the wake path: the read-only poll peek
     * populates this cache in the default mode too, and an entry it leaves
     * behind has to be evicted on close for exactly the same reason. */
    if (!h || __atomic_load_n( &madeira_fast_mode, __ATOMIC_RELAXED ) <= MADEIRA_FS_MODE_OFF) return;
    e = &madeira_fast_cache[(h >> 2) & (MADEIRA_FAST_CACHE_SIZE - 1)];

    server_enter_uninterrupted_section( &madeira_fast_mutex, &sigset );
    if (__atomic_load_n( &e->handle, __ATOMIC_RELAXED ) == h)
        madeira_fast_evict_locked( e );
    server_leave_uninterrupted_section( &madeira_fast_mutex, &sigset );
}

/* ml982 DEFECT: A POSITIVE ENTRY CAN OUTLIVE THE PROCESS IT BELONGS TO.
 *
 * The cache key is (handle value, owning pid) because this one address space
 * holds every pseudo-process, and a positive entry is invalidated by
 * madeira_fast_close() -- which is NtClose and the DUPLICATE_CLOSE_SOURCE
 * path, i.e. by THIS process closing the handle.  Nothing invalidates the
 * entries of a process that simply DIES: its whole handle table is torn down
 * server-side, with no NtClose on this side to observe.
 *
 * On its own that is only a leak of dead entries.  What makes it a
 * correctness problem is that the server reuses a dead process's id
 * (alloc_ptid keeps a free list), so a LATER pseudo-process can be handed the
 * same id, allocate the same low handle values, and hit a slot whose (handle,
 * pid) both match and whose cell is still live because the EVENT is still
 * alive in some other process.  That is a set or a wait landing on a
 * completely unrelated object -- the same failure mode as the ml962 torn
 * publish, reachable without any race at all.
 *
 * One scan of 2048 slots, once, on the process's own init thread, closes it:
 * at that moment this process owns no handles, so any entry carrying our pid
 * is by definition a ghost.  Cost is a few microseconds per process launch.
 */
void madeira_fast_flush_pid(void)
{
    unsigned int pid = madeira_fast_pid();
    sigset_t sigset;
    int i;

    if (!pid) return;
    server_enter_uninterrupted_section( &madeira_fast_mutex, &sigset );
    for (i = 0; i < MADEIRA_FAST_CACHE_SIZE; i++)
    {
        struct madeira_fast_entry *e = &madeira_fast_cache[i];

        if (__atomic_load_n( &e->handle, __ATOMIC_RELAXED ) &&
            __atomic_load_n( &e->pid, __ATOMIC_RELAXED ) == pid)
            madeira_fast_evict_locked( e );
    }
    server_leave_uninterrupted_section( &madeira_fast_mutex, &sigset );
}

/* Returns the cell for `handle', or NULL for "use the server".  `access' is
 * the access the caller needs; if the handle does not have it we return NULL
 * so the slow path can produce the real STATUS_ACCESS_DENIED.
 *
 * ml972: `gen_out' receives the cell generation this answer is valid for.  A
 * caller that goes on to BLOCK on the cell must re-check it (see
 * madeira_cell_alive() and defect 2 in madeira_fast_wait): the cell can be
 * freed and handed to an entirely different event while the caller is parked
 * on it, and the state word alone cannot tell the two apart. */
static struct madeira_sync_cell *madeira_fast_lookup( HANDLE handle, ACCESS_MASK access,
                                                      unsigned int *manual, unsigned int *gen_out,
                                                      unsigned int *kind_out )
{
    unsigned int h = wine_server_obj_handle( handle );
    unsigned int pid = madeira_fast_pid();
    struct madeira_fast_entry *e;
    unsigned int s1, s2, gen = 0, acc = 0, man = 0, type = 0;
    struct madeira_sync_cell *cell;
    unsigned int ret;
    int idx;

    if (!h || is_pseudo_handle( handle )) return NULL;
    /* ml962: the owning process id is half the cache key, and a thread with no
     * Wine TEB (a DXMT/pthread-created one that reached an Nt* entry point)
     * reports 0 for it.  Caching under pid 0 would put every such thread of
     * every pseudo-process into one namespace where the same handle VALUE means
     * different objects, so those callers simply keep the server path. */
    if (!pid) return NULL;
    e = &madeira_fast_cache[(h >> 2) & (MADEIRA_FAST_CACHE_SIZE - 1)];

    /* ml962: the READ side, matching the corrected write side above.  Every
     * field is read with a relaxed atomic (so the compiler cannot re-load one
     * after the validating seq read) and the ACQUIRE fence keeps all of them
     * ordered before it -- including `handle' and `pid', which the ml952 code
     * compared before the fence and therefore before the entry was known to be
     * stable. */
    s1 = __atomic_load_n( &e->seq, __ATOMIC_ACQUIRE );
    if (!(s1 & 1) &&
        __atomic_load_n( &e->handle, __ATOMIC_RELAXED ) == h &&
        __atomic_load_n( &e->pid, __ATOMIC_RELAXED ) == pid)
    {
        idx = __atomic_load_n( &e->cell,   __ATOMIC_RELAXED );
        gen = __atomic_load_n( &e->gen,    __ATOMIC_RELAXED );
        acc = __atomic_load_n( &e->access, __ATOMIC_RELAXED );
        man = __atomic_load_n( &e->manual, __ATOMIC_RELAXED );
        __atomic_thread_fence( __ATOMIC_ACQUIRE );
        s2 = __atomic_load_n( &e->seq, __ATOMIC_ACQUIRE );
        if (s1 == s2)
        {
            if (idx < 0) return NULL;                       /* known: no cell */
            if ((acc & access) != access) return NULL;
            cell = &madeira_sync_cells[idx];
            /* the cell may have been freed and handed to another event since
             * we cached it; that can only happen after this handle was closed,
             * but check anyway rather than mutate a stranger's event */
            if (MADEIRA_SG_GEN( __atomic_load_n( &cell->sg, __ATOMIC_ACQUIRE ) ) == gen)
            {
                /* ml1010: `kind' comes out of the CELL, not the cache, because
                 * it is immutable for this generation and the load above is
                 * exactly the proof that the generation is still ours.  A
                 * semaphore cell reached with the semaphore path turned off
                 * must look like "no cell" so that every caller keeps the
                 * server path it had before ml1010. */
                unsigned int kind = madeira_cell_kind( cell );

                if (kind == MADEIRA_CELL_KIND_SEM && !madeira_fast_sem_enabled()) return NULL;
                *manual = man;
                *gen_out = gen;
                *kind_out = kind;
                return cell;
            }
            ios_srv_nt_count( IOS_FS_STALE_GEN );
        }
    }

    /* Learn it.  One request per handle, ever -- unless the slot is being
     * fought over, which is what IOS_FS_RELEARN measures: a learn for a handle
     * whose own entry is still in the slot means the entry was rejected (pid
     * mismatch or a recycled cell), and a large count there is cache thrash,
     * not cold misses. */
    if (__atomic_load_n( &e->handle, __ATOMIC_RELAXED ) == h) ios_srv_nt_count( IOS_FS_RELEARN );
    SERVER_START_REQ( get_inproc_sync_fd )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            type = reply->type;
            acc  = reply->access;
        }
    }
    SERVER_END_REQ;
    if (ret)
    {
        /* ml962: STATUS_NOT_IMPLEMENTED is this request's "that object has no
         * in-process sync" answer, and on iOS it is the ONLY answer for
         * anything that is not a live cell-backed event -- there is no
         * /dev/ntsync, so get_obj_inproc_sync() always fails and the success
         * reply below is unreachable.  Without caching it here the negative
         * answer was never stored at all and every single wait on a thread,
         * process, mutex, semaphore, timer, file or pulsed event paid an extra
         * round trip on top of the select it was going to do anyway.
         *
         * A negative entry is fail-SAFE in a way a positive one is not: the
         * only thing it can ever do is send a caller to the server.  So it
         * does not need the invalidation guarantees the positive entries get
         * from madeira_fast_close() -- a handle value recycled behind our back
         * (a server-side close at process exit, say) costs the fast path for
         * that handle and nothing else.
         *
         * Every other status (a bad handle, above all) stays uncached so the
         * caller's slow path raises the real error. */
        if (ret == STATUS_NOT_IMPLEMENTED)
        {
            madeira_fast_publish( e, h, pid, -1, 0, 0, 0 );
            ios_srv_nt_count( IOS_FS_LEARN_NONE );
        }
        return NULL;
    }

    if (!(type & MADEIRA_FAST_REPLY_FLAG))
    {
        madeira_fast_publish( e, h, pid, -1, 0, acc, 0 );
        ios_srv_nt_count( IOS_FS_LEARN_NONE );
        return NULL;
    }
    idx  = MADEIRA_FAST_REPLY_IDX( type );
    man  = !!(type & MADEIRA_FAST_REPLY_MANUAL);
    /* the index comes off the wire; a value the table cannot hold would index
     * out of bounds, so treat it as "no cell" rather than trusting it */
    if (idx >= MADEIRA_SYNC_CELLS)
    {
        madeira_fast_publish( e, h, pid, -1, 0, acc, 0 );
        ios_srv_nt_count( IOS_FS_LEARN_NONE );
        return NULL;
    }
    ios_srv_nt_count( IOS_FS_LEARN_EVENT );
    cell = &madeira_sync_cells[idx];
    /* the handle we hold pins the object, which pins the cell, so this
     * generation cannot go stale between here and the store below */
    gen  = MADEIRA_SG_GEN( __atomic_load_n( &cell->sg, __ATOMIC_ACQUIRE ) );
    madeira_fast_publish( e, h, pid, idx, gen, acc, man );

    if ((acc & access) != access) return NULL;
    {
        unsigned int kind = madeira_cell_kind( cell );

        if (kind == MADEIRA_CELL_KIND_SEM && !madeira_fast_sem_enabled()) return NULL;
        *kind_out = kind;
    }
    *manual = man;
    *gen_out = gen;
    return cell;
}

/* ml972: "is this still the cell we were told about?"
 *
 * Cell allocation and freeing are server-side, and `gen' is bumped on BOTH, so
 * a mismatch means the event we resolved has been destroyed and the cell has
 * (possibly) already been handed to another event.  Every operation that can
 * observe the cell AFTER an unbounded pause -- i.e. after a park -- has to ask
 * again, because the state word of the NEW occupant is a perfectly ordinary
 * RESET/SET and is indistinguishable from the old one's.
 *
 * ml990: this is now only for the places that need the question ON ITS OWN --
 * across a park, and in the watchdog.  Every place that reads or writes the
 * STATE gets the generation out of the same 64-bit load or CAS instead, which
 * is what closes the ml982 residual: there is no longer a gap between "is it
 * mine" and "take it". */
static inline int madeira_cell_alive( const struct madeira_sync_cell *cell, unsigned int gen )
{
    return MADEIRA_SG_GEN( __atomic_load_n( &cell->sg, __ATOMIC_ACQUIRE ) ) == gen;
}

/* Take the token if there is one.  A manual-reset event is never consumed; an
 * auto-reset one is consumed with a CAS, which is what makes "exactly one
 * waiter is released" true no matter how many threads and the server race.
 *
 * ml990: `gen' is now part of the comparison, in the SAME atomic operation as
 * the state.  For an auto-reset event that means the CAS cannot succeed
 * against a cell that changed owner since the load, so a token can never be
 * taken out of a stranger's event; for a manual-reset one the single load
 * establishes "at this instant the cell was mine AND it was SET", which the
 * ml982 pair of a separate alive-check plus a separate state load could not. */
static inline int madeira_fast_try( struct madeira_sync_cell *cell, unsigned int manual,
                                    unsigned int gen, unsigned int kind )
{
    uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );

    if (MADEIRA_SG_GEN( sg ) != gen) return 0;
    /* ml1010: a SEMAPHORE's state half is its COUNT, so "is there a token" is
     * `count > 0' and taking one is a decrement -- but everything else is the
     * event argument unchanged, because the generation rides in the same CAS.
     * The retry loop exists because a concurrent release (another client, or
     * the server) changes the word without invalidating our claim to a token:
     * losing the CAS to a +n must not be reported as "not signaled".
     *
     * A count is never "already ours to keep" the way a manual-reset event's
     * state is, so a semaphore always CASes. */
    if (kind == MADEIRA_CELL_KIND_SEM)
    {
        for (;;)
        {
            int cur = MADEIRA_SG_STATE( sg );

            if (cur <= 0) return 0;              /* empty, or DISABLED (-1) */
            if (__atomic_compare_exchange_n( &cell->sg, &sg,
                                             MADEIRA_SG( gen, cur - 1 ), 0,
                                             __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ))
                return 1;
            if (MADEIRA_SG_GEN( sg ) != gen) return 0;   /* recycled under us */
        }
    }
    if (MADEIRA_SG_STATE( sg ) != MADEIRA_CELL_SET) return 0;
    if (manual) return 1;
    return __atomic_compare_exchange_n( &cell->sg, &sg,
                                        MADEIRA_SG( gen, MADEIRA_CELL_RESET ), 0,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST );
}

/* ml1010: NtReleaseSemaphore's whole arithmetic, done on the cell.
 *
 * Returns MADEIRA_FAST_MISS to hand the call to the server, MADEIRA_FAST_DONE
 * when the release is complete, or MADEIRA_FAST_SERVER when the cell is
 * already updated but the server still has to re-run its own wait queue.
 * *status carries STATUS_SEMAPHORE_LIMIT_EXCEEDED for an overflow, which is
 * answered here because the answer is "change nothing" and the cell holds
 * everything needed to decide it.
 *
 * The overflow rule is upstream release_semaphore()'s, read off the same two
 * numbers: count + n must not pass max.  `max' comes out of the cell (it is
 * written before the generation that publishes the cell and never changes), so
 * no extra server state is consulted.  On the error path *previous is NOT
 * written, which is what the server path does too -- NtReleaseSemaphore only
 * copies reply->prev_count when wine_server_call() succeeded. */
static enum madeira_fast_result madeira_fast_sem_release( HANDLE handle, ULONG count,
                                                          ULONG *previous, unsigned int *status )
{
    struct madeira_sync_cell *cell;
    unsigned int manual = 0, gen = 0, kind = 0, max;
    uint64_t sg;
    int cur;

    *status = STATUS_SUCCESS;
    if (!madeira_fastsync_enabled() || !madeira_fast_sem_enabled()) return MADEIRA_FAST_MISS;
    if (!(cell = madeira_fast_lookup( handle, SEMAPHORE_MODIFY_STATE, &manual, &gen, &kind )))
        return MADEIRA_FAST_MISS;
    if (kind != MADEIRA_CELL_KIND_SEM) return MADEIRA_FAST_MISS;

    max = __atomic_load_n( &cell->smax, __ATOMIC_RELAXED );
    if (!max || max > 0x7fffffffu) return MADEIRA_FAST_MISS;   /* cannot happen; do not trust it */

    for (;;)
    {
        sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
        if (MADEIRA_SG_GEN( sg ) != gen) return MADEIRA_FAST_MISS;
        cur = MADEIRA_SG_STATE( sg );
        if (cur < 0) return MADEIRA_FAST_MISS;                 /* DISABLED */
        if (count > max || (unsigned int)cur + count > max)
        {
            *status = STATUS_SEMAPHORE_LIMIT_EXCEEDED;
            return MADEIRA_FAST_DONE;                          /* no state change */
        }
        if (__atomic_compare_exchange_n( &cell->sg, &sg,
                                         MADEIRA_SG( gen, cur + (int)count ), 0,
                                         __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ))
            break;
    }
    if (previous) *previous = (ULONG)cur;
    ios_srv_nt_count( IOS_FS_SEM_REL );
    /* ml1110: the count went up HERE, off-server.  Stamp it before either
     * wake, so a waiter that times out a moment later measures the age of the
     * token and not the age of the notification. */
    if (count) madeira_late_stamp( cell );

    /* Dekker, client half #2: the CAS above and this load are both seq_cst, and
     * a parking waiter does `waiters++; load count' with the same ordering, so
     * the two cannot miss each other.  Wake one for a single token and all for
     * a burst; a waiter woken with nothing left for it simply re-parks. */
    if (count && __atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
    {
        madeira_fast_wake( madeira_cell_futex( cell ), count > 1 );
        ios_srv_nt_count( IOS_NT_FAST_WAKE );
    }

    /* Dekker, client half #1: if the server has anybody queued on this object
     * it is the only thing that can wake them, so a request still has to go --
     * and it is `release_semaphore' with a count of ZERO, which changes nothing
     * and runs wake_up( obj, 0 ).  Releasing again here would mint a second set
     * of tokens out of one ReleaseSemaphore, which is the ml952 double-release
     * bug in its semaphore form. */
    if (count && __atomic_load_n( &cell->srv_waiters, __ATOMIC_SEQ_CST ))
        return MADEIRA_FAST_SERVER;
    return MADEIRA_FAST_DONE;
}

/* NtSetEvent / NtResetEvent. */
static enum madeira_fast_result madeira_fast_event_op( HANDLE handle, int set, LONG *prev_state )
{
    struct madeira_sync_cell *cell;
    unsigned int manual = 0, gen = 0, kind = 0;
    int want = set ? MADEIRA_CELL_SET : MADEIRA_CELL_RESET;
    int prev;

    if (!madeira_fastsync_enabled()) return MADEIRA_FAST_MISS;
    if (!(cell = madeira_fast_lookup( handle, EVENT_MODIFY_STATE, &manual, &gen, &kind )))
        return MADEIRA_FAST_MISS;
    /* ml1010: NtSetEvent on a semaphore handle is a type error the server has
     * to raise, and a cell of the wrong kind must never be written here. */
    if (kind != MADEIRA_CELL_KIND_EVENT) return MADEIRA_FAST_MISS;

    for (;;)
    {
        uint64_t sg;

        /* ml972: a freed cell passes through DISABLED, but the server can
         * re-allocate it to another event before we look, and then the word
         * reads as an ordinary RESET/SET.  The generation is the only thing
         * that separates "my event" from "the event that got my cell", so test
         * it on every attempt rather than trusting DISABLED to still be there.
         *
         * ml990: the test is now the SAME LOAD as the state read, and its
         * result is carried into the CAS below as the expected value -- so a
         * recycle between the two can no longer let this store land on a
         * stranger's event.  That was the last lost-wakeup vector, and it is
         * why the wake path can now default on. */
        sg   = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
        if (MADEIRA_SG_GEN( sg ) != gen) return MADEIRA_FAST_MISS;
        prev = MADEIRA_SG_STATE( sg );
        if (prev == MADEIRA_CELL_DISABLED) return MADEIRA_FAST_MISS;  /* pulsed, or freed */
        /* ml962: MADEIRA_CELL_CLAIMED means the server has decided, inside
         * event_sync_signaled(), to hand this auto-reset token to one of its
         * own queued waiters and has not yet run event_sync_satisfied().
         * Writing over it here LOSES the operation: satisfied() stores RESET
         * unconditionally, so a CAS CLAIMED->SET would be swallowed and the
         * SetEvent would release nobody at all.  The server is single-threaded
         * and cannot process a request between its own signaled() and
         * satisfied(), so handing this to the server is exactly right -- the
         * event_op below is applied strictly after the claim is resolved. */
        if (prev == MADEIRA_CELL_CLAIMED) return MADEIRA_FAST_MISS;
        if (prev == want) break;                                      /* no transition */
        if (__atomic_compare_exchange_n( &cell->sg, &sg, MADEIRA_SG( gen, want ), 0,
                                         __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST )) break;
    }
    if (prev_state) *prev_state = (prev != MADEIRA_CELL_RESET);

    /* A reset can never release anybody, so it is always complete here --
     * including for the server, whose event_sync_signaled() reads this word. */
    if (!set) return MADEIRA_FAST_DONE;

    madeira_late_stamp( cell );   /* ml1110: raised off-server, see above */

    /* Dekker, client half #2: the state store above and this load are both
     * seq_cst, and a parking waiter does `waiters++; load state' with the same
     * ordering, so the two cannot miss each other. */
    if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
    {
        madeira_fast_wake( madeira_cell_futex( cell ), manual );
        ios_srv_nt_count( IOS_NT_FAST_WAKE );
    }

    /* Dekker, client half #1: if the server has anybody queued on this object
     * it is the only thing that can wake them, so the request still has to go.
     * The cell is already updated, so the reply's `state' is stale and the
     * caller ignores it -- and the request the caller sends is
     * MADEIRA_EVENT_OP_WAKE, NOT SET_EVENT: see ios_fastsync.h.  A second
     * server-side set here is what released two waiters for one SetEvent. */
    if (__atomic_load_n( &cell->srv_waiters, __ATOMIC_SEQ_CST )) return MADEIRA_FAST_SERVER;
    return MADEIRA_FAST_DONE;
}

/* ml982: THE READ-ONLY ZERO-TIMEOUT ANSWER ("poll peek").
 *
 * WHY THIS IS A DIFFERENT AND MUCH SMALLER CLAIM THAN THE WAKE PATH.
 * The measurement that motivates all of this has 116607 zero-timeout
 * single-object waits per 10 s, of which 115920 time out.  Every one of them
 * is a full wineserver round trip to be told "no".  Answering the NO from the
 * cell costs nothing and risks nothing, because:
 *
 *  - it never CONSUMES anything.  An auto-reset event cannot be acquired by a
 *    peek: the only answer this function is allowed to give is "not signaled",
 *    and "not signaled" transfers no token, releases nobody and writes no
 *    memory.  The entire lost-wakeup / double-release problem space -- which
 *    is what the wake path is hard for -- is structurally absent.
 *  - the word it reads IS the server's own state.  For a cell-backed event
 *    the server's event_sync_signaled() reads this same address:
 *    MADEIRA_CELL_RESET is exactly the value for which it answers "not
 *    signaled" (manual: st != RESET; auto: a CAS out of SET).  So RESET here
 *    and STATUS_TIMEOUT there are the same fact, not two opinions.
 *  - every other value -- SET, CLAIMED, DISABLED -- and every doubt about
 *    whether this cell is still ours goes to the server untouched.
 *  - one poll in MADEIRA_FS_PEEK_EVERY goes to the server anyway, which bounds
 *    system-APC latency and makes a wrong cache entry self-correcting.
 *
 * This is why it is the half that ships ON by default while the wake path does
 * not.
 *
 * The gate is per THREAD and is stepped exactly once per peeked poll. */
static inline int madeira_peek_budget(void)
{
    static __thread unsigned int streak;
    unsigned int s = ++streak;

    /* The yield test comes FIRST and is independent of the server test: both
     * periods are powers of two, so testing the server one first would make
     * every yield point fall on a poll that went to the server anyway and the
     * yield would never happen. */
    if (!(s & (MADEIRA_FS_PEEK_YIELD - 1))) NtYieldExecution();
    return (s & (MADEIRA_FS_PEEK_EVERY - 1)) != 0;    /* 0 = send this one to the server */
}

/* "is this cell provably NOT signaled right now?"
 *
 * ml982 read the state word and then re-read `gen' after it, so that an
 * unchanged generation either side of the load proved no recycle had happened
 * across it.  ml990 gets both out of ONE load, which is the same proof without
 * the sandwich: at the instant of that load the cell carried our generation
 * and read RESET, so the RESET was our event's. */
static inline int madeira_peek_cell( struct madeira_sync_cell *cell, unsigned int gen )
{
    uint64_t sg;

    if (!__atomic_load_n( &madeira_fast_peek, __ATOMIC_RELAXED )) return 0;
    if (!madeira_peek_budget()) return 0;
    sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
    if (MADEIRA_SG_GEN( sg ) != gen) return 0;
    /* MADEIRA_CELL_RESET is 0, which for a SEMAPHORE cell is exactly "the
     * count is empty" -- the same value and the same meaning, so this test
     * needs no kind of its own.  Every other value goes to the server. */
    if (MADEIRA_SG_STATE( sg ) != MADEIRA_CELL_RESET) return 0;
    ios_srv_nt_count( IOS_FS_POLLPEEK );
    return 1;
}

/* A single-handle, non-alertable, non-wait-all wait.
 *
 * Returns STATUS_SUCCESS when the wait was satisfied with no server call,
 * STATUS_TIMEOUT when a zero-timeout poll was answered from the cell, or
 * STATUS_NOT_IMPLEMENTED for "fall through to server_wait", in which case
 * *fallback is the timeout the caller must use from here (a relative timeout
 * is reduced by the time this function spent, so the total wait is unchanged;
 * an absolute one needs no adjustment). */
static NTSTATUS madeira_fast_wait_inner( HANDLE handle, const LARGE_INTEGER *timeout,
                                         const LARGE_INTEGER **fallback, LARGE_INTEGER *store )
{
    struct madeira_sync_cell *cell;
    unsigned int manual = 0, gen = 0, kind = 0;
    unsigned long long t0, spent = 0, budget_ns, park_t0 = 0;
    int i, st, rounds, parked = 0;

    *fallback = timeout;
    if (!madeira_fastsync_enabled())
    {
        /* Wake path off (the default).  The read-only peek still applies, and
         * it is the only thing this function may do in that mode. */
        if (timeout && !timeout->QuadPart && madeira_fast_cells_enabled() &&
            __atomic_load_n( &madeira_fast_peek, __ATOMIC_RELAXED ) &&
            (cell = madeira_fast_lookup( handle, SYNCHRONIZE, &manual, &gen, &kind )) &&
            madeira_peek_cell( cell, gen ))
            return STATUS_TIMEOUT;
        return STATUS_NOT_IMPLEMENTED;
    }
    if (!(cell = madeira_fast_lookup( handle, SYNCHRONIZE, &manual, &gen, &kind )))
        return STATUS_NOT_IMPLEMENTED;

    if (madeira_fast_try( cell, manual, gen, kind ))
    {
        ios_srv_nt_count( IOS_NT_FAST_HIT );
        if (kind == MADEIRA_CELL_KIND_SEM) ios_srv_nt_count( IOS_FS_SEM_WAIT );
        return STATUS_SUCCESS;
    }

    /* A zero timeout is a state query.  madeira_fast_try() has just failed to
     * take a token, which for an auto-reset event means either "not signaled"
     * or "somebody else took it first" -- both of which are STATUS_TIMEOUT for
     * this caller, but only the cell can say which, and only the RESET answer
     * may be given here (see madeira_peek_cell). */
    if (timeout && !timeout->QuadPart)
    {
        if (madeira_peek_cell( cell, gen )) return STATUS_TIMEOUT;
        ios_srv_nt_count( IOS_NT_FAST_MISS );
        return STATUS_NOT_IMPLEMENTED;
    }

    for (i = 0; i < MADEIRA_FAST_SPIN; i++)
    {
        __asm__ __volatile__( "isb" ::: "memory" );
        if (madeira_fast_try( cell, manual, gen, kind ))
        {
            ios_srv_nt_count( IOS_NT_FAST_HIT );
            if (kind == MADEIRA_CELL_KIND_SEM) ios_srv_nt_count( IOS_FS_SEM_WAIT );
            return STATUS_SUCCESS;
        }
    }

    /* ml1050 PHASE B: the adaptive, time-bounded spin.  The ladder above is an
     * iteration count and cannot be a duration; this is a duration and reads
     * the clock once per block of MADEIRA_FAST_SPIN isbs rather than once per
     * iteration, so the measurement does not dominate the thing measured.  It
     * is skipped entirely when the credit has decayed (budget 0), which costs
     * one relaxed load. */
    {
        int spin_probe = 0;
        unsigned long long spin_ns = madeira_fast_spin_budget_ns( timeout, &spin_probe );

        if (spin_ns)
        {
            unsigned long long s0 = madeira_now_ns();
            for (;;)
            {
                for (i = 0; i < MADEIRA_FAST_SPIN; i++)
                {
                    __asm__ __volatile__( "isb" ::: "memory" );
                    if (madeira_fast_try( cell, manual, gen, kind ))
                    {
                        ios_srv_nt_count( IOS_NT_FAST_HIT );
                        __atomic_fetch_add( &madeira_fast_spin_hits, 1, __ATOMIC_RELAXED );
                        if (kind == MADEIRA_CELL_KIND_SEM) ios_srv_nt_count( IOS_FS_SEM_WAIT );
                        /* ml1100: a probe that paid re-arms; an ordinary spin that
                         * paid nudges.  See MADEIRA_SPIN_CREDIT_REARM. */
                        if (spin_probe)
                            madeira_fast_spin_credit_add( MADEIRA_SPIN_CREDIT_REARM );
                        else
                            madeira_fast_spin_credit_add( MADEIRA_SPIN_CREDIT_UP );
                        return STATUS_SUCCESS;
                    }
                }
                /* A generation change means the cell was recycled under us:
                 * stop spinning on a stranger's object and let the loop below
                 * take the miss. */
                if (!madeira_cell_alive( cell, gen )) break;
                if (madeira_now_ns() - s0 >= spin_ns) break;
            }
            __atomic_fetch_add( &madeira_fast_spin_misses, 1, __ATOMIC_RELAXED );
            madeira_fast_spin_credit_add( -1 );
        }
    }

    /* Never park past the caller's own relative timeout: doing so would turn a
     * 200 us WaitForSingleObject into a 2 ms one. */
    budget_ns = madeira_fast_cap_ns;
    if (timeout && timeout->QuadPart < 0 &&
        (unsigned long long)(-timeout->QuadPart) * 100 < budget_ns)
        budget_ns = (unsigned long long)(-timeout->QuadPart) * 100;

    /* ml972: `rounds' bounds the loop independently of the clock.  Every
     * iteration either parks for the whole remaining budget or finds the word
     * already changed, so a handful of rounds is plenty; the point of the
     * counter is that a clock which stops, jumps or returns garbage can no
     * longer turn this into an unbounded spin (or, with the old code, into a
     * single pass that charged the caller a bogus amount of time). */
    t0 = madeira_now_ns();
    for (rounds = 0; rounds < 64; rounds++)
    {
        spent = madeira_now_ns() - t0;

        if (spent >= budget_ns) break;

        __atomic_add_fetch( &cell->waiters, 1, __ATOMIC_SEQ_CST );
        {
            /* ml990: one load answers both "is it still mine" and "what is the
             * state", so a cell recycled between the two can no longer make
             * this thread park on a stranger's futex word believing it is its
             * own.  A generation mismatch here takes the same exit as a
             * mismatch after the park: leave `waiters' alone (it now belongs
             * to the new occupant's count) and hand the wait to the server. */
            uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );

            if (MADEIRA_SG_GEN( sg ) != gen) break;
            st = MADEIRA_SG_STATE( sg );
        }
        if (st == MADEIRA_CELL_RESET)
        {
            ios_srv_nt_count( IOS_NT_FAST_SLEEP );
            /* the value is re-tested inside the syscall, so a set landing
             * between the load above and here does not sleep */
            park_t0 = madeira_now_ns();
            madeira_fast_park( madeira_cell_futex( cell ), MADEIRA_CELL_RESET, budget_ns - spent );
            parked = 1;
        }

        /* ml972 DEFECT 2: THE PARK IS THE ONE UNBOUNDED PAUSE IN HERE, AND THE
         * CELL CAN CHANGE OWNER ACROSS IT.
         *
         * While this thread was parked the event it is waiting for can be
         * destroyed (its last handle closed) and the server can hand the cell
         * to a brand new event.  madeira_cell_free() does store DISABLED and
         * wake everyone, but the very next create_event can re-allocate the
         * same cell and store RESET or SET over it before this thread is
         * scheduled -- and at that point the state word is indistinguishable
         * from our own event's.  Two things go wrong without this check:
         *
         *  - madeira_fast_try() below would CONSUME the new occupant's
         *    auto-reset token: one SetEvent delivered to a thread that never
         *    waited on that event, and the thread that did wait never woken.
         *    With a loader creating and closing events thousands of times a
         *    second, cells are recycled constantly and that is a lost wakeup
         *    on a live handshake -- a worker that never resumes.
         *
         *  - the `waiters' decrement would pay back a count the server has
         *    already zeroed (madeira_cell_alloc resets it), taking the new
         *    occupant's count to -1.  The next genuine waiter's `waiters++'
         *    then brings it back to 0, so a setter's `if (waiters) wake' does
         *    nothing and that waiter sleeps out the whole cap on every handoff
         *    from then on.  Over-counting only ever costs a spurious
         *    os_sync_wake, so leave the count alone instead.
         *
         * The generation is bumped on both free and alloc, so one load decides
         * it.  A mismatch means "this handle is no longer mine to reason
         * about": hand the wait to the server, which owns the handle table and
         * will return the real status (including STATUS_INVALID_HANDLE if the
         * handle really is gone). */
        if (!madeira_cell_alive( cell, gen )) break;
        __atomic_sub_fetch( &cell->waiters, 1, __ATOMIC_SEQ_CST );

        /* DISABLED (pulsed/freed) or CLAIMED (a server-side waiter is being
         * handed this token right now) both mean "queue with the server".
         *
         * ml1010: for a SEMAPHORE cell there is no CLAIMED -- 2 is a count of
         * two -- so the only value that means "go to the server" is the
         * negative one, and every non-negative count is a legal state to keep
         * trying from. */
        if (kind == MADEIRA_CELL_KIND_SEM)
        {
            if (st < 0) break;
        }
        else if (st != MADEIRA_CELL_RESET && st != MADEIRA_CELL_SET) break;
        if (madeira_fast_try( cell, manual, gen, kind ))
        {
            ios_srv_nt_count( IOS_NT_FAST_HIT );
            if (kind == MADEIRA_CELL_KIND_SEM) ios_srv_nt_count( IOS_FS_SEM_WAIT );
            /* ml1050: THE WAKE-LATENCY DISTRIBUTION, WHICH NOTHING MEASURED.
             *
             * This is the interval from entering the park to the CAS that
             * satisfied the wait -- i.e. how long a handoff that had to go
             * through the kernel actually took, measured only on handoffs that
             * completed.  It is the number the spin budget has to be set
             * against: a p50 of a few microseconds says the 40 us timed spin
             * will pay for itself, a p50 in the hundreds says the signaller
             * genuinely was not ready and spinning only burns a core.
             *
             * Not measured from the signaller's CAS on purpose: that would
             * need a timestamp inside the shared cell, and the cell is 32
             * bytes with two per cache line by design (ios_fastsync.h) and its
             * size is asserted by build/host-tests/fastsync-cellrace.c.  The
             * park-to-satisfied interval is an upper bound on the true wake
             * latency and answers the same question. */
            if (parked) madeira_fast_park_hist_add( madeira_now_ns() - park_t0 );
            return STATUS_SUCCESS;
        }
    }

    if (timeout && timeout->QuadPart < 0)
    {
        /* ml972 DEFECT 1, HALF B: THE REMAINDER IS AN INVARIANT, NOT A
         * MEASUREMENT.
         *
         * budget_ns is by construction min(cap, the caller's whole timeout),
         * and the loop above may not park past it -- so this function can only
         * ever have consumed budget_ns of the caller's wait.  ml962 instead
         * re-read the clock here and subtracted whatever came out, which made
         * the caller's remaining timeout a function of the clock rather than
         * of the policy: any overshoot (a clock that counts time the park did
         * not, a park that overslept its own timeout, a preemption between the
         * last loop test and here) came straight off the caller's budget, and
         * a large enough one drove `left' to zero.  A zero relative timeout is
         * not "no time left", it is Wine's POLL: server_wait returns
         * STATUS_TIMEOUT without waiting at all.  That is the reported bug --
         * WaitForSingleObject(ev, 300) returning WAIT_TIMEOUT after 0 ms --
         * and in a program that treats a timed wait as a sleep it is also an
         * unbounded busy loop.
         *
         * Clamping the elapsed time to the budget makes the failure
         * unrepresentable: left >= |timeout| - budget_ns/100 >= 0, and it is 0
         * only when the budget WAS the caller's whole timeout (a wait shorter
         * than the cap, which really has expired).  Erring long is the safe
         * direction for a timeout; erring short is a wait that never waits. */
        long long left;

        spent = madeira_now_ns() - t0;
        if (spent > budget_ns) spent = budget_ns;
        left = -timeout->QuadPart - (long long)(spent / 100);
        store->QuadPart = (left > 0) ? -left : 0;
        *fallback = store;
    }
    ios_srv_nt_count( IOS_NT_FAST_MISS );
    return STATUS_NOT_IMPLEMENTED;
}

/* ml1050: the presenting thread's fast-path wait time, for the [frame] line.
 * A wrapper rather than a stamp at each of the seven returns: the question is
 * how long the CALL took, and that is one measurement, not seven.  On every
 * thread but the presenter this is a register read, a compare and a branch --
 * ios_frame_tracking() is inline and reads no memory the caller did not
 * already have. */
static NTSTATUS madeira_fast_wait( HANDLE handle, const LARGE_INTEGER *timeout,
                                   const LARGE_INTEGER **fallback, LARGE_INTEGER *store )
{
    unsigned long long t0;
    NTSTATUS ret;

    if (!ios_frame_tracking())
        return madeira_fast_wait_inner( handle, timeout, fallback, store );
    t0 = madeira_now_ns();
    ret = madeira_fast_wait_inner( handle, timeout, fallback, store );
    ios_frame_wait_add( IOS_FRAME_WAIT_FAST, madeira_now_ns() - t0 );
    return ret;
}

/***********************************************************************
 *   ml982: THE WATCHDOG -- a hang becomes a logged hiccup
 *
 * WHERE A HANG CAN ACTUALLY LIVE.  The fast path parks for at most
 * madeira_fast_cap_ns (2 ms, 50 ms at the top of the knob's range) and then
 * hands the wait to the server, so "parked on a cell for two seconds" is not a
 * state this code can reach.  A thread that is stuck is stuck in server_wait,
 * and once it is there only the server can wake it.  So the watchdog cannot
 * live in the park loop: it has to live in the fall-through, and the way to
 * give an INFINITE wait a heartbeat is to stop making it infinite.
 *
 * WHAT IT LOOKS FOR.  Both sides read the same word, so they cannot disagree
 * about RESET vs SET by opinion -- only by accident.  The one observable
 * accident is: the server has just evaluated this object and said NOT
 * SIGNALED, while the cell says SET.  That is a token nobody can collect: the
 * wake that should have followed the set was lost, or the set landed on a cell
 * that is no longer the one the server is reading.  Either way this thread
 * would wait forever.
 *
 * WHY THE SECOND OPINION.  A plain "the timed wait expired and the cell says
 * SET" is a false positive whenever the set simply landed in the gap between
 * the two.  So the check re-asks the server with a ZERO-timeout select, which
 * is both the confirmation and the cure when there is nothing wrong: if the
 * object really is signaled the server satisfies the wait there and then and
 * the caller gets its STATUS_SUCCESS.  Only "server says no AND the cell still
 * says SET" is reported.
 *
 * WHAT IT DOES ABOUT IT.  One log line per process, a counter for the rest,
 * and MADEIRA_EVENT_OP_DISABLE on that one object -- the PulseEvent exit,
 * which folds the cell state back into the server's own bit, wakes every
 * parked client and makes every future operation on that event take the server
 * path.  A false positive therefore costs one permanently slower event and
 * nothing else, which is the right price for never hanging.
 *
 * COST ON THE HOT PATH: none.  This runs only for an INFINITE single-object
 * wait that the wake path could not satisfy, only when the wake path is
 * active, and then once per interval per parked thread -- and the interval
 * backs off ×4 to a minute, so a worker idle for an hour costs about 60
 * requests, against the 338000 per 10 s this mechanism exists to remove.
 ***********************************************************************/

#define MADEIRA_FS_WATCH_MS_FIRST   2000u
#define MADEIRA_FS_WATCH_MS_MAX    60000u

static int madeira_desync_logged;

/* Take one object out of the fast path for good.  Best effort: a failure here
 * (a handle that has meanwhile been closed, say) leaves the object exactly as
 * it was, which is the state we were already coping with. */
static void madeira_fast_demote( HANDLE handle, unsigned int kind )
{
    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        /* ml1010: the semaphore opcode is answered ahead of event_op's own
         * object-type check, because the handle is a semaphore handle. */
        req->op     = (kind == MADEIRA_CELL_KIND_SEM) ? MADEIRA_SEM_OP_DISABLE
                                                      : MADEIRA_EVENT_OP_DISABLE;
        wine_server_call( req );
    }
    SERVER_END_REQ;
    madeira_fast_close( handle );   /* forget the cell; the next learn says -1 */
}

/* Returns a status to hand back to the caller, or STATUS_NOT_IMPLEMENTED for
 * "no verdict, keep waiting". */
static unsigned int madeira_fast_watchdog_check( HANDLE handle, unsigned int flags,
                                                 const union select_op *op, data_size_t size )
{
    struct madeira_sync_cell *cell;
    unsigned int manual = 0, gen = 0, kind = 0, ret;
    LARGE_INTEGER zero;
    int st, st2;

    ios_srv_nt_count( IOS_FS_WATCHDOG );
    if (!(cell = madeira_fast_lookup( handle, SYNCHRONIZE, &manual, &gen, &kind )))
        return STATUS_NOT_IMPLEMENTED;             /* not a cell object any more */

    {
        uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
        if (MADEIRA_SG_GEN( sg ) != gen) return STATUS_NOT_IMPLEMENTED;
        st = MADEIRA_SG_STATE( sg );
    }
    /* RESET is the coherent answer and DISABLED means the server is already
     * authoritative; CLAIMED is a token in flight on the server thread, which
     * resolves in nanoseconds and is nobody's hang.
     *
     * ml1010: for a SEMAPHORE the same question is "the cell says there is a
     * token (count > 0) while this thread is still waiting", i.e. st > 0. */
    if (kind == MADEIRA_CELL_KIND_SEM) { if (st <= 0) return STATUS_NOT_IMPLEMENTED; }
    else if (st != MADEIRA_CELL_SET) return STATUS_NOT_IMPLEMENTED;

    /* Second opinion, and the cure if there is nothing wrong. */
    zero.QuadPart = 0;
    ret = server_wait( op, size, flags, &zero );
    if (ret != STATUS_TIMEOUT) return ret;         /* satisfied, or a real status */

    {
        uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
        st2 = MADEIRA_SG_STATE( sg );
        if (MADEIRA_SG_GEN( sg ) != gen) return STATUS_NOT_IMPLEMENTED;
        if (kind == MADEIRA_CELL_KIND_SEM)
        {
            if (st2 <= 0) return STATUS_NOT_IMPLEMENTED;   /* somebody consumed it: fine */
        }
        else if (st2 != MADEIRA_CELL_SET) return STATUS_NOT_IMPLEMENTED;
    }

    ios_srv_nt_count( IOS_FS_DESYNC );
    if (!__atomic_exchange_n( &madeira_desync_logged, 1, __ATOMIC_RELAXED ))
        ERR( "[fastsync] DESYNC handle=%p kind=%s cell=%d gen=%u state=%d/%d waiters=%d "
             "srv_waiters=%d manual=%u - the server reports this object NOT signaled while "
             "the shared cell says signaled; demoting it to the server path permanently.  "
             "Further occurrences are counted as desync= in [srv-stats].\n",
             handle, kind == MADEIRA_CELL_KIND_SEM ? "sem" : "event",
             (int)(cell - madeira_sync_cells),
             MADEIRA_SG_GEN( __atomic_load_n( &cell->sg, __ATOMIC_RELAXED ) ), st, st2,
             __atomic_load_n( &cell->waiters, __ATOMIC_RELAXED ),
             __atomic_load_n( &cell->srv_waiters, __ATOMIC_RELAXED ), manual );

    madeira_fast_demote( handle, kind );
    return STATUS_NOT_IMPLEMENTED;                 /* re-wait, now on the server */
}

/***********************************************************************
 *   ml1110: THE LATE-WAKE CENSUS, RECORDING SIDE
 ***********************************************************************/

static void madeira_late_charge_hot( unsigned int idx, unsigned int kind )
{
    unsigned int i;

    for (i = 0; i < IOS_LATE_HOT_N; i++)
    {
        unsigned int have = __atomic_load_n( &madeira_late_hot_cell[i], __ATOMIC_RELAXED );

        if (have == idx + 1u)
        {
            __atomic_fetch_add( &madeira_late_hot_n[i], 1, __ATOMIC_RELAXED );
            return;
        }
        if (!have)
        {
            unsigned int zero = 0;

            if (__atomic_compare_exchange_n( &madeira_late_hot_cell[i], &zero, idx + 1u, 0,
                                             __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
            {
                __atomic_store_n( &madeira_late_hot_kind[i], kind, __ATOMIC_RELAXED );
                __atomic_fetch_add( &madeira_late_hot_n[i], 1, __ATOMIC_RELAXED );
                return;
            }
            i--;                                   /* somebody took it; re-read */
        }
    }
    /* more than IOS_LATE_HOT_N distinct objects in one window: the totals above
     * still count it, only the naming is dropped */
}

/* One timed wait has just come back STATUS_TIMEOUT.  `hb' distinguishes the
 * ml982/ml1060 heartbeat's own expiry (the caller asked for INFINITE) from a
 * finite timeout the GUEST asked for, because the two mean different things:
 * a late heartbeat is a wake this port owed and did not deliver, while a late
 * guest timeout is that plus a result the guest can legitimately observe. */
static void madeira_late_note( HANDLE handle, int hb )
{
    struct madeira_sync_cell *cell;
    unsigned int manual = 0, gen = 0, kind = 0, b, age_us;
    unsigned int rel;
    uint64_t sg;

    if (!madeira_late_enabled()) return;
    __atomic_fetch_add( &madeira_late_counts[hb ? MADEIRA_LATE_HB : MADEIRA_LATE_TMO_FIN],
                        1, __ATOMIC_RELAXED );
    /* MADEIRA_FASTSYNC=0 means there are no cells to read, and without this
     * gate the lookup below would issue one get_inproc_sync_fd per handle to
     * learn that -- an extra request on the one path whose whole point is to
     * be the pre-fastsync port.  `tmo_fin' above is still counted, because it
     * costs nothing and the rate is worth having in both configurations. */
    if (!madeira_fast_cells_enabled()) return;
    if (!(cell = madeira_fast_lookup( handle, SYNCHRONIZE, &manual, &gen, &kind ))) return;

    sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
    if (MADEIRA_SG_GEN( sg ) != gen) return;        /* recycled: says nothing */
    if (!madeira_cell_signalled( kind, manual, MADEIRA_SG_STATE( sg ) )) return;

    /* From here on: the wait expired while the object could have released it. */
    if (hb) __atomic_fetch_add( &madeira_late_counts[MADEIRA_LATE_HB_LATE], 1, __ATOMIC_RELAXED );
    __atomic_fetch_add( &madeira_late_counts[kind == MADEIRA_CELL_KIND_SEM
                                             ? MADEIRA_LATE_SEM : MADEIRA_LATE_EVENT],
                        1, __ATOMIC_RELAXED );
    madeira_late_charge_hot( (unsigned int)(cell - madeira_sync_cells), kind );

    rel = __atomic_load_n( &cell->rel_us, __ATOMIC_RELAXED );
    if (!rel)
    {
        /* signalled, but no CLIENT release ever raised this cell -- so the
         * server raised it, and a server-side release walks its own queue in
         * the same call.  Counted apart rather than bucketed at age 0, which
         * would make the distribution say the opposite of the truth. */
        __atomic_fetch_add( &madeira_late_counts[MADEIRA_LATE_NOSTAMP], 1, __ATOMIC_RELAXED );
        return;
    }
    age_us = (unsigned int)(madeira_now_ns() / 1000) - rel;   /* wrap-safe */
    for (b = 0; b + 1 < IOS_LATE_AGE_N && age_us >= (1u << b); b++) ;
    __atomic_fetch_add( &madeira_late_age[b], 1, __ATOMIC_RELAXED );
}

/* "a release whose wake was delivered only by a later timeout", counted at the
 * one place that can see both halves: the heartbeat timed out, and the
 * watchdog's zero-timeout re-ask then satisfied the wait on the spot. */
static inline void madeira_late_rescued(void)
{
    if (madeira_late_enabled())
        __atomic_fetch_add( &madeira_late_counts[MADEIRA_LATE_RESCUED], 1, __ATOMIC_RELAXED );
}

unsigned int madeira_late_wake_peek( unsigned int *rescued )
{
    *rescued = __atomic_load_n( &madeira_late_counts[MADEIRA_LATE_RESCUED], __ATOMIC_RELAXED );
    return __atomic_load_n( &madeira_late_counts[MADEIRA_LATE_SEM], __ATOMIC_RELAXED )
         + __atomic_load_n( &madeira_late_counts[MADEIRA_LATE_EVENT], __ATOMIC_RELAXED );
}

void madeira_late_wake_snapshot( struct ios_late_snapshot *out )
{
    unsigned int i, total = 0, acc = 0;

    memset( out, 0, sizeof(*out) );
    out->tmo_fin    = __atomic_exchange_n( &madeira_late_counts[MADEIRA_LATE_TMO_FIN], 0, __ATOMIC_RELAXED );
    out->late_sem   = __atomic_exchange_n( &madeira_late_counts[MADEIRA_LATE_SEM], 0, __ATOMIC_RELAXED );
    out->late_event = __atomic_exchange_n( &madeira_late_counts[MADEIRA_LATE_EVENT], 0, __ATOMIC_RELAXED );
    out->nostamp    = __atomic_exchange_n( &madeira_late_counts[MADEIRA_LATE_NOSTAMP], 0, __ATOMIC_RELAXED );
    out->hb         = __atomic_exchange_n( &madeira_late_counts[MADEIRA_LATE_HB], 0, __ATOMIC_RELAXED );
    out->hb_late    = __atomic_exchange_n( &madeira_late_counts[MADEIRA_LATE_HB_LATE], 0, __ATOMIC_RELAXED );
    out->rescued    = __atomic_exchange_n( &madeira_late_counts[MADEIRA_LATE_RESCUED], 0, __ATOMIC_RELAXED );

    for (i = 0; i < IOS_LATE_AGE_N; i++)
    {
        out->age[i] = __atomic_exchange_n( &madeira_late_age[i], 0, __ATOMIC_RELAXED );
        total += out->age[i];
    }
    /* Percentiles are read off the log2 histogram and reported as the bucket's
     * LOWER bound, so they never overstate -- the same rule [sleep0] uses. */
    for (i = 0; i < IOS_LATE_AGE_N && total; i++)
    {
        acc += out->age[i];
        if (!out->age_p50 && acc * 2 >= total) out->age_p50 = i ? (1u << (i - 1)) : 0;
        if (!out->age_p90 && acc * 10 >= total * 9) { out->age_p90 = i ? (1u << (i - 1)) : 0; break; }
    }

    for (i = 0; i < IOS_LATE_HOT_N; i++)
    {
        unsigned int c = __atomic_exchange_n( &madeira_late_hot_cell[i], 0, __ATOMIC_RELAXED );

        out->hot[i].cell = c ? c - 1u : 0xffffffffu;
        out->hot[i].kind = __atomic_exchange_n( &madeira_late_hot_kind[i], 0, __ATOMIC_RELAXED );
        out->hot[i].late = __atomic_exchange_n( &madeira_late_hot_n[i], 0, __ATOMIC_RELAXED );
    }
}

/* The INFINITE single-object wait, with a heartbeat.  Used only when the wake
 * path is live; otherwise the caller issues the plain infinite server_wait it
 * always did.
 *
 * ml1060: IT NOW COVERS ALERTABLE WAITS TOO, AND THAT IS THE WHOLE POINT.
 *
 * Through ml1050 both callers gated this on `!alertable', alongside the gate on
 * madeira_fast_wait() -- which genuinely does need it, because a thread parked
 * on a futex cell cannot notice a queued user APC.  The heartbeat needs no such
 * thing: every iteration is an ordinary server_wait with the caller's own
 * `flags' (SELECT_ALERTABLE included), so an APC still comes back as
 * STATUS_USER_APC and is returned to the caller unchanged; the ONLY difference
 * from a single infinite wait is that a wait which has produced nothing for
 * `ms' is re-asked.
 *
 * What the gate cost is measurable in a device log: k67, a managed-runtime
 * title whose worker waits are all `WaitForSingleObjectEx( h, INFINITE, TRUE )',
 * shows `select: w1 inf=56429' per 10 s -- 56429 infinite single-object waits
 * that reached the server with timeout == NULL, i.e. that never entered this
 * function -- together with `watchdog=3(8)' and `desync=0(0)'.  desync=0 there
 * is not evidence of health: it is evidence that the detector was switched off
 * for every thread that could hang.  The same gate is why `sem_wait=0(4)' and
 * `pollpeek=0(1)': an alertable wait sees none of this mechanism.  The wake
 * path and the peek keep the gate (a peek answering STATUS_TIMEOUT would skip
 * the STATUS_USER_APC an alertable zero-timeout wait owes its caller); the
 * heartbeat, which always goes to the server, does not. */
static unsigned int madeira_fast_watched_wait( const union select_op *op, data_size_t size,
                                               unsigned int flags, HANDLE handle )
{
    unsigned int ms = MADEIRA_FS_WATCH_MS_FIRST, ret, manual = 0, gen = 0, kind = 0;

    /* Only a cell-backed object can desync, and only one is worth waking a
     * parked thread for.  A wait on a thread, a process, a mutex, a timer or a
     * file keeps the plain infinite wait it always had -- this is answered from
     * the negative cache, so it is a couple of loads.  ml1010 adds semaphores
     * to the set that gets the heartbeat. */
    if (!madeira_fast_lookup( handle, SYNCHRONIZE, &manual, &gen, &kind ))
        return server_wait( op, size, flags, NULL );

    for (;;)
    {
        LARGE_INTEGER t;

        t.QuadPart = -(LONGLONG)ms * 10000;
        if ((ret = server_wait( op, size, flags, &t )) != STATUS_TIMEOUT) return ret;
        /* ml1110: the heartbeat expired.  Ask the cell, before the watchdog's
         * zero-timeout re-ask changes it, whether this wait was owed a wake. */
        madeira_late_note( handle, 1 );
        ret = madeira_fast_watchdog_check( handle, flags, op, size );
        if (ret != STATUS_NOT_IMPLEMENTED)
        {
            /* ml1110: the re-ask SATISFIED it.  This wait was delivered by a
             * timer, not by a wake, and that is the number this census exists
             * to produce.  A real status other than SUCCESS (a user APC, an
             * abandoned mutex) is not a rescue and is not counted as one. */
            if (ret == STATUS_WAIT_0) madeira_late_rescued();
            return ret;
        }
        if (ms < MADEIRA_FS_WATCH_MS_MAX)
        {
            ms *= 4;
            if (ms > MADEIRA_FS_WATCH_MS_MAX) ms = MADEIRA_FS_WATCH_MS_MAX;
        }
    }
}

#endif /* WINE_IOS */


/* create a struct security_descriptor and contained information in one contiguous piece of memory */
unsigned int alloc_object_attributes( const OBJECT_ATTRIBUTES *attr, struct object_attributes **ret,
                                      data_size_t *ret_len )
{
    unsigned int len = sizeof(**ret);
    SID *owner = NULL, *group = NULL;
    ACL *dacl = NULL, *sacl = NULL;
    SECURITY_DESCRIPTOR *sd;

    *ret = NULL;
    *ret_len = 0;

    if (!attr) return STATUS_SUCCESS;

    if (attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if ((sd = attr->SecurityDescriptor))
    {
        len += sizeof(struct security_descriptor);
	if (sd->Revision != SECURITY_DESCRIPTOR_REVISION) return STATUS_UNKNOWN_REVISION;
        if (sd->Control & SE_SELF_RELATIVE)
        {
            SECURITY_DESCRIPTOR_RELATIVE *rel = (SECURITY_DESCRIPTOR_RELATIVE *)sd;
            if (rel->Owner) owner = (PSID)((BYTE *)rel + rel->Owner);
            if (rel->Group) group = (PSID)((BYTE *)rel + rel->Group);
            if ((sd->Control & SE_SACL_PRESENT) && rel->Sacl) sacl = (PSID)((BYTE *)rel + rel->Sacl);
            if ((sd->Control & SE_DACL_PRESENT) && rel->Dacl) dacl = (PSID)((BYTE *)rel + rel->Dacl);
        }
        else
        {
            owner = sd->Owner;
            group = sd->Group;
            if (sd->Control & SE_SACL_PRESENT) sacl = sd->Sacl;
            if (sd->Control & SE_DACL_PRESENT) dacl = sd->Dacl;
        }

        if (owner) len += offsetof( SID, SubAuthority[owner->SubAuthorityCount] );
        if (group) len += offsetof( SID, SubAuthority[group->SubAuthorityCount] );
        if (sacl) len += sacl->AclSize;
        if (dacl) len += dacl->AclSize;

        /* fix alignment for the Unicode name that follows the structure */
        len = (len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        if ((ULONG_PTR)attr->ObjectName->Buffer & (sizeof(WCHAR) - 1)) return STATUS_DATATYPE_MISALIGNMENT;
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
        len += attr->ObjectName->Length;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    len = (len + 3) & ~3;  /* DWORD-align the entire structure */

    if (!(*ret = calloc( len, 1 ))) return STATUS_NO_MEMORY;

    (*ret)->rootdir = wine_server_obj_handle( attr->RootDirectory );
    (*ret)->attributes = attr->Attributes;

    if (attr->SecurityDescriptor)
    {
        struct security_descriptor *descr = (struct security_descriptor *)(*ret + 1);
        unsigned char *ptr = (unsigned char *)(descr + 1);

        descr->control = sd->Control & ~SE_SELF_RELATIVE;
        if (owner) descr->owner_len = offsetof( SID, SubAuthority[owner->SubAuthorityCount] );
        if (group) descr->group_len = offsetof( SID, SubAuthority[group->SubAuthorityCount] );
        if (sacl) descr->sacl_len = sacl->AclSize;
        if (dacl) descr->dacl_len = dacl->AclSize;

        memcpy( ptr, owner, descr->owner_len );
        ptr += descr->owner_len;
        memcpy( ptr, group, descr->group_len );
        ptr += descr->group_len;
        memcpy( ptr, sacl, descr->sacl_len );
        ptr += descr->sacl_len;
        memcpy( ptr, dacl, descr->dacl_len );
        (*ret)->sd_len = (sizeof(*descr) + descr->owner_len + descr->group_len + descr->sacl_len +
                          descr->dacl_len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        unsigned char *ptr = (unsigned char *)(*ret + 1) + (*ret)->sd_len;
        (*ret)->name_len = attr->ObjectName->Length;
        memcpy( ptr, attr->ObjectName->Buffer, (*ret)->name_len );
    }

    *ret_len = len;
    return STATUS_SUCCESS;
}


static unsigned int validate_open_object_attributes( const OBJECT_ATTRIBUTES *attr )
{
    if (!attr || attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if (attr->ObjectName)
    {
        if ((ULONG_PTR)attr->ObjectName->Buffer & (sizeof(WCHAR) - 1)) return STATUS_DATATYPE_MISALIGNMENT;
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    return STATUS_SUCCESS;
}

#ifdef NTSYNC_IOC_EVENT_READ

static NTSTATUS linux_release_semaphore_obj( int obj, ULONG count, ULONG *prev_count )
{
    if (ioctl( obj, NTSYNC_IOC_SEM_RELEASE, &count ) < 0)
    {
        if (errno == EOVERFLOW) return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        return errno_to_status( errno );
    }
    if (prev_count) *prev_count = count;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_query_semaphore_obj( int obj, SEMAPHORE_BASIC_INFORMATION *info )
{
    struct ntsync_sem_args args = {0};
    if (ioctl( obj, NTSYNC_IOC_SEM_READ, &args ) < 0) return errno_to_status( errno );
    info->CurrentCount = args.count;
    info->MaximumCount = args.max;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_set_event_obj( int obj, LONG *prev_state )
{
    __u32 prev;
    if (ioctl( obj, NTSYNC_IOC_EVENT_SET, &prev ) < 0) return errno_to_status( errno );
    if (prev_state) *prev_state = prev;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_reset_event_obj( int obj, LONG *prev_state )
{
    __u32 prev;
    if (ioctl( obj, NTSYNC_IOC_EVENT_RESET, &prev ) < 0) return errno_to_status( errno );
    if (prev_state) *prev_state = prev;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_pulse_event_obj( int obj, LONG *prev_state )
{
    __u32 prev;
    if (ioctl( obj, NTSYNC_IOC_EVENT_PULSE, &prev ) < 0) return errno_to_status( errno );
    if (prev_state) *prev_state = prev;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_query_event_obj( int obj, EVENT_BASIC_INFORMATION *info )
{
    struct ntsync_event_args args = {0};
    if (ioctl( obj, NTSYNC_IOC_EVENT_READ, &args ) < 0) return errno_to_status( errno );
    info->EventType = args.manual ? NotificationEvent : SynchronizationEvent;
    info->EventState = args.signaled;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_release_mutex_obj( int obj, LONG *prev_count )
{
    struct ntsync_mutex_args args = {.owner = GetCurrentThreadId()};
    if (ioctl( obj, NTSYNC_IOC_MUTEX_UNLOCK, &args ) < 0)
    {
        if (errno == EOVERFLOW) return STATUS_MUTANT_LIMIT_EXCEEDED;
        if (errno == EPERM) return STATUS_MUTANT_NOT_OWNED;
        return errno_to_status( errno );
    }
    if (prev_count) *prev_count = 1 - args.count;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_query_mutex_obj( int obj, MUTANT_BASIC_INFORMATION *info )
{
    struct ntsync_mutex_args args = {0};
    if (ioctl( obj, NTSYNC_IOC_MUTEX_READ, &args ) < 0)
    {
        if (errno == EOWNERDEAD)
        {
            info->AbandonedState = TRUE;
            info->OwnedByCaller = FALSE;
            info->CurrentCount = 1;
            return STATUS_SUCCESS;
        }
        return errno_to_status( errno );
    }
    info->AbandonedState = FALSE;
    info->OwnedByCaller = (args.owner == GetCurrentThreadId());
    info->CurrentCount = 1 - args.count;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_wait_objs( int device, DWORD count, const int *objs, WAIT_TYPE type,
                                 int alert_fd, const LARGE_INTEGER *timeout )
{
    struct ntsync_wait_args args = {0};
    unsigned long request;
    struct timespec now;
    int ret;

    if (!timeout || timeout->QuadPart == TIMEOUT_INFINITE)
    {
        args.timeout = ~(__u64)0;
    }
    else if (timeout->QuadPart <= 0)
    {
        clock_gettime( CLOCK_MONOTONIC, &now );
        args.timeout = ((ULONGLONG)now.tv_sec * NSECPERSEC) + now.tv_nsec + (-timeout->QuadPart * 100);
    }
    else
    {
        args.timeout = (timeout->QuadPart * 100) - (SECS_1601_TO_1970 * NSECPERSEC);
        args.flags |= NTSYNC_WAIT_REALTIME;
    }

    args.objs = (uintptr_t)objs;
    args.count = count;
    args.owner = GetCurrentThreadId();
    args.index = ~0u;
    args.alert = alert_fd;

    if (type != WaitAll || count == 1) request = NTSYNC_IOC_WAIT_ANY;
    else request = NTSYNC_IOC_WAIT_ALL;

    do { ret = ioctl( device, request, &args ); }
    while (ret < 0 && errno == EINTR);

    if (!ret)
    {
        if (args.index == count)
        {
            static const LARGE_INTEGER timeout;

            ret = server_wait( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE, &timeout );
            assert( ret == STATUS_USER_APC );
            return ret;
        }

        return type != WaitAll ? args.index : 0;
    }
    if (errno == EOWNERDEAD) return STATUS_ABANDONED + (type != WaitAll ? args.index : 0);
    if (errno == ETIMEDOUT) return STATUS_TIMEOUT;
    return errno_to_status( errno );
}

#else /* NTSYNC_IOC_EVENT_READ */

static NTSTATUS linux_release_semaphore_obj( int obj, ULONG count, ULONG *prev_count )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_query_semaphore_obj( int obj, SEMAPHORE_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_set_event_obj( int obj, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_reset_event_obj( int obj, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_pulse_event_obj( int obj, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_query_event_obj( int obj, EVENT_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_release_mutex_obj( int obj, LONG *prev_count )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_query_mutex_obj( int obj, MUTANT_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_wait_objs( int device, DWORD count, const int *objs, WAIT_TYPE type,
                                 int alert_fd, const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* NTSYNC_IOC_EVENT_READ */

/* It's possible for synchronization primitives to remain alive even after being
 * closed, because a thread is still waiting on them. It's rare in practice, and
 * documented as being undefined behaviour by Microsoft, but it works, and some
 * applications rely on it. This means we need to refcount handles, and defer
 * deleting them on the server side until the refcount reaches zero. We do this
 * by having each client process hold a handle to the in-process synchronization
 * object, as well as a private refcount. When the client refcount reaches zero,
 * it closes the handle; when all handles are closed, the server deletes the
 * in-process synchronization object.
 *
 * We also need this for signal-and-wait. The signal and wait operations aren't
 * atomic, but we can't perform the signal and then return STATUS_INVALID_HANDLE
 * for the wait—we need to either do both operations or neither. That means we
 * need to grab references to both objects, and prevent them from being
 * destroyed before we're done with them.
 *
 * We want lookup of objects from the cache to be very fast; ideally, it should
 * be lock-free. We achieve this by using atomic modifications to "refcount",
 * and guaranteeing that all other fields are valid and correct *as long as*
 * refcount is nonzero, and we store the entire structure in memory which will
 * never be freed.
 *
 * This means that acquiring the object can't use a simple atomic increment; it
 * has to use a compare-and-swap loop to ensure that it doesn't try to increment
 * an object with a zero refcount. That's still leagues better than a real lock,
 * though, and release can be a single atomic decrement.
 *
 * It also means that threads modifying the cache need to take a lock, to
 * prevent other threads from writing to it concurrently.
 *
 * It's possible for an object currently in use (by a waiter) to be closed and
 * the same handle immediately reallocated to a different object. This should be
 * a very rare situation, and in that case we simply don't cache the handle.
 */
struct inproc_sync
{
    LONG           refcount;  /* reference count of the sync object */
    int            fd;        /* unix file descriptor */
    unsigned int   access;    /* handle access rights */
    unsigned short type;      /* enum inproc_sync_type as short to save space */
    unsigned short closed;    /* fd has been closed but sync is still referenced */
};

#define INPROC_SYNC_CACHE_BLOCK_SIZE  (65536 / sizeof(struct inproc_sync))
#define INPROC_SYNC_CACHE_ENTRIES     128

static struct inproc_sync *inproc_sync_cache[INPROC_SYNC_CACHE_ENTRIES];
static struct inproc_sync inproc_sync_cache_initial_block[INPROC_SYNC_CACHE_BLOCK_SIZE];

static inline unsigned int inproc_sync_handle_to_index( HANDLE handle, unsigned int *entry )
{
    unsigned int idx = (wine_server_obj_handle(handle) >> 2) - 1;
    *entry = idx / INPROC_SYNC_CACHE_BLOCK_SIZE;
    return idx % INPROC_SYNC_CACHE_BLOCK_SIZE;
}

static BOOL is_pseudo_handle( HANDLE handle )
{
    return ((ULONG)(ULONG_PTR)handle >= 0xfffffffa);
}

static struct inproc_sync *cache_inproc_sync( HANDLE handle, struct inproc_sync *sync )
{
    unsigned int entry, idx = inproc_sync_handle_to_index( handle, &entry );
    struct inproc_sync *cache;
    int refcount;

    /* don't cache pseudo-handles; waiting on them is pointless anyway */
    if (is_pseudo_handle( handle )) return sync;

    if (entry >= INPROC_SYNC_CACHE_ENTRIES)
    {
        FIXME( "too many allocated handles, not caching %p\n", handle );
        return sync;
    }

    if (!inproc_sync_cache[entry])  /* do we need to allocate a new block of entries? */
    {
        if (!entry) inproc_sync_cache[0] = inproc_sync_cache_initial_block;
        else
        {
            static const size_t size = INPROC_SYNC_CACHE_BLOCK_SIZE * sizeof(struct inproc_sync);
            void *ptr = anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
            if (ptr == MAP_FAILED) return sync;
            inproc_sync_cache[entry] = ptr;
        }
    }

    cache = &inproc_sync_cache[entry][idx];

    if (InterlockedCompareExchange( &cache->refcount, 0, 0 ))
    {
        /* The handle is currently being used for another object (i.e. it was
         * closed and then reused, but some thread is waiting on the old handle
         * or otherwise simultaneously using the old object). We can't cache
         * this object until the old one is completely destroyed. */
        return sync;
    }

    cache->fd = sync->fd;
    cache->access = sync->access;
    cache->type = sync->type;
    cache->closed = sync->closed;
    /* Make sure we set the other members before the refcount; this store needs
     * release semantics [paired with the load in get_cached_inproc_sync()].
     * Set the refcount to 2 (one for the handle, one for the caller). */
    refcount = InterlockedExchange( &cache->refcount, 2 );
    assert( !refcount );

    assert( sync->refcount == 1 );
    memset( sync, 0, sizeof(*sync) );

    return cache;
}

/* returns the previous value */
static inline LONG interlocked_inc_if_nonzero( LONG *dest )
{
    LONG val, tmp;
    for (val = *dest;; val = tmp)
    {
        if (!val || (tmp = InterlockedCompareExchange( dest, val + 1, val )) == val)
            break;
    }
    return val;
}

static void release_inproc_sync( struct inproc_sync *sync )
{
    /* save the fd now; as soon as the refcount hits 0 we cannot
     * access the cache anymore */
    int fd = sync->fd;
    LONG ref = InterlockedDecrement( &sync->refcount );

    assert( ref >= 0 );
    if (!ref) close( fd );
}

static struct inproc_sync *get_cached_inproc_sync( HANDLE handle )
{
    unsigned int entry, idx = inproc_sync_handle_to_index( handle, &entry );
    struct inproc_sync *cache;

    if (entry >= INPROC_SYNC_CACHE_ENTRIES || !inproc_sync_cache[entry]) return NULL;

    cache = &inproc_sync_cache[entry][idx];

    /* this load needs acquire semantics [paired with the store in
     * cache_inproc_sync()] */
    if (!interlocked_inc_if_nonzero( &cache->refcount )) return NULL;

    if (cache->closed)
    {
        /* The object is still being used, but "handle" has been closed. The
         * handle value might have been reused for another object in the
         * meantime, in which case we have to report that valid object, so
         * force the caller to check the server. */
        release_inproc_sync( cache );
        return NULL;
    }

    return cache;
}

/* fd_cache_mutex must be held to avoid races with other thread receiving fds */
static NTSTATUS get_server_inproc_sync( HANDLE handle, struct inproc_sync *sync )
{
    NTSTATUS ret;

    SERVER_START_REQ( get_inproc_sync_fd )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            obj_handle_t fd_handle;
            sync->refcount = 1;
            sync->fd = wine_server_receive_fd( &fd_handle );
            assert( wine_server_ptr_handle(fd_handle) == handle );
            sync->access = reply->access;
            sync->type = reply->type;
            sync->closed = 0;
        }
    }
    SERVER_END_REQ;

    return ret;
}

/* returns a pointer to a cache entry; if the object could not be cached,
 * returns "cache" instead, which should be allocated on stack */
static NTSTATUS get_inproc_sync( HANDLE handle, enum inproc_sync_type desired_type, ACCESS_MASK desired_access,
                                 struct inproc_sync *stack, struct inproc_sync **out )
{
    struct inproc_sync *sync;
    sigset_t sigset;
    NTSTATUS ret;

    /* try to find it in the cache already */
    if ((sync = get_cached_inproc_sync( handle ))) ret = STATUS_SUCCESS;
    else
    {
        /* We need to use fd_cache_mutex here to protect against races with
         * other threads trying to receive fds for the fd cache,
         * and we need to use an uninterrupted section to prevent reentrancy.
         * We also need fd_cache_mutex to protect against the same race with
         * NtClose, that is, to prevent the object from being cached again between
         * close_inproc_sync() and close_handle.
         *
         * The mutex also protects cache_inproc_sync(). Accessing the cache is
         * done without a lock, but populating it currently is not. */
        server_enter_uninterrupted_section( &fd_cache_mutex, &sigset );
        if (!(sync = get_cached_inproc_sync( handle )))
        {
            if ((ret = get_server_inproc_sync( handle, stack )))
            {
                server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
                return ret;
            }
            sync = cache_inproc_sync( handle, stack );
        }
        server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
    }

    if (desired_type != INPROC_SYNC_UNKNOWN && desired_type != sync->type)
    {
        release_inproc_sync( sync );
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if ((sync->access & desired_access) != desired_access)
    {
        release_inproc_sync( sync );
        return STATUS_ACCESS_DENIED;
    }

    *out = sync;
    return STATUS_SUCCESS;
}

extern NTSTATUS check_signal_access( struct inproc_sync *sync )
{
    switch (sync->type)
    {
    case INPROC_SYNC_INTERNAL:
        return STATUS_OBJECT_TYPE_MISMATCH;
    case INPROC_SYNC_EVENT:
        if (!(sync->access & EVENT_MODIFY_STATE)) return STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    case INPROC_SYNC_MUTEX:
        if (!(sync->access & SYNCHRONIZE)) return STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    case INPROC_SYNC_SEMAPHORE:
        if (!(sync->access & SEMAPHORE_MODIFY_STATE)) return STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }

    assert( 0 );
    return STATUS_OBJECT_TYPE_MISMATCH;
}

/* caller must hold fd_cache_mutex */
void close_inproc_sync( HANDLE handle )
{
    struct inproc_sync *cache;

    if (inproc_device_fd < 0) return;
    if ((cache = get_cached_inproc_sync( handle )))
    {
        cache->closed = 1;
        /* once for the reference we just grabbed, and once for the handle */
        release_inproc_sync( cache );
        release_inproc_sync( cache );
    }
}

static NTSTATUS inproc_release_semaphore( HANDLE handle, ULONG count, ULONG *prev_count )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_SEMAPHORE, SEMAPHORE_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_release_semaphore_obj( sync->fd, count, prev_count );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_query_semaphore( HANDLE handle, SEMAPHORE_BASIC_INFORMATION *info )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_SEMAPHORE, SEMAPHORE_QUERY_STATE, &stack, &sync ))) return ret;
    ret = linux_query_semaphore_obj( sync->fd, info );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_set_event( HANDLE handle, LONG *prev_state )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_set_event_obj( sync->fd, prev_state );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_reset_event( HANDLE handle, LONG *prev_state )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_reset_event_obj( sync->fd, prev_state );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_pulse_event( HANDLE handle, LONG *prev_state )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_pulse_event_obj( sync->fd, prev_state );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_query_event( HANDLE handle, EVENT_BASIC_INFORMATION *info )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_QUERY_STATE, &stack, &sync ))) return ret;
    ret = linux_query_event_obj( sync->fd, info );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_release_mutex( HANDLE handle, LONG *prev_count )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_MUTEX, 0, &stack, &sync ))) return ret;
    ret = linux_release_mutex_obj( sync->fd, prev_count );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_query_mutex( HANDLE handle, MUTANT_BASIC_INFORMATION *info )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_MUTEX, MUTANT_QUERY_STATE, &stack, &sync ))) return ret;
    ret = linux_query_mutex_obj( sync->fd, info );
    release_inproc_sync( sync );
    return ret;
}

static int get_inproc_alert_fd(void)
{
    struct ntdll_thread_data *data = ntdll_get_thread_data();
    obj_handle_t token;
    sigset_t sigset;
    int fd;

    if ((fd = data->alert_fd) < 0)
    {
        server_enter_uninterrupted_section( &fd_cache_mutex, &sigset );

        SERVER_START_REQ( get_inproc_alert_fd )
        {
            if (!server_call_unlocked( req ))
            {
                data->alert_fd = fd = wine_server_receive_fd( &token );
                assert( token == reply->handle );
            }
        }
        SERVER_END_REQ;

        server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
    }

    return fd;
}

static NTSTATUS inproc_wait( DWORD count, const HANDLE *handles, WAIT_TYPE type,
                             BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    struct inproc_sync *syncs[64], stack[ARRAY_SIZE(syncs)];
    int objs[ARRAY_SIZE(syncs)], alert_fd = 0;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;

    assert( count <= ARRAY_SIZE(syncs) );
    objs[0] = -1;  /* make gcc happy, otherwise it thinks objs is not initialized */
    for (int i = 0; i < count; ++i)
    {
        if ((ret = get_inproc_sync( handles[i], INPROC_SYNC_UNKNOWN, SYNCHRONIZE, &stack[i], &syncs[i] )))
        {
            while (i--) release_inproc_sync( syncs[i] );
            return ret;
        }
        objs[i] = syncs[i]->fd;
    }

    if (alertable) alert_fd = get_inproc_alert_fd();
    ret = linux_wait_objs( inproc_device_fd, count, objs, type, alert_fd, timeout );

    while (count--) release_inproc_sync( syncs[count] );
    return ret;
}

static NTSTATUS inproc_signal_and_wait( HANDLE signal, HANDLE wait,
                                        BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    struct inproc_sync stack_signal, stack_wait, *signal_sync = &stack_signal, *wait_sync = &stack_wait;
    int alert_fd = 0;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_inproc_sync( signal, INPROC_SYNC_UNKNOWN, 0, &stack_signal, &signal_sync ))) return ret;
    if ((ret = check_signal_access( signal_sync ))) goto done;

    if ((ret = get_inproc_sync( wait, INPROC_SYNC_UNKNOWN, SYNCHRONIZE, &stack_wait, &wait_sync ))) goto done;

    switch (signal_sync->type)
    {
    case INPROC_SYNC_EVENT:     ret = linux_set_event_obj( signal_sync->fd, NULL ); break;
    case INPROC_SYNC_MUTEX:     ret = linux_release_mutex_obj( signal_sync->fd, NULL ); break;
    case INPROC_SYNC_SEMAPHORE: ret = linux_release_semaphore_obj( signal_sync->fd, 1, NULL ); break;
    default: assert( 0 ); break;
    }

    if (!ret)
    {
        if (alertable) alert_fd = get_inproc_alert_fd();
        ret = linux_wait_objs( inproc_device_fd, 1, &wait_sync->fd, WaitAny, alert_fd, timeout );
    }

    release_inproc_sync( wait_sync );
done:
    release_inproc_sync( signal_sync );
    return ret;
}


/******************************************************************************
 *              NtCreateSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                   LONG initial, LONG max )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, initial %d, max %d\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", initial, max );

    *handle = 0;
    if (max <= 0 || initial < 0 || initial > max) return STATUS_INVALID_PARAMETER;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_semaphore )
    {
        req->access  = access;
        req->initial = initial;
        req->max     = max;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_semaphore )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtQuerySemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySemaphore( HANDLE handle, SEMAPHORE_INFORMATION_CLASS class,
                                  void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    SEMAPHORE_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != SemaphoreBasicInformation)
    {
        FIXME("(%p,%d,%u) Unknown class\n", handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(SEMAPHORE_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

#ifdef WINE_IOS
    /* ml1010: answer from the cell.  This is a pure READ of the word that IS
     * the server's own count -- semaphore_sync_signaled() and the server's
     * release_semaphore() read and write this same address -- so it is the
     * same fact the server would have reported, not a second opinion.  It
     * consumes nothing, so none of the lost-wakeup reasoning applies and it
     * needs no peek budget; it is gated only on the semaphore path being on. */
    if (madeira_fast_cells_enabled() && madeira_fast_sem_enabled())
    {
        struct madeira_sync_cell *cell;
        unsigned int manual = 0, gen = 0, kind = 0;

        if ((cell = madeira_fast_lookup( handle, SEMAPHORE_QUERY_STATE, &manual, &gen, &kind )) &&
            kind == MADEIRA_CELL_KIND_SEM)
        {
            uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );

            if (MADEIRA_SG_GEN( sg ) == gen && MADEIRA_SG_STATE( sg ) >= 0)
            {
                out->CurrentCount = MADEIRA_SG_STATE( sg );
                out->MaximumCount = __atomic_load_n( &cell->smax, __ATOMIC_RELAXED );
                if (ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
                ios_srv_nt_count( IOS_NT_FAST_HIT );
                return STATUS_SUCCESS;
            }
        }
    }
#endif

    if ((ret = inproc_query_semaphore( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount = reply->current;
            out->MaximumCount = reply->max;
            if (ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtReleaseSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseSemaphore( HANDLE handle, ULONG count, ULONG *previous )
{
    unsigned int ret;
#ifdef WINE_IOS
    int wake_only = 0;
#endif

    TRACE( "handle %p, count %u, prev_count %p\n", handle, count, previous );

    ios_srv_nt_count( IOS_NT_RELEASE_SEM );

#ifdef WINE_IOS
    {
        unsigned int fast_status = STATUS_SUCCESS;

        switch (madeira_fast_sem_release( handle, count, previous, &fast_status ))
        {
        case MADEIRA_FAST_DONE:
            ios_srv_nt_count( IOS_NT_FAST_HIT );
            return fast_status;
        case MADEIRA_FAST_SERVER:
            /* The cell (and *previous) are already right, so this request must
             * NOT release again -- a fast waiter may have taken a token in the
             * meantime and a second server-side release on top of that hands
             * out tokens nobody produced.  A count of ZERO is upstream's own
             * "change nothing, then wake_up( obj, 0 )", which is exactly the
             * re-evaluation the server's queue needs.  See ios_fastsync.h. */
            ios_srv_nt_count( IOS_NT_FAST_MISS );
            previous  = NULL;
            wake_only = 1;
            break;
        default:
            break;
        }
    }
#endif

    if ((ret = inproc_release_semaphore( handle, count, previous )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( release_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
#ifdef WINE_IOS
        req->count  = wake_only ? 0 : count;
#else
        req->count  = count;
#endif
        if (!(ret = wine_server_call( req )))
        {
            if (previous) *previous = reply->prev_count;
        }
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *              NtCreateEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                               EVENT_TYPE type, BOOLEAN state )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, type %u, state %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", type, state );

    *handle = 0;
    if (type != NotificationEvent && type != SynchronizationEvent) return STATUS_INVALID_PARAMETER;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_event )
    {
        req->access = access;
        req->manual_reset = (type == NotificationEvent);
        req->initial_state = state;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtSetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtSetEvent( HANDLE handle, LONG *prev_state )
{
    unsigned int ret;
#ifdef WINE_IOS
    int op = SET_EVENT;
#endif

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    ios_srv_nt_count( IOS_NT_SET_EVENT );

#ifdef WINE_IOS
    switch (madeira_fast_event_op( handle, 1, prev_state ))
    {
    case MADEIRA_FAST_DONE:
        ios_srv_nt_count( IOS_NT_FAST_HIT );
        return STATUS_SUCCESS;
    case MADEIRA_FAST_SERVER:
        /* ml962: the cell (and prev_state) are already right, so this request
         * must NOT signal the event again -- a fast waiter may have taken the
         * token in the meantime and a server-side SET_EVENT on top of that
         * releases a second waiter for one SetEvent.  MADEIRA_EVENT_OP_WAKE
         * only runs wake_up(), which re-reads the cell.  See ios_fastsync.h. */
        ios_srv_nt_count( IOS_NT_FAST_MISS );
        prev_state = NULL;
        op = MADEIRA_EVENT_OP_WAKE;
        break;
    default:
        break;
    }
#endif

    if ((ret = inproc_set_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
#ifdef WINE_IOS
        req->op     = op;
#else
        req->op     = SET_EVENT;
#endif
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtSetEventBoostPriority (NTDLL.@)
 */
NTSTATUS WINAPI NtSetEventBoostPriority( HANDLE handle )
{
    return NtSetEvent( handle, NULL );
}


/******************************************************************************
 *              NtResetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtResetEvent( HANDLE handle, LONG *prev_state )
{
    unsigned int ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    ios_srv_nt_count( IOS_NT_RESET_EVENT );

#ifdef WINE_IOS
    /* A reset releases nobody, so a cell update is the whole operation --
     * including for the server, whose event_sync_signaled() reads that word. */
    if (madeira_fast_event_op( handle, 0, prev_state ) != MADEIRA_FAST_MISS)
    {
        ios_srv_nt_count( IOS_NT_FAST_HIT );
        return STATUS_SUCCESS;
    }
#endif

    if ((ret = inproc_reset_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = RESET_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtClearEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtClearEvent( HANDLE handle )
{
    /* FIXME: same as NtResetEvent ??? */
    return NtResetEvent( handle, NULL );
}


/******************************************************************************
 *              NtPulseEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtPulseEvent( HANDLE handle, LONG *prev_state )
{
    unsigned int ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    ios_srv_nt_count( IOS_NT_PULSE_EVENT );

    if ((ret = inproc_pulse_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = PULSE_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtQueryEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryEvent( HANDLE handle, EVENT_INFORMATION_CLASS class,
                              void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    EVENT_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != EventBasicInformation)
    {
        FIXME("(%p, %d, %d) Unknown class\n", handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(EVENT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = inproc_query_event( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(EVENT_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_event )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->EventType  = reply->manual_reset ? NotificationEvent : SynchronizationEvent;
            out->EventState = reply->state;
            if (ret_len) *ret_len = sizeof(EVENT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtCreateMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                BOOLEAN owned )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, owned %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", owned );

    *handle = 0;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_mutex )
    {
        req->access  = access;
        req->owned   = owned;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/**************************************************************************
 *              NtOpenMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_mutex )
    {
        req->access  = access;
        req->attributes = attr->Attributes;
        req->rootdir = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *              NtReleaseMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseMutant( HANDLE handle, LONG *prev_count )
{
    unsigned int ret;

    TRACE( "handle %p, prev_count %p\n", handle, prev_count );

    ios_srv_nt_count( IOS_NT_RELEASE_MUTANT );

    if ((ret = inproc_release_mutex( handle, prev_count )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( release_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
        if (prev_count) *prev_count = 1 - reply->prev_count;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************
 *              NtQueryMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryMutant( HANDLE handle, MUTANT_INFORMATION_CLASS class,
                               void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    MUTANT_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != MutantBasicInformation)
    {
        FIXME( "(%p, %d, %d) Unknown class\n", handle, class, len );
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(MUTANT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = inproc_query_mutex( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(MUTANT_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount   = 1 - reply->count;
            out->OwnedByCaller  = reply->owned;
            out->AbandonedState = reply->abandoned;
            if (ret_len) *ret_len = sizeof(MUTANT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtCreateJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_job )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *		NtOpenJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_job )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtTerminateJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtTerminateJobObject( HANDLE handle, NTSTATUS status )
{
    unsigned int ret;

    TRACE( "(%p, %d)\n", handle, status );

    SERVER_START_REQ( terminate_job )
    {
        req->handle = wine_server_obj_handle( handle );
        req->status = status;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;

    return ret;
}


/**************************************************************************
 *		NtQueryInformationJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info,
                                             ULONG len, ULONG *ret_len )
{
    unsigned int ret;

    TRACE( "semi-stub: %p %u %p %u %p\n", handle, class, info, len, ret_len );

    if (class >= MaxJobObjectInfoClass) return STATUS_INVALID_PARAMETER;

    switch (class)
    {
    case JobObjectBasicAccountingInformation:
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION *accounting = info;

        if (len < sizeof(*accounting)) return STATUS_INFO_LENGTH_MISMATCH;
        SERVER_START_REQ(get_job_info)
        {
            req->handle = wine_server_obj_handle( handle );
            if (!(ret = wine_server_call( req )))
            {
                memset( accounting, 0, sizeof(*accounting) );
                accounting->TotalProcesses = reply->total_processes;
                accounting->ActiveProcesses = reply->active_processes;
            }
        }
        SERVER_END_REQ;
        if (ret_len) *ret_len = sizeof(*accounting);
        return ret;
    }
    case JobObjectBasicProcessIdList:
    {
        JOBOBJECT_BASIC_PROCESS_ID_LIST *process = info;
        DWORD count, i;

        if (len < sizeof(*process)) return STATUS_INFO_LENGTH_MISMATCH;

        count  = len - offsetof( JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList );
        count /= sizeof(process->ProcessIdList[0]);

        SERVER_START_REQ( get_job_info )
        {
            req->handle = wine_server_user_handle(handle);
            wine_server_set_reply(req, process->ProcessIdList, count * sizeof(process_id_t));
            if (!(ret = wine_server_call(req)))
            {
                process->NumberOfAssignedProcesses = reply->active_processes;
                process->NumberOfProcessIdsInList = min(count, reply->active_processes);
            }
        }
        SERVER_END_REQ;

        if (ret != STATUS_SUCCESS) return ret;

        if (sizeof(process_id_t) < sizeof(process->ProcessIdList[0]))
        {
            /* start from the end to not overwrite */
            for (i = process->NumberOfProcessIdsInList; i--;)
            {
                ULONG_PTR id = ((process_id_t *)process->ProcessIdList)[i];
                process->ProcessIdList[i] = id;
            }
        }

        if (ret_len)
            *ret_len = offsetof( JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList[process->NumberOfProcessIdsInList] );
        return count < process->NumberOfAssignedProcesses ? STATUS_MORE_ENTRIES : STATUS_SUCCESS;
    }
    case JobObjectExtendedLimitInformation:
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION *extended_limit = info;

        if (len < sizeof(*extended_limit)) return STATUS_INFO_LENGTH_MISMATCH;
        memset( extended_limit, 0, sizeof(*extended_limit) );
        if (ret_len) *ret_len = sizeof(*extended_limit);
        return STATUS_SUCCESS;
    }
    case JobObjectBasicLimitInformation:
    {
        JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit = info;

        if (len < sizeof(*basic_limit)) return STATUS_INFO_LENGTH_MISMATCH;
        memset( basic_limit, 0, sizeof(*basic_limit) );
        if (ret_len) *ret_len = sizeof(*basic_limit);
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}


/**************************************************************************
 *		NtSetInformationJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info, ULONG len )
{
    unsigned int status = STATUS_NOT_IMPLEMENTED;
    JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit;
    ULONG info_size = sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
    DWORD limit_flags = JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS;

    TRACE( "(%p, %u, %p, %u)\n", handle, class, info, len );

    if (class >= MaxJobObjectInfoClass) return STATUS_INVALID_PARAMETER;

    switch (class)
    {

    case JobObjectExtendedLimitInformation:
        info_size = sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        limit_flags = JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS;
        /* fall through */
    case JobObjectBasicLimitInformation:
        if (len != info_size) return STATUS_INVALID_PARAMETER;
        basic_limit = info;
        if (basic_limit->LimitFlags & ~limit_flags) return STATUS_INVALID_PARAMETER;
        SERVER_START_REQ( set_job_limits )
        {
            req->handle = wine_server_obj_handle( handle );
            req->limit_flags = basic_limit->LimitFlags;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;
    case JobObjectAssociateCompletionPortInformation:
        if (len != sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT)) return STATUS_INVALID_PARAMETER;
        SERVER_START_REQ( set_job_completion_port )
        {
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT *port_info = info;
            req->job = wine_server_obj_handle( handle );
            req->port = wine_server_obj_handle( port_info->CompletionPort );
            req->key = wine_server_client_ptr( port_info->CompletionKey );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;
    case JobObjectBasicUIRestrictions:
        status = STATUS_SUCCESS;
        /* fall through */
    default:
        FIXME( "stub: %p %u %p %u\n", handle, class, info, len );
    }
    return status;
}


/**************************************************************************
 *		NtIsProcessInJob (NTDLL.@)
 */
NTSTATUS WINAPI NtIsProcessInJob( HANDLE process, HANDLE job )
{
    unsigned int status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( process_in_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/**************************************************************************
 *		NtAssignProcessToJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtAssignProcessToJobObject( HANDLE job, HANDLE process )
{
    unsigned int status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( assign_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/**********************************************************************
 *           NtCreateDebugObject  (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateDebugObject( HANDLE *handle, ACCESS_MASK access,
                                     OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if (flags & ~DEBUG_KILL_ON_CLOSE) return STATUS_INVALID_PARAMETER;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_debug_obj )
    {
        req->access = access;
        req->flags  = flags;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**********************************************************************
 *           NtSetInformationDebugObject  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationDebugObject( HANDLE handle, DEBUGOBJECTINFOCLASS class,
                                             void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    ULONG flags;

    if (class != DebugObjectKillProcessOnExitInformation) return STATUS_INVALID_PARAMETER;
    if (len != sizeof(ULONG))
    {
        if (ret_len) *ret_len = sizeof(ULONG);
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    flags = *(ULONG *)info;
    if (flags & ~DEBUG_KILL_ON_CLOSE) return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( set_debug_obj_info )
    {
        req->debug = wine_server_obj_handle( handle );
        req->flags = flags;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!ret && ret_len) *ret_len = 0;
    return ret;
}


/* convert the server event data to an NT state change; helper for NtWaitForDebugEvent */
static NTSTATUS event_data_to_state_change( const union debug_event_data *data, DBGUI_WAIT_STATE_CHANGE *state )
{
    int i;

    switch (data->code)
    {
    case DbgIdle:
    case DbgReplyPending:
        return STATUS_PENDING;
    case DbgCreateThreadStateChange:
    {
        DBGUI_CREATE_THREAD *info = &state->StateInfo.CreateThread;
        info->HandleToThread         = wine_server_ptr_handle( data->create_thread.handle );
        info->NewThread.StartAddress = wine_server_get_ptr( data->create_thread.start );
        return STATUS_SUCCESS;
    }
    case DbgCreateProcessStateChange:
    {
        DBGUI_CREATE_PROCESS *info = &state->StateInfo.CreateProcessInfo;
        info->HandleToProcess                       = wine_server_ptr_handle( data->create_process.process );
        info->HandleToThread                        = wine_server_ptr_handle( data->create_process.thread );
        info->NewProcess.FileHandle                 = wine_server_ptr_handle( data->create_process.file );
        info->NewProcess.BaseOfImage                = wine_server_get_ptr( data->create_process.base );
        info->NewProcess.DebugInfoFileOffset        = data->create_process.dbg_offset;
        info->NewProcess.DebugInfoSize              = data->create_process.dbg_size;
        info->NewProcess.InitialThread.StartAddress = wine_server_get_ptr( data->create_process.start );
        return STATUS_SUCCESS;
    }
    case DbgExitThreadStateChange:
        state->StateInfo.ExitThread.ExitStatus = data->exit.exit_code;
        return STATUS_SUCCESS;
    case DbgExitProcessStateChange:
        state->StateInfo.ExitProcess.ExitStatus = data->exit.exit_code;
        return STATUS_SUCCESS;
    case DbgExceptionStateChange:
    case DbgBreakpointStateChange:
    case DbgSingleStepStateChange:
    {
        DBGKM_EXCEPTION *info = &state->StateInfo.Exception;
        info->FirstChance = data->exception.first;
        info->ExceptionRecord.ExceptionCode    = data->exception.exc_code;
        info->ExceptionRecord.ExceptionFlags   = data->exception.flags;
        info->ExceptionRecord.ExceptionRecord  = wine_server_get_ptr( data->exception.record );
        info->ExceptionRecord.ExceptionAddress = wine_server_get_ptr( data->exception.address );
        info->ExceptionRecord.NumberParameters = data->exception.nb_params;
        for (i = 0; i < data->exception.nb_params; i++)
            info->ExceptionRecord.ExceptionInformation[i] = data->exception.params[i];
        return STATUS_SUCCESS;
    }
    case DbgLoadDllStateChange:
    {
        DBGKM_LOAD_DLL *info = &state->StateInfo.LoadDll;
        info->FileHandle          = wine_server_ptr_handle( data->load_dll.handle );
        info->BaseOfDll           = wine_server_get_ptr( data->load_dll.base );
        info->DebugInfoFileOffset = data->load_dll.dbg_offset;
        info->DebugInfoSize       = data->load_dll.dbg_size;
        info->NamePointer         = wine_server_get_ptr( data->load_dll.name );
        if ((DWORD_PTR)data->load_dll.base != data->load_dll.base)
            return STATUS_PARTIAL_COPY;
        return STATUS_SUCCESS;
    }
    case DbgUnloadDllStateChange:
        state->StateInfo.UnloadDll.BaseAddress = wine_server_get_ptr( data->unload_dll.base );
        if ((DWORD_PTR)data->unload_dll.base != data->unload_dll.base)
            return STATUS_PARTIAL_COPY;
        return STATUS_SUCCESS;
    }
    return STATUS_INTERNAL_ERROR;
}

#ifndef _WIN64
/* helper to NtWaitForDebugEvent; retrieve machine from PE image */
static NTSTATUS get_image_machine( HANDLE handle, USHORT *machine )
{
    IMAGE_DOS_HEADER dos_hdr;
    IMAGE_NT_HEADERS nt_hdr;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    FILE_POSITION_INFORMATION pos_info;
    NTSTATUS status;

    offset.QuadPart = 0;
    status = NtReadFile( handle, NULL, NULL, NULL,
                         &iosb, &dos_hdr, sizeof(dos_hdr), &offset, NULL );
    if (!status)
    {
        offset.QuadPart = dos_hdr.e_lfanew;
        status = NtReadFile( handle, NULL, NULL, NULL, &iosb,
                             &nt_hdr, FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader), &offset, NULL );
        if (!status)
            *machine = nt_hdr.FileHeader.Machine;
        /* Reset file pos at beginning of file */
        pos_info.CurrentByteOffset.QuadPart = 0;
        NtSetInformationFile( handle, &iosb, &pos_info, sizeof(pos_info), FilePositionInformation );
    }
    return status;
}
#endif

/**********************************************************************
 *           NtWaitForDebugEvent  (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForDebugEvent( HANDLE handle, BOOLEAN alertable, LARGE_INTEGER *timeout,
                                     DBGUI_WAIT_STATE_CHANGE *state )
{
    union debug_event_data data;
    unsigned int ret;
    BOOL wait = TRUE;

    for (;;)
    {
        SERVER_START_REQ( wait_debug_event )
        {
            req->debug = wine_server_obj_handle( handle );
            wine_server_set_reply( req, &data, sizeof(data) );
            ret = wine_server_call( req );
            if (!ret)
            {
                ret = event_data_to_state_change( &data, state );
                state->NewState = data.code;
                state->AppClientId.UniqueProcess = ULongToHandle( reply->pid );
                state->AppClientId.UniqueThread  = ULongToHandle( reply->tid );
            }
        }
        SERVER_END_REQ;

#ifndef _WIN64
        /* don't pass 64bit load events to 32bit callers */
        if (!ret && state->NewState == DbgLoadDllStateChange)
        {
            USHORT machine;
            if (!get_image_machine( state->StateInfo.LoadDll.FileHandle, &machine ) &&
                machine != current_machine)
                ret = STATUS_PARTIAL_COPY;
        }
        if (ret == STATUS_PARTIAL_COPY)
        {
            if (state->NewState == DbgLoadDllStateChange)
                NtClose( state->StateInfo.LoadDll.FileHandle );
            NtDebugContinue( handle, &state->AppClientId, DBG_CONTINUE );
            wait = TRUE;
            continue;
        }
#endif
        if (ret != STATUS_PENDING) return ret;
        if (!wait) return STATUS_TIMEOUT;
        wait = FALSE;
        ret = NtWaitForSingleObject( handle, alertable, timeout );
        if (ret != STATUS_WAIT_0) return ret;
    }
}


/**************************************************************************
 *           NtCreateDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateDirectoryObject( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_directory )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *           NtOpenDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenDirectoryObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_directory )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *           NtQueryDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryDirectoryObject( HANDLE handle, DIRECTORY_BASIC_INFORMATION *buffer,
                                        ULONG size, BOOLEAN single_entry, BOOLEAN restart,
                                        ULONG *context, ULONG *ret_size )
{
    unsigned int status, i, count, total_len, pos, used_size, used_count, strpool_head;
    ULONG index = restart ? 0 : *context;
    struct directory_entry *entries;

    if (!(entries = malloc( size ))) return STATUS_NO_MEMORY;

    SERVER_START_REQ( get_directory_entries )
    {
        req->handle = wine_server_obj_handle( handle );
        req->index = index;
        req->max_count = single_entry ? 1 : UINT_MAX;
        wine_server_set_reply( req, entries, size );
        status = wine_server_call( req );
        count = reply->count;
        total_len = reply->total_len;
    }
    SERVER_END_REQ;

    if (status && status != STATUS_MORE_ENTRIES)
    {
        free( entries );
        return status;
    }

    used_count = 0;
    used_size = sizeof(*buffer);  /* "null terminator" entry */
    for (i = pos = 0; i < count; i++)
    {
        const struct directory_entry *entry = (const struct directory_entry *)((char *)entries + pos);
        unsigned int entry_size = sizeof(*buffer) + entry->name_len + entry->type_len + 2 * sizeof(WCHAR);

        if (used_size + entry_size > size)
        {
            status = STATUS_MORE_ENTRIES;
            break;
        }
        used_count++;
        used_size += entry_size;
        pos += sizeof(*entry) + ((entry->name_len + entry->type_len + 3) & ~3);
    }

    /*
     * Avoid making strpool_head a pointer, since it can point beyond end
     * of the buffer.  Out-of-bounds pointers trigger undefined behavior
     * just by existing, even when they are never dereferenced.
     */
    strpool_head = sizeof(*buffer) * (used_count + 1);  /* after the "null terminator" entry */
    for (i = pos = 0; i < used_count; i++)
    {
        const struct directory_entry *entry = (const struct directory_entry *)((char *)entries + pos);

        buffer[i].ObjectName.Buffer = (WCHAR *)((char *)buffer + strpool_head);
        buffer[i].ObjectName.Length = entry->name_len;
        buffer[i].ObjectName.MaximumLength = entry->name_len + sizeof(WCHAR);
        memcpy( buffer[i].ObjectName.Buffer, (entry + 1), entry->name_len );
        buffer[i].ObjectName.Buffer[entry->name_len / sizeof(WCHAR)] = 0;
        strpool_head += entry->name_len + sizeof(WCHAR);

        buffer[i].ObjectTypeName.Buffer = (WCHAR *)((char *)buffer + strpool_head);
        buffer[i].ObjectTypeName.Length = entry->type_len;
        buffer[i].ObjectTypeName.MaximumLength = entry->type_len + sizeof(WCHAR);
        memcpy( buffer[i].ObjectTypeName.Buffer, (char *)(entry + 1) + entry->name_len, entry->type_len );
        buffer[i].ObjectTypeName.Buffer[entry->type_len / sizeof(WCHAR)] = 0;
        strpool_head += entry->type_len + sizeof(WCHAR);

        pos += sizeof(*entry) + ((entry->name_len + entry->type_len + 3) & ~3);
    }

    if (size >= sizeof(*buffer))
        memset( &buffer[used_count], 0, sizeof(buffer[used_count]) );

    free( entries );

    if (!count && !status)
    {
        if (ret_size) *ret_size = sizeof(*buffer);
        return STATUS_NO_MORE_ENTRIES;
    }

    if (single_entry && !used_count)
    {
        if (ret_size) *ret_size = 2 * sizeof(*buffer) + 2 * sizeof(WCHAR) + total_len;
        return STATUS_BUFFER_TOO_SMALL;
    }

    *context = index + used_count;
    if (ret_size) *ret_size = strpool_head;
    return status;
}


/**************************************************************************
 *           NtCreateSymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                            OBJECT_ATTRIBUTES *attr, UNICODE_STRING *target )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if (!target->MaximumLength) return STATUS_INVALID_PARAMETER;
    if (!target->Buffer) return STATUS_ACCESS_VIOLATION;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_symlink )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        wine_server_add_data( req, target->Buffer, target->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *           NtOpenSymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                          const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_symlink )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *           NtQuerySymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySymbolicLinkObject( HANDLE handle, UNICODE_STRING *target, ULONG *length )
{
    unsigned int ret;

    if (!target) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( query_symlink )
    {
        req->handle = wine_server_obj_handle( handle );
        if (target->MaximumLength >= sizeof(WCHAR))
            wine_server_set_reply( req, target->Buffer, target->MaximumLength - sizeof(WCHAR) );
        if (!(ret = wine_server_call( req )))
        {
            target->Length = wine_server_reply_size(reply);
            target->Buffer[target->Length / sizeof(WCHAR)] = 0;
            if (length) *length = reply->total + sizeof(WCHAR);
        }
        else if (length && ret == STATUS_BUFFER_TOO_SMALL) *length = reply->total + sizeof(WCHAR);
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtMakePermanentObject (NTDLL.@)
 */
NTSTATUS WINAPI NtMakePermanentObject( HANDLE handle )
{
    unsigned int ret;

    TRACE("%p\n", handle);

    SERVER_START_REQ( set_object_permanence )
    {
        req->handle = wine_server_obj_handle( handle );
        req->permanent = 1;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtMakeTemporaryObject (NTDLL.@)
 */
NTSTATUS WINAPI NtMakeTemporaryObject( HANDLE handle )
{
    unsigned int ret;

    TRACE("%p\n", handle);

    SERVER_START_REQ( set_object_permanence )
    {
        req->handle = wine_server_obj_handle( handle );
        req->permanent = 0;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtCreateTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                               TIMER_TYPE type )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, type %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", type );

    *handle = 0;
    if (type != NotificationTimer && type != SynchronizationTimer) return STATUS_INVALID_PARAMETER;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_timer )
    {
        req->access  = access;
        req->manual  = (type == NotificationTimer);
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;

}


/**************************************************************************
 *		NtOpenTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_timer )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtSetTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtSetTimer( HANDLE handle, const LARGE_INTEGER *when, PTIMER_APC_ROUTINE callback,
                            void *arg, BOOLEAN resume, ULONG period, BOOLEAN *state )
{
    unsigned int ret = STATUS_SUCCESS;

    TRACE( "(%p,%p,%p,%p,%08x,0x%08x,%p)\n", handle, when, callback, arg, resume, period, state );

    SERVER_START_REQ( set_timer )
    {
        req->handle   = wine_server_obj_handle( handle );
        req->period   = period;
        req->expire   = when->QuadPart;
        req->callback = wine_server_client_ptr( callback );
        req->arg      = wine_server_client_ptr( arg );
        ret = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;

    /* set error but can still succeed */
    if (resume && ret == STATUS_SUCCESS) return STATUS_TIMER_RESUME_IGNORED;
    return ret;
}


/**************************************************************************
 *		NtCancelTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtCancelTimer( HANDLE handle, BOOLEAN *state )
{
    unsigned int ret;

    TRACE( "handle %p, state %p\n", handle, state );

    SERVER_START_REQ( cancel_timer )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *		NtQueryTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryTimer( HANDLE handle, TIMER_INFORMATION_CLASS class,
                              void *info, ULONG len, ULONG *ret_len )
{
    TIMER_BASIC_INFORMATION *basic_info = info;
    unsigned int ret;
    LARGE_INTEGER now;

    TRACE( "(%p,%d,%p,0x%08x,%p)\n", handle, class, info, len, ret_len );

    switch (class)
    {
    case TimerBasicInformation:
        if (len < sizeof(TIMER_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

        SERVER_START_REQ( get_timer_info )
        {
            req->handle = wine_server_obj_handle( handle );
            ret = wine_server_call(req);
            /* convert server time to absolute NTDLL time */
            basic_info->RemainingTime.QuadPart = reply->when;
            basic_info->TimerState = reply->signaled;
        }
        SERVER_END_REQ;

        /* convert into relative time */
        if (basic_info->RemainingTime.QuadPart > 0) NtQuerySystemTime( &now );
        else
        {
            NtQueryPerformanceCounter( &now, NULL );
            basic_info->RemainingTime.QuadPart = -basic_info->RemainingTime.QuadPart;
        }

        if (now.QuadPart > basic_info->RemainingTime.QuadPart)
            basic_info->RemainingTime.QuadPart = 0;
        else
            basic_info->RemainingTime.QuadPart -= now.QuadPart;

        if (ret_len) *ret_len = sizeof(TIMER_BASIC_INFORMATION);
        return ret;
    }

    FIXME( "Unhandled class %d\n", class );
    return STATUS_INVALID_INFO_CLASS;
}


/******************************************************************
 *		NtWaitForMultipleObjects (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForMultipleObjects( DWORD count, const HANDLE *handles, WAIT_TYPE type,
                                          BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT i, flags = SELECT_INTERRUPTIBLE;
    unsigned int ret;
#ifdef WINE_IOS
    LARGE_INTEGER madeira_store;   /* ml952: a relative timeout, less whatever
                                    * the fast path spent, when it falls through */
#endif

    if (!count || count > MAXIMUM_WAIT_OBJECTS) return STATUS_INVALID_PARAMETER_1;
    if (type != WaitAll && type != WaitAny) FIXME( "Unsupported wait type %u\n", type );
    ios_srv_nt_count( count > 1 ? IOS_NT_WAIT_MULTI : IOS_NT_WAIT_SINGLE );

    if (TRACE_ON(sync))
    {
        TRACE( "type %u, alertable %u, handles {%p", type, alertable, handles[0] );
        for (i = 1; i < count; i++) TRACE( ", %p", handles[i] );
        TRACE( "}, timeout %s\n", debugstr_timeout(timeout) );
    }

    /* Reject pseudo-handles up front. These are not valid for multi-object waits. */
    for (i = 0; i < count; i++)
    {
        if (is_pseudo_handle( handles[i] )) return STATUS_INVALID_HANDLE;
    }

    if ((ret = inproc_wait( count, handles, type, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
    {
        TRACE( "-> %#x\n", ret );
        return ret;
    }

#ifdef WINE_IOS
    /* ml952: a one-handle WaitAny is a NtWaitForSingleObject in disguise and
     * is the only multi-object shape the fast path may take -- wait-all and
     * anything with a second handle need the server's atomic evaluation. */
    if (count == 1 && type != WaitAll && !alertable)
    {
        const LARGE_INTEGER *left;

        if ((ret = madeira_fast_wait( handles[0], timeout, &left, &madeira_store )) != STATUS_NOT_IMPLEMENTED)
            return ret;
        timeout = left;   /* madeira_store has function scope: see above */
    }
#endif

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.wait.op = type == WaitAll ? SELECT_WAIT_ALL : SELECT_WAIT;
    for (i = 0; i < count; i++) select_op.wait.handles[i] = wine_server_obj_handle( handles[i] );
#ifdef WINE_IOS
    /* ml1060: no `!alertable' here any more -- see madeira_fast_watched_wait(). */
    if (count == 1 && type != WaitAll && !timeout && madeira_fastsync_enabled())
    {
        ret = madeira_fast_watched_wait( &select_op, offsetof( union select_op, wait.handles[1] ),
                                         flags, handles[0] );
        TRACE( "-> %#x\n", ret );
        return ret;
    }
#endif
    ret = server_wait( &select_op, offsetof( union select_op, wait.handles[count] ), flags, timeout );
#ifdef WINE_IOS
    /* ml1110: a finite wait that expired -- was the object signalled anyway? */
    if (ret == STATUS_TIMEOUT && count == 1 && type != WaitAll && timeout && timeout->QuadPart)
        madeira_late_note( handles[0], 0 );
#endif
    TRACE( "-> %#x\n", ret );
    return ret;
}


/******************************************************************
 *		NtWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForSingleObject( HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;
    unsigned int ret;
#ifdef WINE_IOS
    LARGE_INTEGER madeira_store;   /* ml952: see NtWaitForMultipleObjects */
#endif

    TRACE( "handle %p, alertable %u, timeout %s\n", handle, alertable, debugstr_timeout(timeout) );
    ios_srv_nt_count( IOS_NT_WAIT_SINGLE );

    if ((ret = inproc_wait( 1, &handle, WaitAny, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
    {
        TRACE( "-> %#x\n", ret );
        return ret;
    }

#ifdef WINE_IOS
    if (!alertable)
    {
        const LARGE_INTEGER *left;

        if ((ret = madeira_fast_wait( handle, timeout, &left, &madeira_store )) != STATUS_NOT_IMPLEMENTED)
        {
            TRACE( "-> %#x\n", ret );
            return ret;
        }
        timeout = left;   /* madeira_store has function scope: see above */
    }
#endif

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.wait.op = SELECT_WAIT;
    select_op.wait.handles[0] = wine_server_obj_handle( handle );
#ifdef WINE_IOS
    /* ml982: an INFINITE single-object wait is the one shape that can hang
     * forever if the fast path ever loses a set, so give it a heartbeat.
     * ml1060: including the ALERTABLE ones, which is every wait a managed
     * runtime issues -- see madeira_fast_watched_wait(). */
    if (!timeout && madeira_fastsync_enabled())
    {
        ret = madeira_fast_watched_wait( &select_op, offsetof( union select_op, wait.handles[1] ),
                                         flags, handle );
        TRACE( "-> %#x\n", ret );
        return ret;
    }
#endif
    ret = server_wait( &select_op, offsetof( union select_op, wait.handles[1] ), flags, timeout );
#ifdef WINE_IOS
    if (ret == STATUS_TIMEOUT && timeout && timeout->QuadPart) madeira_late_note( handle, 0 );
#endif
    TRACE( "-> %#x\n", ret );
    return ret;
}


/******************************************************************
 *		NtSignalAndWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtSignalAndWaitForSingleObject( HANDLE signal, HANDLE wait,
                                                BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;
    NTSTATUS ret;

    TRACE( "signal %p, wait %p, alertable %u, timeout %s\n", signal, wait, alertable, debugstr_timeout(timeout) );

    if (!signal) return STATUS_INVALID_HANDLE;
    ios_srv_nt_count( IOS_NT_SIGNAL_AND_WAIT );

    if ((ret = inproc_signal_and_wait( signal, wait, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.signal_and_wait.op = SELECT_SIGNAL_AND_WAIT;
    select_op.signal_and_wait.wait = wine_server_obj_handle( wait );
    select_op.signal_and_wait.signal = wine_server_obj_handle( signal );
    return server_wait( &select_op, sizeof(select_op.signal_and_wait), flags, timeout );
}


/******************************************************************
 *              iOS-Madeira ml970: ONE spin governor, for Sleep(0) AND
 *                                 for SwitchToThread
 *
 * HISTORY.  ml950 discovered that a 32-bit D3D9 title spins on Sleep(0) and
 * gave it a pause/yield ladder; ml951 turned the periodic yield into a bounded
 * futex park once a streak was unambiguously a spin; ml960 made the park
 * length escalate (10/50/200 us at streaks 512/4096/32768) because one rung
 * was still 33 k syscalls/s.  All three tuned the SMALLER of this process's
 * two spins.
 *
 * ml970 MEASUREMENT (log 46: 10 min of the same title at 40-60 fps; per 10 s
 * [srv-stats] window, 20 windows):
 *
 *     sleep0   = 1.27 - 2.01 M     (127 - 201 k Sleep(0)/s)
 *     park     = 108 - 196 k       ( 11 -  20 k futex parks/s -- the ladder)
 *     yield_sc = 8.2  - 14.3 M     (0.8 - 1.4 M sched_yield/s)   <-- the find
 *
 * and [prof] localises the yields to a single thread:
 *
 *     swtch_pri     <- Madeira`NtYieldExecution+0x28    13.9 - 15.2 % of ALL CPU
 *       kern by thread: -> tid=00c0 = 100 %             (one thread, no others)
 *     __ulock_wait2 <- Madeira`NtDelayExecution+0x3f4    6.6 -  8.6 %
 *     swtch_pri     <- Madeira`NtDelayExecution+0x410    2.8 -  3.7 %
 *
 * The two NtDelayExecution entries ARE the old ladder: ios_delay_zero is
 * inlined into NtDelayExecution, so both its park and its yield carry
 * NtDelayExecution return addresses.  NtYieldExecution+0x28 therefore cannot
 * be the ladder -- it is the EXPORTED entry point, i.e. callers from outside
 * this file.  There are only three: win32u's message pump (ml940, hard-capped
 * at 5 k/s), server_wait's zero-timeout poll streak (the whole process issues
 * 3.7 k server requests/s, so at most that), and the guest's own
 * SwitchToThread through wow64.  The ladder can account for at most ~60 k of
 * the 11.5 M yields in a window.  So ~99.5 % of 1.15 M sched_yield/s is ONE
 * 32-bit guest thread -- the render thread -- calling SwitchToThread in a spin
 * loop, and it had no throttle of any kind: every call was a syscall.  That is
 * 7x more Sleep(0)-equivalent spinning than Sleep(0) itself, and it is the
 * single largest kernel entry in the process.
 *
 * WHAT THE OLD LADDER GOT WRONG, besides missing that caller.  Its rungs are
 * indexed by CALL COUNT, so how deep a spinner gets depends on how fast its
 * loop happens to iterate, not on how long it has been waiting: a tight
 * SwitchToThread loop reaches rung 3 in microseconds while a loop with real
 * work between polls never leaves rung 0.  And its syscall rate is
 * 1-in-IOS_SLEEP0_YIELD_EVERY *calls*, which is a rate the ladder cannot bound
 * -- 1.15 M calls/s at 1-in-8 would still be 144 k syscalls/s.
 *
 * THE POLICY.  Index everything by ELAPSED SPIN TIME, and bound the KERNEL
 * ENTRY RATE directly instead of the call rate:
 *
 *   - between kernel entries the thread spins in userspace with an `isb sy'
 *     pause whose length doubles every 8 calls (8 -> 256 isb, ~100 ns -> ~3 us).
 *     A userspace poll adds NO handoff latency and costs no syscall, which is
 *     exactly the trade a spin-wait wants; the reason to leave userspace at all
 *     is fairness, not latency.
 *   - the thread enters the kernel at most once per GAP, where GAP grows with
 *     how long this streak has already run:
 *
 *         spun <  50 us : gap  20 us     park  15 us
 *         spun < 500 us : gap 100 us     park  15 us
 *         spun <   5 ms : gap 300 us     park  30 us
 *         spun >=  5 ms : gap 500 us     park  60 us
 *
 *     so a permanently spinning thread costs 1/500 us = 2 k syscalls/s, and the
 *     two spinning threads in this workload cost ~4 k/s together (target: 5 k).
 *   - the FIRST kernel entry of a streak is a real sched_yield(), every later
 *     one is a bounded futex park.  An isolated SwitchToThread or Sleep(0) --
 *     one that is pacing, not spinning -- therefore still performs a real,
 *     immediate yield, byte for byte the old semantics; only the 2nd and later
 *     calls of a back-to-back streak are governed.
 *   - PARK LENGTH IS DELIBERATELY SHORT and does NOT grow to fill the gap.
 *     The park exists to hand the core to whoever we are waiting for, not to
 *     sleep through the handoff: a 15-60 us park inside a 500 us gap means the
 *     probability that the peer's progress lands inside a park at all is
 *     60/500 = 12 %, so the ADDED handoff latency is 0 at the p50 and <= 60 us
 *     at the p88 -- against the old ladder's 200 us park reached after a
 *     quarter second of spinning.  The 1 ms hard cap the brief asks for is
 *     IOS_SPIN_PARK_MAX_NS below; nothing in the table comes near it.
 *
 * WHY IT STILL CANNOT LIVELOCK.  The classic failure is two guest threads on
 * one core where A polls a flag only B can set.  Rung 0's gap is 20 us, so a
 * brand-new streak reaches the kernel within 20 us of starting and A's first
 * kernel entry is a real yield; after that every kernel entry is a park, which
 * is a genuine deschedule, not a hint a loaded scheduler may ignore.  The
 * invariant is therefore stronger than the old ladder's: no governed thread
 * ever spins more than 500 us of wall time without descheduling, at ANY rung
 * and at any loop rate, where the old one only promised "every 8th call".
 *
 * PER-CALL-SITE LEARNING.  The brief asks for the streak distribution keyed by
 * the guest RIP.  That key is not cheaply available here and would be a lie if
 * it were: the wow64 CPU area's Eip is only valid after FEX flushes its JIT
 * state into it (see Context::FlushThreadStateContext), which is itself a
 * server round trip, and the unix-side return address is the syscall
 * dispatcher for every 32-bit caller alike.  What IS free and, on this
 * workload, equivalent is a PER-THREAD estimator: each spinning thread has one
 * dominant spin site (tid 00c0 is 100 % of the yields).  So the governor keeps
 * an EWMA of this thread's finished streak durations and, when history says
 * this thread's spins run long, starts one rung in instead of paying the
 * cheap-rung syscalls again -- the "park length that would have covered ~80 %
 * of past streaks" idea, applied to the gap rather than the park because the
 * gap is what the syscall rate is a function of.  The FULL distribution goes
 * to the log as `[sleep0] hist:' (ios_spin_hist.h) so the next capture either
 * justifies these constants or replaces them; if it shows several distinct
 * modes per thread, that is the evidence that a real per-site key is worth its
 * cost, and not before.
 */
#define IOS_SPIN_WINDOW      20000ull   /* 2 ms, in 100 ns ticks: gap that ends a streak */
#define IOS_SPIN_T1            500ull   /* 50 us  */
#define IOS_SPIN_T2           5000ull   /* 500 us */
#define IOS_SPIN_T3          50000ull   /* 5 ms   */
#define IOS_SPIN_PARK_MAX_NS 1000000ull /* hard cap: never park past 1 ms */

/* iOS-Madeira ml998: THE DEEP RUNGS WERE SPINNING, NOT PARKING.
 *
 * `gap' is the minimum time between kernel entries and `park' is how long the
 * thread is descheduled at each one, so the fraction of a streak this thread
 * is NOT burning a core is park/gap.  The ml970 tables read as an escalation
 * but they are the opposite of one:
 *
 *      rung 0   park 15 us / gap  20 us  =  75 % parked
 *      rung 1   park 15 us / gap 100 us  =  15 % parked
 *      rung 2   park 30 us / gap 300 us  =  10 % parked
 *      rung 3   park 60 us / gap 500 us  =  12 % parked
 *
 * The longer the spin had already run -- that is, the more certain it was that
 * this thread had nothing to do -- the larger the share of the time it spent
 * in ios_cpu_pause() burning the core.  The escalation removed SYSCALLS, but
 * the syscall is the only part of a rung that gives the CPU back, so removing
 * it removed the saving and kept the cost.
 *
 * What that cost, measured: [prof] names `ios_spin_governor+0x320' -- the ISB
 * delay loop -- as the single hottest PC in the process in almost every
 * 10 s window of the qp4.txt capture, at 23.6-31.7 % of all CPU mid-game and
 * 50.6-60.8 % during level loads, more than the JIT and more than the file
 * lookups.  [sleep0] explains why: 2.6 M governed calls per 10 s window from
 * ~500 streaks, i.e. ~2 us of ISB per call for the entire length of a streak.
 *
 * The retune sets park just under gap on every rung, so a thread that is
 * waiting is parked ~95 % of the time instead of ~10 %.  It is exactly the
 * same ladder and the same policy; only the duty cycle changes.
 *
 * The latency this costs is bounded by the rung's park length, and [sleep0]'s
 * own distribution says what that is worth: `hist us' puts 96 % of finished
 * streaks at >= 2 ms and the p50 time-to-progress at 8 ms with p80 at 16 ms,
 * with fewer than 5 % finishing under 1 ms.  So the deepest rung's 380 us
 * granularity is under 5 % of the median wait it applies to, against giving
 * back ~0.7 of a core.  The short rungs stay short precisely because a spin
 * that has not yet run 500 us might still be a genuine quick handoff.
 *
 * The syscall rate barely moves, which is the part worth being explicit
 * about: the gaps shrank by only ~20 %, so a p50 8 ms streak still takes on
 * the order of 25 kernel entries rather than the ~22 it took before.  What
 * changes is what those entries do with the time between them -- ~7.5 ms of
 * the 8 ms is now spent descheduled instead of ~1 ms.  [srv-stats] `park'
 * should therefore read ~3.0-3.2 k/s where it read ~2.5 k/s, while [sleep0]
 * `sleep0'+`yield' collapse from ~2.6 M per 10 s window to ~130 k, because a
 * parked thread is not calling the governor at all.
 *
 * Unchanged: the first kernel entry of a streak is still a real sched_yield(),
 * so Sleep(0)/SwitchToThread keeps its Windows-observable semantics, and
 * IOS_SPIN_PARK_MAX_NS still caps every park at 1 ms. */

/* kernel-entry gap per rung, in 100 ns ticks */
static const ULONGLONG ios_spin_gap_ticks[4]  = {   200ull,  1000ull,  2500ull,   4000ull };
/* park length per rung, in ns -- just under the rung's gap, so the thread is
 * descheduled for essentially the whole of it */
static const ULONGLONG ios_spin_park_ns[4]    = { 15000ull, 80000ull, 240000ull, 380000ull };

static __thread ULONGLONG    ios_spin_t0;        /* streak start, ticks           */
static __thread ULONGLONG    ios_spin_last;      /* last governed call, ticks     */
static __thread ULONGLONG    ios_spin_sys;       /* last kernel entry, 0 = none   */
static __thread ULONGLONG    ios_spin_ewma;      /* EWMA of past streak durations */
static __thread unsigned int ios_spin_calls;     /* calls in the current streak   */
static __thread unsigned int ios_spin_syscalls;  /* kernel entries in this streak */
static __thread unsigned int ios_spin_pause_shift;

/* ml970: the distribution, for [srv-stats].  See build/ntdll-unix/shims/ios_spin_hist.h. */
static unsigned int       ios_spin_h_calls[IOS_SPIN_HIST_N];
static unsigned int       ios_spin_h_us[IOS_SPIN_HIST_N];
static unsigned int       ios_spin_n_streaks, ios_spin_n_sleep0, ios_spin_n_yield;
static unsigned int       ios_spin_n_sys_yield, ios_spin_n_sys_park, ios_spin_n_warm;

static inline void ios_cpu_pause( unsigned int loops )
{
#if defined(__aarch64__) || defined(__arm64__)
    while (loops--) __asm__ __volatile__( "isb sy" ::: "memory" );
#else
    while (loops--) __asm__ __volatile__( "" ::: "memory" );
#endif
}

static inline void ios_raw_yield(void)
{
#ifdef HAVE_SCHED_YIELD
    ios_srv_nt_count( IOS_NT_YIELD_SYSCALL );
    __atomic_fetch_add( &ios_spin_n_sys_yield, 1, __ATOMIC_RELAXED );
    sched_yield();
#endif
}

/* bounded deschedule: wait on a private word nothing ever wakes, so this
 * always returns by timeout.  futex_wait() maps to
 * os_sync_wait_on_address_with_timeout()/__ulock_wait() on Darwin.
 * ml970: `ns' is the rung's park length and is clamped to the 1 ms cap here,
 * so no future table edit can smuggle a longer sleep past the invariant. */
static void ios_cpu_park( ULONGLONG ns )
{
#ifdef USE_FUTEX
    static __thread LONG park_word;
    struct timespec ts;

    if (ns > IOS_SPIN_PARK_MAX_NS) ns = IOS_SPIN_PARK_MAX_NS;
    ts.tv_sec  = 0;
    ts.tv_nsec = (long)ns;
    ios_srv_nt_count( IOS_NT_SLEEP0_PARK );
    __atomic_fetch_add( &ios_spin_n_sys_park, 1, __ATOMIC_RELAXED );
    futex_wait( &park_word, 0, &ts );
#else
    (void)ns;
    ios_raw_yield();
#endif
}

static inline int ios_spin_log2b( unsigned long long v )
{
    int b = 0;
    while (v > 1 && b < IOS_SPIN_HIST_N - 1) { v >>= 1; b++; }
    return b;
}

/* A streak ends when the thread makes progress: a real wait (server_wait calls
 * ios_spin_reset), a non-zero sleep, or a gap longer than the 2 ms window.
 * That is why the duration recorded here IS the time-to-progress. */
static void ios_spin_end_streak(void)
{
    ULONGLONG dur_us;

    if (!ios_spin_calls) return;
    dur_us = (ios_spin_last - ios_spin_t0) / 10;
    __atomic_fetch_add( &ios_spin_h_calls[ios_spin_log2b( ios_spin_calls )], 1, __ATOMIC_RELAXED );
    __atomic_fetch_add( &ios_spin_h_us[ios_spin_log2b( dur_us + 1 )], 1, __ATOMIC_RELAXED );
    __atomic_fetch_add( &ios_spin_n_streaks, 1, __ATOMIC_RELAXED );
    /* EWMA with a 1/4 weight: fast enough to follow a phase change (loading ->
     * gameplay), slow enough that one long stall does not pin the thread on a
     * deep rung for the next thousand streaks. */
    ios_spin_ewma = ios_spin_ewma ? (ios_spin_ewma * 3 + (ios_spin_last - ios_spin_t0)) / 4
                                  : (ios_spin_last - ios_spin_t0);
    ios_spin_calls = 0;
    ios_spin_syscalls = 0;
    ios_spin_pause_shift = 0;
    ios_spin_sys = 0;
}

/* called from server_ios.c's server_wait, and from the non-zero delay path */
void ios_spin_reset(void)
{
    ios_spin_end_streak();
}

/* ml950 name kept: build/ntdll-unix/server_ios.c calls ios_spin_reset(). */

/* from_yield: 1 = NtYieldExecution (SwitchToThread), 0 = Sleep(0). */
static NTSTATUS ios_spin_governor( int from_yield )
{
    ULONGLONG now = monotonic_counter(), spun, gap;
    int rung, warm;

    if (now - ios_spin_last > IOS_SPIN_WINDOW)
    {
        ios_spin_end_streak();
        ios_spin_t0 = now;
    }
    ios_spin_last = now;
    ios_spin_calls++;
    __atomic_fetch_add( from_yield ? &ios_spin_n_yield : &ios_spin_n_sleep0, 1, __ATOMIC_RELAXED );

    spun = now - ios_spin_t0;
    rung = spun >= IOS_SPIN_T3 ? 3 : spun >= IOS_SPIN_T2 ? 2 : spun >= IOS_SPIN_T1 ? 1 : 0;

    /* Learned start (see the note above): a thread whose spins have
     * historically run for milliseconds gains nothing from the 20 us rung but
     * its syscalls, so skip ahead.  Never past rung 2, so every thread still
     * reaches the kernel inside 300 us of a streak starting no matter what the
     * estimator believes. */
    warm = ios_spin_ewma >= IOS_SPIN_T3 ? 2 : ios_spin_ewma >= IOS_SPIN_T2 ? 1 : 0;
    if (rung < warm)
    {
        rung = warm;
        if (ios_spin_calls == 1) __atomic_fetch_add( &ios_spin_n_warm, 1, __ATOMIC_RELAXED );
    }
    gap = ios_spin_gap_ticks[rung];

    if (!ios_spin_sys || now - ios_spin_sys >= gap)
    {
        ios_spin_sys = now;
        if (!ios_spin_syscalls++)
        {
            /* First kernel entry of a streak: a real yield, exactly as an
             * ungoverned Sleep(0)/SwitchToThread would have done.  This is the
             * whole of the Windows-observable semantics ("other runnable
             * threads may have the CPU"), and it is what a pacing caller --
             * one call per frame, one per queue drain -- gets every time,
             * because a 16 ms gap always starts a fresh streak. */
            ios_raw_yield();
        }
        else ios_cpu_park( ios_spin_park_ns[rung] );
        return STATUS_SUCCESS;
    }

    ios_cpu_pause( 8u << ios_spin_pause_shift );
    if (ios_spin_pause_shift < 5 && !(ios_spin_calls & 7)) ios_spin_pause_shift++;
    return STATUS_SUCCESS;
}

/* [srv-stats] pulls the window's distribution through here once per 10 s. */
void ios_spin_hist_snapshot( struct ios_spin_snapshot *out )
{
    unsigned int i, total = 0, acc = 0;

    for (i = 0; i < IOS_SPIN_HIST_N; i++)
    {
        out->calls[i] = __atomic_exchange_n( &ios_spin_h_calls[i], 0, __ATOMIC_RELAXED );
        out->us[i]    = __atomic_exchange_n( &ios_spin_h_us[i], 0, __ATOMIC_RELAXED );
        total += out->us[i];
    }
    out->streaks    = __atomic_exchange_n( &ios_spin_n_streaks, 0, __ATOMIC_RELAXED );
    out->gov_sleep0 = __atomic_exchange_n( &ios_spin_n_sleep0, 0, __ATOMIC_RELAXED );
    out->gov_yield  = __atomic_exchange_n( &ios_spin_n_yield, 0, __ATOMIC_RELAXED );
    out->sys_yield  = __atomic_exchange_n( &ios_spin_n_sys_yield, 0, __ATOMIC_RELAXED );
    out->sys_park   = __atomic_exchange_n( &ios_spin_n_sys_park, 0, __ATOMIC_RELAXED );
    out->warm_hits  = __atomic_exchange_n( &ios_spin_n_warm, 0, __ATOMIC_RELAXED );

    /* Bucket-resolution percentiles: bucket i holds durations in
     * [2^(i-1), 2^i) us, and the reported value is that bucket's low edge.
     * Coarse on purpose -- the policy's rungs are decades apart, so a decade
     * is the precision the decision actually needs. */
    out->us_p50 = out->us_p80 = 0;
    for (i = 0; i < IOS_SPIN_HIST_N && total; i++)
    {
        acc += out->us[i];
        if (!out->us_p50 && acc * 2 >= total)  out->us_p50 = i ? (1u << i) : 0;
        if (!out->us_p80 && acc * 5 >= total * 4) { out->us_p80 = i ? (1u << i) : 0; break; }
    }
}


/******************************************************************
 *		NtYieldExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtYieldExecution(void)
{
#ifdef HAVE_SCHED_YIELD
    /* iOS-Madeira ml940: upstream brackets the yield with two
     * getrusage( RUSAGE_THREAD ) calls and compares ru_nvcsw/ru_nivcsw to
     * decide STATUS_NO_YIELD_PERFORMED.  RUSAGE_THREAD is a Linux extension:
     * the iPhoneOS SDK's <sys/resource.h> defines only RUSAGE_SELF and
     * RUSAGE_CHILDREN, so on this target both calls were already
     * preprocessed away and this function has always been the older
     * upstream body - sched_yield() then STATUS_SUCCESS, which is what Wine
     * returned unconditionally for years before the rusage heuristic was
     * added.  Removed outright so the dead branch cannot come back through a
     * RUSAGE_THREAD shim, because there is no cheap honest substitute on
     * Darwin: swtch_pri(0) (what libsystem_kernel turns sched_yield into)
     * reports nothing about whether another thread ran, and a
     * clock_gettime( CLOCK_MONOTONIC_RAW ) delta - a commpage read here, not
     * a syscall - would only measure elapsed time, never a context switch,
     * so it would be a guess dressed up as a fact.  The only consumer is
     * kernelbase's SwitchToThread (dlls/kernelbase/thread.c:707), whose
     * BOOL is advisory.
     *
     * iOS-Madeira ml970: and the syscall itself now goes through the spin
     * governor above.  [prof] measured 1.15 M sched_yield/s arriving HERE,
     * from one 32-bit guest thread's SwitchToThread spin loop -- 13.9-15.2 %
     * of all CPU, the largest kernel entry in the process and seven times the
     * Sleep(0) traffic the ml950-ml960 ladder was built for.  The return value
     * is unchanged (STATUS_SUCCESS, never STATUS_NO_YIELD_PERFORMED) and an
     * isolated call still issues a real, immediate sched_yield(); what the
     * governor removes is the 2nd..Nth syscall of a back-to-back streak.
     * Callers that are themselves rate limited (win32u's ios_pump_yield,
     * server_wait's poll streak) are unaffected in practice: their own limits
     * are far below the governor's first rung. */
    return ios_spin_governor( 1 );
#else
    return STATUS_NO_YIELD_PERFORMED;
#endif
}


/******************************************************************
 *		NtDelayExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    unsigned int status = STATUS_SUCCESS;

    /* if alertable, we need to query the server */
    if (alertable)
    {
        /* Since server_wait will result in an unconditional implicit yield,
           we never return STATUS_NO_YIELD_PERFORMED */
        if ((status = server_wait( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE, timeout )) == STATUS_TIMEOUT)
            status = STATUS_SUCCESS;
        return status;
    }

    if (!timeout || timeout->QuadPart == TIMEOUT_INFINITE)  /* sleep forever */
    {
        for (;;) select( 0, NULL, NULL, NULL, NULL );
    }
    else
    {
        LARGE_INTEGER now;
        timeout_t when, diff;

        if ((when = timeout->QuadPart) < 0)
        {
            NtQuerySystemTime( &now );
            when = now.QuadPart - when;
        }

        /* Note that we yield after establishing the desired timeout, but
           we only care about the result of the yield for zero timeouts.
           iOS-Madeira ml940: upstream yields here unconditionally and only
           then tests `when'.  A zero timeout (Sleep(0)) IS a pure yield and
           its status is the one thing the caller can observe, so it still
           yields.  A non-zero timeout is about to block in the select()
           loop below, which deschedules this thread anyway, so the extra
           swtch_pri(0) bought nothing and cost one syscall on every single
           Sleep(n) - a 1 ms pacing loop paid it a thousand times a second.
           The alertable path above never yielded either (server_wait's wait
           is the implicit yield), so this makes the two paths agree.
           iOS-Madeira ml950: and a zero timeout now goes through the streak
           limiter above instead of an unconditional syscall. */
        if (!when)
        {
            ios_srv_nt_count( IOS_NT_DELAY_ZERO );
            return ios_spin_governor( 0 );
        }
        ios_srv_nt_count( IOS_NT_DELAY_NONZERO );
        ios_spin_reset();

        /* ml1050: charge a real Sleep(n) on the PRESENTING thread to the frame
         * breakdown's `sleep=' bucket.  This is the bucket that catches a
         * poll-with-backoff handoff -- libc++'s std::atomic::wait fallback,
         * which DXMT's CpuFence and chunk ring both ride, escalates to
         * sleep_for(elapsed/2) once a wait passes ~64 us, and a millisecond
         * of that per frame is invisible in every other counter this port
         * has.  Two clock reads, only on the presenting thread. */
        {
#ifdef WINE_IOS
            unsigned long long sl0 = ios_frame_tracking() ? madeira_now_ns() : 0;
#endif
            for (;;)
            {
                struct timeval tv;
                NtQuerySystemTime( &now );
                diff = (when - now.QuadPart + 9) / 10;
                if (diff <= 0) break;
                tv.tv_sec  = diff / 1000000;
                tv.tv_usec = diff % 1000000;
                if (select( 0, NULL, NULL, NULL, &tv ) != -1) break;
            }
#ifdef WINE_IOS
            if (sl0) ios_frame_wait_add( IOS_FRAME_WAIT_SLEEP, madeira_now_ns() - sl0 );
#endif
        }
    }
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtQueryPerformanceCounter (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryPerformanceCounter( LARGE_INTEGER *counter, LARGE_INTEGER *frequency )
{
    counter->QuadPart = monotonic_counter();
    if (frequency) frequency->QuadPart = TICKSPERSEC;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtQuerySystemTime (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySystemTime( LARGE_INTEGER *time )
{
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;
    static clockid_t clock_id = CLOCK_MONOTONIC; /* placeholder */

    if (clock_id == CLOCK_MONOTONIC)
    {
#ifdef CLOCK_REALTIME_COARSE
        struct timespec res;

        /* Use CLOCK_REALTIME_COARSE if it has 1 ms or better resolution */
        if (!clock_getres( CLOCK_REALTIME_COARSE, &res ) && res.tv_sec == 0 && res.tv_nsec <= 1000000)
            clock_id = CLOCK_REALTIME_COARSE;
        else
#endif /* CLOCK_REALTIME_COARSE */
            clock_id = CLOCK_REALTIME;
    }

    if (!clock_gettime( clock_id, &ts ))
    {
        time->QuadPart = ticks_from_time_t( ts.tv_sec ) + (ts.tv_nsec + 50) / 100;
    }
    else
#endif /* HAVE_CLOCK_GETTIME */
    {
        struct timeval now;

        gettimeofday( &now, 0 );
        time->QuadPart = ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10;
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetSystemTime (NTDLL.@)
 */
NTSTATUS WINAPI NtSetSystemTime( const LARGE_INTEGER *new, LARGE_INTEGER *old )
{
    LARGE_INTEGER now;
    LONGLONG diff;

    NtQuerySystemTime( &now );
    if (old) *old = now;
    diff = new->QuadPart - now.QuadPart;
    if (diff > -TICKSPERSEC / 2 && diff < TICKSPERSEC / 2) return STATUS_SUCCESS;
    ERR( "not allowed: difference %d ms\n", (int)(diff / 10000) );
    return STATUS_PRIVILEGE_NOT_HELD;
}


/***********************************************************************
 *              NtQueryTimerResolution (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryTimerResolution( ULONG *min_res, ULONG *max_res, ULONG *current_res )
{
    TRACE( "(%p,%p,%p)\n", min_res, max_res, current_res );
    *max_res = *current_res = 10000; /* See NtSetTimerResolution() */
    *min_res = 156250;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetTimerResolution (NTDLL.@)
 */
NTSTATUS WINAPI NtSetTimerResolution( ULONG res, BOOLEAN set, ULONG *current_res )
{
    static BOOL has_request = FALSE;

    TRACE( "(%u,%u,%p), semi-stub!\n", res, set, current_res );

    /* Wine has no support for anything other that 1 ms and does not keep of
     * track resolution requests anyway.
     * Fortunately NtSetTimerResolution() should ignore requests to lower the
     * timer resolution. So by claiming that 'some other process' requested the
     * max resolution already, there no need to actually change it.
     */
    *current_res = 10000;

    /* Just keep track of whether this process requested a specific timer
     * resolution.
     */
    if (!has_request && !set)
        return STATUS_TIMER_RESOLUTION_NOT_SET;
    has_request = set;

    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtSetIntervalProfile (NTDLL.@)
 */
NTSTATUS WINAPI NtSetIntervalProfile( ULONG interval, KPROFILE_SOURCE source )
{
    FIXME( "%u,%d\n", interval, source );
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtGetTickCount (NTDLL.@)
 */
ULONG WINAPI NtGetTickCount(void)
{
    /* note: we ignore TickCountMultiplier */
    return user_shared_data->TickCount.LowPart;
}


/******************************************************************************
 *              RtlGetSystemTimePrecise (NTDLL.@)
 */
NTSTATUS system_time_precise( void *args )
{
    LONGLONG *ret = args;
    struct timeval now;
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;

    if (!clock_gettime( CLOCK_REALTIME, &ts ))
    {
        *ret = ticks_from_time_t( ts.tv_sec ) + (ts.tv_nsec + 50) / 100;
        return STATUS_SUCCESS;
    }
#endif
    gettimeofday( &now, 0 );
    *ret = ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtCreateKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateKeyedEvent( HANDLE *handle, ACCESS_MASK access,
                                    const OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, flags %#x\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", flags );

    *handle = 0;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_keyed_event )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenKeyedEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_keyed_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}

#ifdef WINE_IOS
/* iOS-Madeira: the process-default keyed event (the one NtWaitForKeyedEvent /
 * NtReleaseKeyedEvent substitute for a NULL handle — reached from
 * RtlRunOnceBeginInitialize / RtlRunOnceComplete on contention) used to be a
 * single anonymous handle created once during session boot.  Every Windows
 * process here is a pseudo-process inside ONE Mach task but wineserver handle
 * tables are PER pseudo-process, so that handle names a DIFFERENT object (or
 * nothing) in every child — the same class of bug that made a 32-bit child's
 * NtMapViewOfSection of the GDI shared section fail with
 * STATUS_OBJECT_TYPE_MISMATCH.  The object NAMESPACE, by contrast, is
 * session-wide, so the default keyed event is a NAMED object (the name Windows
 * itself uses) that each pseudo-process opens into its own table, once.
 * wineserver already creates that object permanently at startup
 * (server/directory.c), so OBJ_OPENIF turns this into a plain open in one round
 * trip and still works if it is ever absent.  Keys are addresses in the one
 * shared address space, so they cannot collide between pseudo-processes and a
 * single shared object pairs waiters and releasers correctly. */
static const WCHAR ios_keyed_event_nameW[] =
    {'\\','K','e','r','n','e','l','O','b','j','e','c','t','s','\\',
     'C','r','i','t','S','e','c','O','u','t','O','f','M','e','m','o','r','y','E','v','e','n','t',0};

HANDLE ios_default_keyed_event(void)
{
    static struct { void *peb; HANDLE handle; } cache[16];
    static unsigned int cache_count, cache_next;
    static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
    void *peb = NtCurrentTeb()->Peb;
    HANDLE handle = 0;
    unsigned int i;

    pthread_mutex_lock( &cache_lock );
    for (i = 0; i < cache_count; i++)
        if (cache[i].peb == peb) { handle = cache[i].handle; break; }

    if (i == cache_count)
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING( ios_keyed_event_nameW );
        OBJECT_ATTRIBUTES attr;
        unsigned int status;

        InitializeObjectAttributes( &attr, &name, OBJ_OPENIF | OBJ_CASE_INSENSITIVE, 0, NULL );
        status = NtCreateKeyedEvent( &handle, GENERIC_READ | GENERIC_WRITE, &attr, 0 );
        if (status && status != STATUS_OBJECT_NAME_EXISTS)
        {
            /* An anonymous one still belongs to THIS handle table, which is the
             * property that was missing; RtlRunOnce keys are addresses in the
             * one shared address space, so they never collide between
             * pseudo-processes and a per-process object pairs correctly. */
            ERR( "[keyed-event] peb=%p: cannot create/open %s (%#x) — using a private one\n",
                 peb, debugstr_w(ios_keyed_event_nameW), status );
            if (NtCreateKeyedEvent( &handle, GENERIC_READ | GENERIC_WRITE, NULL, 0 ))
                handle = keyed_event;
        }
        /* rotating: a slot that is being overwritten belongs to a
         * pseudo-process that exited long ago (its whole handle table is gone
         * with it), and a live one that loses its slot simply opens again. */
        i = cache_next;
        cache[i].peb = peb;
        cache[i].handle = handle;
        cache_next = (i + 1) % ARRAY_SIZE(cache);
        if (cache_count < ARRAY_SIZE(cache)) cache_count++;
    }
    pthread_mutex_unlock( &cache_lock );
    return handle;
}
#endif

/******************************************************************************
 *              NtWaitForKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    TRACE( "handle %p, key %p, alertable %u, timeout %s\n", handle, key, alertable, debugstr_timeout(timeout) );

#ifdef WINE_IOS
    if (!handle) handle = ios_default_keyed_event();
#else
    if (!handle) handle = keyed_event;
#endif
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_WAIT;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_wait( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}


/******************************************************************************
 *              NtReleaseKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    TRACE( "handle %p, key %p, alertable %u, timeout %s\n", handle, key, alertable, debugstr_timeout(timeout) );

#ifdef WINE_IOS
    if (!handle) handle = ios_default_keyed_event();
#else
    if (!handle) handle = keyed_event;
#endif
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_RELEASE;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_wait( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}


/***********************************************************************
 *             NtCreateIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateIoCompletion( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                      ULONG threads )
{
    unsigned int status;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "(%p, %x, %p, %d)\n", handle, access, attr, threads );

    *handle = 0;
    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_completion )
    {
        req->access     = access;
        req->concurrent = threads;
        wine_server_add_data( req, objattr, len );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return status;
}


/***********************************************************************
 *             NtOpenIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenIoCompletion( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int status;

    *handle = 0;
    if ((status = validate_open_object_attributes( attr ))) return status;

    SERVER_START_REQ( open_completion )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}


/***********************************************************************
 *             NtSetIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtSetIoCompletion( HANDLE handle, ULONG_PTR key, ULONG_PTR value,
                                   NTSTATUS status, SIZE_T count )
{
    unsigned int ret;

    TRACE( "(%p, %lx, %lx, %x, %lx)\n", handle, key, value, status, count );

    SERVER_START_REQ( add_completion )
    {
        req->handle      = wine_server_obj_handle( handle );
        req->ckey        = key;
        req->cvalue      = value;
        req->status      = status;
        req->information = count;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}

/***********************************************************************
 *             NtSetIoCompletionEx (NTDLL.@)
 *
 * completion_reserve_handle is a handle allocated by NtAllocateReserveObject() for pre-allocating
 * memory for completion objects to deal with low-memory situations. It's not in use for now.
 */
NTSTATUS WINAPI NtSetIoCompletionEx( HANDLE completion_handle, HANDLE completion_reserve_handle,
                                     ULONG_PTR key, ULONG_PTR value, NTSTATUS status, SIZE_T count )
{
    unsigned int ret;

    TRACE( "(%p, %p, %lx, %lx, %x, %lx)\n", completion_handle, completion_reserve_handle,
           key, value, status, count );

    if (!completion_reserve_handle) return STATUS_INVALID_HANDLE;

    SERVER_START_REQ( add_completion )
    {
        req->handle         = wine_server_obj_handle( completion_handle );
        req->ckey           = key;
        req->cvalue         = value;
        req->status         = status;
        req->information    = count;
        req->reserve_handle = wine_server_obj_handle( completion_reserve_handle );
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}

/***********************************************************************
 *             NtRemoveIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletion( HANDLE handle, ULONG_PTR *key, ULONG_PTR *value,
                                      IO_STATUS_BLOCK *io, LARGE_INTEGER *timeout )
{
    HANDLE wait_handle = NULL;
    unsigned int status;

    TRACE( "(%p, %p, %p, %p, %p)\n", handle, key, value, io, timeout );

    SERVER_START_REQ( remove_completion )
    {
        req->handle = wine_server_obj_handle( handle );
        req->alertable = 0;
        if (!(status = wine_server_call( req )))
        {
            *key            = reply->ckey;
            *value          = reply->cvalue;
            io->Information = reply->information;
            io->Status      = reply->status;
        }
        else wait_handle = wine_server_ptr_handle( reply->wait_handle );
    }
    SERVER_END_REQ;
    if (status != STATUS_PENDING) return status;
    if (!timeout || timeout->QuadPart) status = server_wait_for_object( wait_handle, FALSE, timeout );
    else                               status = STATUS_TIMEOUT;
    if (status != WAIT_OBJECT_0) return status;

    SERVER_START_REQ( get_thread_completion )
    {
        if (!(status = wine_server_call( req )))
        {
            *key            = reply->ckey;
            *value          = reply->cvalue;
            io->Information = reply->information;
            io->Status      = reply->status;
        }
    }
    SERVER_END_REQ;

    return status;
}


/***********************************************************************
 *             NtRemoveIoCompletionEx (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletionEx( HANDLE handle, FILE_IO_COMPLETION_INFORMATION *info, ULONG count,
                                        ULONG *written, LARGE_INTEGER *timeout, BOOLEAN alertable )
{
    HANDLE wait_handle = NULL;
    unsigned int status;
    ULONG i = 0;

    TRACE( "%p %p %u %p %p %u\n", handle, info, count, written, timeout, alertable );

    if (!count) return STATUS_INVALID_PARAMETER;

    while (i < count)
    {
        SERVER_START_REQ( remove_completion )
        {
            req->handle = wine_server_obj_handle( handle );
            req->alertable = alertable;
            if (!(status = wine_server_call( req )))
            {
                info[i].CompletionKey             = reply->ckey;
                info[i].CompletionValue           = reply->cvalue;
                info[i].IoStatusBlock.Information = reply->information;
                info[i].IoStatusBlock.Status      = reply->status;
            }
            else wait_handle = wine_server_ptr_handle( reply->wait_handle );
        }
        SERVER_END_REQ;
        if (status != STATUS_SUCCESS) break;
        ++i;
    }
    if (i || (status != STATUS_PENDING && status != STATUS_USER_APC))
    {
        if (i) status = STATUS_SUCCESS;
        goto done;
    }
    if (status == STATUS_USER_APC)
    {
        status = NtDelayExecution( TRUE, NULL );
        assert( status == STATUS_USER_APC );
        goto done;
    }
    if (!timeout || timeout->QuadPart) status = server_wait_for_object( wait_handle, alertable, timeout );
    else                               status = STATUS_TIMEOUT;
    if (status != WAIT_OBJECT_0) goto done;

    SERVER_START_REQ( get_thread_completion )
    {
        if (!(status = wine_server_call( req )))
        {
            info[i].CompletionKey             = reply->ckey;
            info[i].CompletionValue           = reply->cvalue;
            info[i].IoStatusBlock.Information = reply->information;
            info[i].IoStatusBlock.Status      = reply->status;
            ++i;
        }
    }
    SERVER_END_REQ;

done:
    *written = i ? i : 1;
    return status;
}


/***********************************************************************
 *             NtQueryIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryIoCompletion( HANDLE handle, IO_COMPLETION_INFORMATION_CLASS class,
                                     void *buffer, ULONG len, ULONG *ret_len )
{
    unsigned int status;

    TRACE( "(%p, %d, %p, 0x%x, %p)\n", handle, class, buffer, len, ret_len );

    if (!buffer) return STATUS_INVALID_PARAMETER;

    switch (class)
    {
    case IoCompletionBasicInformation:
    {
        ULONG *info = buffer;
        if (ret_len) *ret_len = sizeof(*info);
        if (len == sizeof(*info))
        {
            SERVER_START_REQ( query_completion )
            {
                req->handle = wine_server_obj_handle( handle );
                if (!(status = wine_server_call( req ))) *info = reply->depth;
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INFO_LENGTH_MISMATCH;
        break;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }
    return status;
}


/***********************************************************************
 *             NtCreateSection (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                 const LARGE_INTEGER *size, ULONG protect,
                                 ULONG sec_flags, HANDLE file )
{
    unsigned int ret;
    unsigned int file_access;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;

    switch (protect & 0xff)
    {
    case PAGE_READONLY:
    case PAGE_EXECUTE_READ:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_WRITECOPY:
        file_access = FILE_READ_DATA;
        break;
    case PAGE_READWRITE:
    case PAGE_EXECUTE_READWRITE:
        if (sec_flags & SEC_IMAGE) file_access = FILE_READ_DATA;
        else file_access = FILE_READ_DATA | FILE_WRITE_DATA;
        break;
    case PAGE_EXECUTE:
    case PAGE_NOACCESS:
        file_access = 0;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_mapping )
    {
        req->access      = access;
        req->flags       = sec_flags;
        req->file_handle = wine_server_obj_handle( file );
        req->file_access = file_access;
        req->size        = size ? size->QuadPart : 0;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/***********************************************************************
 *             NtCreateSectionEx (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSectionEx( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                   const LARGE_INTEGER *size, ULONG protect, ULONG sec_flags,
                                   HANDLE file, MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    if (count) FIXME( "extended params not supported\n" );
    return NtCreateSection( handle, access, attr, size, protect, sec_flags, file );
}


/***********************************************************************
 *             NtOpenSection (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_mapping )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/***********************************************************************
 *             NtCreatePort (NTDLL.@)
 */
NTSTATUS WINAPI NtCreatePort( HANDLE *handle, OBJECT_ATTRIBUTES *attr, ULONG info_len,
                              ULONG data_len, ULONG *reserved )
{
    FIXME( "(%p,%p,%u,%u,%p),stub!\n", handle, attr, info_len, data_len, reserved );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                               LPC_SECTION_WRITE *write, LPC_SECTION_READ *read, ULONG *max_len,
                               void *info, ULONG *info_len )
{
    FIXME( "(%p,%s,%p,%p,%p,%p,%p,%p),stub!\n", handle, debugstr_us(name), qos,
           write, read, max_len, info, info_len );
    if (info && info_len) TRACE("msg = %s\n", debugstr_an( info, *info_len ));
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtSecureConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtSecureConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                                     LPC_SECTION_WRITE *write, PSID sid, LPC_SECTION_READ *read,
                                     ULONG *max_len, void *info, ULONG *info_len )
{
    FIXME( "(%p,%s,%p,%p,%p,%p,%p,%p,%p),stub!\n", handle, debugstr_us(name), qos,
           write, sid, read, max_len, info, info_len );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtListenPort (NTDLL.@)
 */
NTSTATUS WINAPI NtListenPort( HANDLE handle, LPC_MESSAGE *msg )
{
    FIXME("(%p,%p),stub!\n", handle, msg );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtAcceptConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtAcceptConnectPort( HANDLE *handle, ULONG id, LPC_MESSAGE *msg, BOOLEAN accept,
                                     LPC_SECTION_WRITE *write, LPC_SECTION_READ *read )
{
    FIXME("(%p,%u,%p,%d,%p,%p),stub!\n", handle, id, msg, accept, write, read );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtCompleteConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtCompleteConnectPort( HANDLE handle )
{
    FIXME( "(%p),stub!\n", handle );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtImpersonateClientOfPort (NTDLL.@)
 */
NTSTATUS WINAPI NtImpersonateClientOfPort( HANDLE handle, LPC_MESSAGE *request )
{
    FIXME( "(%p,%p),stub!\n", handle, request );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReadRequestData (NTDLL.@)
 */
NTSTATUS WINAPI NtReadRequestData( HANDLE handle, LPC_MESSAGE *request, ULONG id,
                                   void *buffer, ULONG len, ULONG *retlen )
{
    FIXME( "(%p,%p,%u,%p,%u,%p),stub!\n", handle, request, id, buffer, len, retlen );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtRegisterThreadTerminatePort (NTDLL.@)
 */
NTSTATUS WINAPI NtRegisterThreadTerminatePort( HANDLE handle )
{
    FIXME( "(%p),stub!\n", handle );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtRequestWaitReplyPort (NTDLL.@)
 */
NTSTATUS WINAPI NtRequestWaitReplyPort( HANDLE handle, LPC_MESSAGE *msg_in, LPC_MESSAGE *msg_out )
{
    FIXME( "(%p,%p,%p),stub!\n", handle, msg_in, msg_out );
    if (msg_in)
        TRACE("datasize %u msgsize %u type %u ranges %u client %p/%p msgid %lu size %lu data %s\n",
              msg_in->DataSize, msg_in->MessageSize, msg_in->MessageType, msg_in->VirtualRangesOffset,
              msg_in->ClientId.UniqueProcess, msg_in->ClientId.UniqueThread, msg_in->MessageId,
              msg_in->SectionSize, debugstr_an( (const char *)msg_in->Data, msg_in->DataSize ));
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReplyPort (NTDLL.@)
 */
NTSTATUS WINAPI NtReplyPort( HANDLE handle, LPC_MESSAGE *reply )
{
    FIXME("(%p,%p),stub!\n", handle, reply );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReplyWaitReceivePort (NTDLL.@)
 */
NTSTATUS WINAPI NtReplyWaitReceivePort( HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg )
{
    FIXME("(%p,%p,%p,%p),stub!\n", handle, id, reply, msg );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReplyWaitReceivePortEx (NTDLL.@)
 */
NTSTATUS WINAPI NtReplyWaitReceivePortEx( HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg,
                                          LARGE_INTEGER *timeout )
{
    FIXME("(%p,%p,%p,%p,%p),stub!\n", handle, id, reply, msg, timeout );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtWriteRequestData (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteRequestData( HANDLE handle, LPC_MESSAGE *request, ULONG id,
                                    void *buffer, ULONG len, ULONG *retlen )
{
    FIXME( "(%p,%p,%u,%p,%u,%p),stub!\n", handle, request, id, buffer, len, retlen );
    return STATUS_NOT_IMPLEMENTED;
}

#define MAX_ATOM_LEN  255
#define IS_INTATOM(x) (((ULONG_PTR)(x) >> 16) == 0)

static unsigned int is_integral_atom( const WCHAR *atomstr, ULONG len, RTL_ATOM *ret_atom )
{
    RTL_ATOM atom;

    if ((ULONG_PTR)atomstr >> 16)
    {
        const WCHAR* ptr = atomstr;
        if (!len) return STATUS_OBJECT_NAME_INVALID;

        if (*ptr++ == '#')
        {
            atom = 0;
            while (ptr < atomstr + len && *ptr >= '0' && *ptr <= '9')
            {
                atom = atom * 10 + *ptr++ - '0';
            }
            if (ptr > atomstr + 1 && ptr == atomstr + len) goto done;
        }
        if (len > MAX_ATOM_LEN) return STATUS_INVALID_PARAMETER;
        return STATUS_MORE_ENTRIES;
    }
    else if ((atom = LOWORD( atomstr )) >= MAXINTATOM) return STATUS_INVALID_PARAMETER;
done:
    if (atom >= MAXINTATOM) atom = 0;
    if (!(*ret_atom = atom)) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

static ULONG integral_atom_name( WCHAR *buffer, ULONG len, RTL_ATOM atom )
{
    char tmp[16];
    int ret = snprintf( tmp, sizeof(tmp), "#%u", atom );

    len /= sizeof(WCHAR);
    if (len)
    {
        if (len <= ret) ret = len - 1;
        ascii_to_unicode( buffer, tmp, ret );
        buffer[ret] = 0;
    }
    return ret * sizeof(WCHAR);
}


/***********************************************************************
 *             NtAddAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtAddAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    unsigned int status = is_integral_atom( name, length / sizeof(WCHAR), atom );

    if (status == STATUS_MORE_ENTRIES)
    {
        SERVER_START_REQ( add_atom )
        {
            wine_server_add_data( req, name, length );
            status = wine_server_call( req );
            *atom = reply->atom;
        }
        SERVER_END_REQ;
    }
    TRACE( "%s -> %x\n", debugstr_wn(name, length/sizeof(WCHAR)), status == STATUS_SUCCESS ? *atom : 0 );
    return status;
}


/***********************************************************************
 *             NtDeleteAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtDeleteAtom( RTL_ATOM atom )
{
    unsigned int status;

    if (!atom) status = STATUS_INVALID_HANDLE;
    else if (atom < MAXINTATOM) status = STATUS_SUCCESS;
    else SERVER_START_REQ( delete_atom )
    {
        req->atom = atom;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/***********************************************************************
 *             NtFindAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtFindAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    unsigned int status = is_integral_atom( name, length / sizeof(WCHAR), atom );

    if (status == STATUS_MORE_ENTRIES)
    {
        SERVER_START_REQ( find_atom )
        {
            wine_server_add_data( req, name, length );
            status = wine_server_call( req );
            *atom = reply->atom;
        }
        SERVER_END_REQ;
    }
    TRACE( "%s -> %x\n", debugstr_wn(name, length/sizeof(WCHAR)), status == STATUS_SUCCESS ? *atom : 0 );
    return status;
}


/***********************************************************************
 *             NtQueryInformationAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryInformationAtom( RTL_ATOM atom, ATOM_INFORMATION_CLASS class,
                                        void *ptr, ULONG size, ULONG *retsize )
{
    unsigned int status;

    switch (class)
    {
    case AtomBasicInformation:
    {
        ULONG name_len;
        ATOM_BASIC_INFORMATION *abi = ptr;

        if (size < sizeof(ATOM_BASIC_INFORMATION)) return STATUS_INVALID_PARAMETER;
        name_len = size - sizeof(ATOM_BASIC_INFORMATION);

        if (atom < MAXINTATOM)
        {
            if (atom)
            {
                abi->NameLength = integral_atom_name( abi->Name, name_len, atom );
                status = name_len ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
                abi->ReferenceCount = 1;
                abi->Pinned = 1;
            }
            else status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            SERVER_START_REQ( get_atom_information )
            {
                req->atom = atom;
                if (name_len) wine_server_set_reply( req, abi->Name, name_len );
                status = wine_server_call( req );
                if (status == STATUS_SUCCESS)
                {
                    name_len = wine_server_reply_size( reply );
                    if (name_len)
                    {
                        abi->NameLength = name_len;
                        abi->Name[name_len / sizeof(WCHAR)] = 0;
                    }
                    else
                    {
                        name_len = reply->total;
                        abi->NameLength = name_len;
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    abi->ReferenceCount = reply->count;
                    abi->Pinned = reply->pinned;
                }
                else name_len = 0;
            }
            SERVER_END_REQ;
        }
        TRACE( "%x -> %s (%u)\n", atom, debugstr_wn(abi->Name, abi->NameLength / sizeof(WCHAR)), status );
        if (retsize) *retsize = sizeof(ATOM_BASIC_INFORMATION) + name_len;
        break;
    }

    default:
        FIXME( "Unsupported class %u\n", class );
        status = STATUS_INVALID_INFO_CLASS;
        break;
    }
    return status;
}


union tid_alert_entry
{
#ifdef USE_FUTEX
    LONG futex;
#elif defined(HAVE_KQUEUE)
    int kq;
#else
    HANDLE event;
#endif
};

#define TID_ALERT_BLOCK_SIZE (65536 / sizeof(union tid_alert_entry))
static union tid_alert_entry *tid_alert_blocks[4096];

static unsigned int handle_to_index( HANDLE handle, unsigned int *block_idx )
{
    unsigned int idx = (wine_server_obj_handle(handle) >> 2) - 1;
    *block_idx = idx / TID_ALERT_BLOCK_SIZE;
    return idx % TID_ALERT_BLOCK_SIZE;
}

static BOOL is_alert_tid_valid( HANDLE tid )
{
    unsigned int block_idx;

    handle_to_index( tid, &block_idx );
    return block_idx <= ARRAY_SIZE(tid_alert_blocks);
}

static union tid_alert_entry *get_tid_alert_entry( HANDLE tid )
{
    unsigned int block_idx, idx = handle_to_index( tid, &block_idx );
    union tid_alert_entry *entry;

    if (block_idx > ARRAY_SIZE(tid_alert_blocks))
    {
        FIXME( "tid %p is too high\n", tid );
        return NULL;
    }

    if (!tid_alert_blocks[block_idx])
    {
        static const size_t size = TID_ALERT_BLOCK_SIZE * sizeof(union tid_alert_entry);
        void *ptr = anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
        if (ptr == MAP_FAILED) return NULL;
        if (InterlockedCompareExchangePointer( (void **)&tid_alert_blocks[block_idx], ptr, NULL ))
            munmap( ptr, size ); /* someone beat us to it */
    }

    entry = &tid_alert_blocks[block_idx][idx % TID_ALERT_BLOCK_SIZE];

#ifdef USE_FUTEX
    return entry;
#elif defined(HAVE_KQUEUE)
    if (!entry->kq)
    {
        int kq = kqueue();
        static const struct kevent init_event =
        {
            .ident = 1,
            .filter = EVFILT_USER,
            .flags = EV_ADD | EV_CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = NULL
        };

        if (kq == -1)
        {
            ERR( "kqueue failed with error: %d (%s)\n", errno, strerror( errno ) );
            return NULL;
        }

        if (kevent( kq, &init_event, 1, NULL, 0, NULL) == -1)
        {
            ERR( "kevent creation failed with error: %d (%s)\n", errno, strerror( errno ) );
            close( kq );
            return NULL;
        }

        if (InterlockedCompareExchange( (LONG *)&entry->kq, kq, 0 ))
            close( kq );
    }
#else
    if (!entry->event)
    {
        HANDLE event;

        if (NtCreateEvent( &event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ))
            return NULL;
        if (InterlockedCompareExchangePointer( &entry->event, event, NULL ))
            NtClose( event );
    }
#endif

    return entry;
}


/***********************************************************************
 *             NtAlertMultipleThreadByThreadId (NTDLL.@)
 */
NTSTATUS WINAPI NtAlertMultipleThreadByThreadId( HANDLE *tids, ULONG count, void *unk1, void *unk2 )
{
    unsigned int i;

    TRACE( "%p %d %p %p\n", tids, (int)count, unk1, unk2 );

    if (unk1 || unk2) FIXME( "unk1 %p, unk2 %p.\n", unk1, unk2 );
    for (i = 0; i < count; ++i)
    {
        if (!is_alert_tid_valid( tids[i] )) return STATUS_INVALID_CID;
    }
    for (i = 0; i < count; ++i) NtAlertThreadByThreadId( tids[i] );
    return STATUS_SUCCESS;
}


/* iOS-Madeira ml400 (task #60): last-64 (from-tid, target-tid) alert pairs.
 * ml400 caught a thread storming instant-ALERTED on INFINITE waits (webhelper
 * 00c8) while other threads slept through their wakes — the recycled-tid
 * theory says a stale threadpool/waiter list in another pseudo-process keeps
 * alerting a dead thread's tid that now belongs to an innocent bystander.
 * The ring is written lock-free on every alert; the storming WAITER dumps it,
 * which names the pounder. */
#define IOS_ALERT_RING 64
static unsigned int ios_alert_ring[IOS_ALERT_RING];
static LONG ios_alert_ring_pos;
static HANDLE ios_pump_alert_tid;   /* ml407: beacon thread's tid, set on its wait */

/* ml439 (#74): periodic alert-flow dump, called from the monitor thread.
 * The ml438 stall shows dozens of threads parked in NtWaitForAlertByThreadId
 * with their alert futexes ALL reading 0 — the wakes were never delivered.
 * Discriminator: if the send-side ring goes STATIC during the stall (pos not
 * advancing) while waiters accumulate, RtlWakeAddress* is not finding the
 * waiters at all — the PE-side addr_waiters table is split across ntdll
 * copies (per-copy .data, the pseudo-process globals family) and the wake
 * dies before reaching the unix layer. If the ring KEEPS advancing, delivery
 * or tid-resolution is at fault instead. */
void ios_alert_ring_dump(void)
{
    static LONG last_pos = -1;
    LONG pos = ios_alert_ring_pos;
    dprintf( 2, "[alert-ring] pos=%d (%+d since last) last8:"
             " %04x->%04x %04x->%04x %04x->%04x %04x->%04x"
             " %04x->%04x %04x->%04x %04x->%04x %04x->%04x rev=ml439\n",
             (int)pos, (int)(last_pos < 0 ? 0 : pos - last_pos),
             ios_alert_ring[(pos-0)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-0)&(IOS_ALERT_RING-1)] & 0xffff,
             ios_alert_ring[(pos-1)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-1)&(IOS_ALERT_RING-1)] & 0xffff,
             ios_alert_ring[(pos-2)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-2)&(IOS_ALERT_RING-1)] & 0xffff,
             ios_alert_ring[(pos-3)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-3)&(IOS_ALERT_RING-1)] & 0xffff,
             ios_alert_ring[(pos-4)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-4)&(IOS_ALERT_RING-1)] & 0xffff,
             ios_alert_ring[(pos-5)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-5)&(IOS_ALERT_RING-1)] & 0xffff,
             ios_alert_ring[(pos-6)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-6)&(IOS_ALERT_RING-1)] & 0xffff,
             ios_alert_ring[(pos-7)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-7)&(IOS_ALERT_RING-1)] & 0xffff );
    last_pos = pos;
}

/* ml441 (#74): THE FIX for the lost-wake stall.  PE ntdll's RtlWaitOnAddress/
 * RtlWakeAddress* (which back SRW locks and condition variables too) keep
 * their waiter lists in `futex_queues[256]` — a static array in each ntdll
 * COPY's .data.  Our pseudo-processes carry multiple ntdll copies (native +
 * EC per pseudo-proc), so a waker walking copy B's array never finds a waiter
 * registered in copy A: the wake dies PE-side, the futex stays 0, the waiter
 * parks forever (ml440: every >60s parker was an addr=NULL RtlWaitOnAddress
 * park).  Fix: ONE table in the unix dylib's .data — single copy per real
 * process by construction — published to every PE copy via a private
 * NtQuerySystemInformation class (0xf00d, system.c).  Layout mirrors PE
 * struct futex_queue { struct list queue; LONG lock; } == 24 bytes; sharing
 * across pseudo-procs is semantically correct because they share one address
 * space (same VA == same memory). */
struct ios_shared_futex_queue
{
    void *next, *prev;
    LONG lock;
};
static struct ios_shared_futex_queue ios_shared_futex_queues[256];
static const char ios_futex_shared_marker[] __attribute__((used)) = "ios-futex-shared rev=ml441";
void *ios_get_shared_futex_queues(void)
{
    return ios_shared_futex_queues;
}

/* ml445 (#74): DEAD-HOLDER REAPER.  Steam's watchdog TerminateThread()s
 * threads at arbitrary points ([thr-term] CROSS-TERM, ml444) — a victim
 * holding FEX's WritePriorityMutex shared (TEB Instrumentation[7]=depth,
 * [8]=&Futex, stamped by the fork's NoteReadAcquired) leaks the hold and the
 * whole JIT machinery cascades to a standstill behind it (#74's stall family).
 * The monitor census spots dead ports whose TEB stamp is still set; when NO
 * live thread shares that TEB (recycling guard — stamps belong to the live
 * generation when one exists), repair the lock word directly and deliver the
 * writer/reader wakes through the ml441 SHARED futex table (single table =
 * unix side can wake PE waiters).  WPM layout (WritePriorityMutex.h):
 * bit31 write-owned, bit30 read-waiter, 29:16 write-waiters, 15:0 read-owners;
 * writers wait on &Futex, readers on &Futex+2. */
static void ios_shared_futex_wake( const void *addr, int all )
{
    struct ios_q { void *next, *prev; LONG lock; } *q;
    struct ios_e { void *next, *prev; const void *addr; unsigned int tid; } *e;
    void *head, *cur;
    unsigned int tids[64];
    int n = 0, i;
    q = (struct ios_q *)&ios_shared_futex_queues[(((ULONG_PTR)addr) >> 4) % 256];
    while (InterlockedCompareExchange( &q->lock, -1, 0 )) YieldProcessor();
    head = (void *)q;
    if (q->next)
    {
        for (cur = q->next; cur != head && n < 64; )
        {
            e = (struct ios_e *)cur;
            cur = e->next;
            if (e->addr == addr)
            {
                tids[n++] = e->tid;
                if (!all) break;
            }
        }
    }
    InterlockedExchange( &q->lock, 0 );
    for (i = 0; i < n; i++)
        NtAlertThreadByThreadId( (HANDLE)(ULONG_PTR)tids[i] );
}

/* ml1000: bounded copy-out of guest memory; defined with the crash story at
 * ios_alert_waiter_dump below. msync() only answers "is it mapped", so it let a
 * PROT_NONE page through and the load took a BUS on a thread with no TEB. */
static int ios_safe_read( ULONG_PTR addr, void *buf, size_t len );

void ios_wpm_reap_shared( unsigned long long mutex_addr, unsigned int depth, unsigned long long dead_teb )
{
    volatile LONG *futex = (volatile LONG *)(ULONG_PTR)mutex_addr;
    LONG old, desired;
    unsigned int owners;
    LONG probe;
    if (!mutex_addr || (mutex_addr & 3) || mutex_addr >= 0x8000000000ULL) return;
    /* ml1000: the reap itself has to be a real atomic RMW on the guest word, so
     * it cannot go through mach_vm_read_overwrite -- but the common failure is
     * a lock whose page is already gone, and this catches that without a fault.
     * The residual window (reprotected between probe and CAS) is inherent to
     * writing another process's lock and is bounded by the orphan detector's
     * three-strike verdict, which is what earns the write in the first place. */
    if (!ios_safe_read( (ULONG_PTR)mutex_addr, &probe, sizeof(probe) )) return;
    do
    {
        old = *futex;
        owners = (unsigned int)old & 0xffff;
        if (!owners) { depth = 0; break; }
        if (depth > owners) depth = owners;
        desired = old - (LONG)depth;
    } while (InterlockedCompareExchange( (LONG *)futex, desired, old ) != old);
    if (!depth) return;
    dprintf( 2, "[lock-reap] WPM %#llx dead_teb=%#llx released %u shared (word %08x -> %08x) rev=ml445\n",
             mutex_addr, dead_teb, depth, (unsigned int)old, (unsigned int)desired );
    /* mirrors unlock_shared: last reader out with writers queued wakes ONE
     * writer (they wait on the full word at +0); if no writers but the
     * read-waiter bit is set, wake the readers at +2 */
    if ((desired & 0xffff) == 0)
    {
        if (desired & 0x3fff0000) ios_shared_futex_wake( (const void *)(ULONG_PTR)mutex_addr, 0 );
        else if (desired & 0x40000000) ios_shared_futex_wake( (const void *)(ULONG_PTR)(mutex_addr + 2), 1 );
    }
}

/* ml446 (#74): reap a DEAD EXCLUSIVE owner of a wine-SRW-backed std::mutex
 * (FEX's CodeBufferWriteMutex, stamped in TEB Instrumentation[6] while held —
 * JIT.cpp).  Mirrors RtlReleaseSRWLockExclusive: owners=0, clear held bit;
 * wake one exclusive waiter at lock+2 if any remain, else wake-all at lock.
 * srw_lock layout: {short exclusive_waiters (bit0=held); ushort owners}. */
void ios_srw_reap_exclusive( unsigned long long lock_addr, unsigned long long dead_teb )
{
    volatile LONG *word = (volatile LONG *)(ULONG_PTR)lock_addr;
    LONG old, desired;
    unsigned int excl;
    LONG probe;
    if (!lock_addr || (lock_addr & 3) || lock_addr >= 0x8000000000ULL) return;
    /* ml1000: same probe-before-RMW as ios_wpm_reap_shared; see the note there. */
    if (!ios_safe_read( (ULONG_PTR)lock_addr, &probe, sizeof(probe) )) return;
    do
    {
        old = *word;
        excl = (unsigned int)old & 0xffff;
        if (!(excl & 1)) return;   /* not exclusively held — nothing to reap */
        desired = (LONG)(excl & ~1u);   /* owners := 0, held bit cleared, waiters kept */
    } while (InterlockedCompareExchange( (LONG *)word, desired, old ) != old);
    dprintf( 2, "[lock-reap] SRW %#llx dead_teb=%#llx released exclusive (word %08x -> %08x) rev=ml446\n",
             lock_addr, dead_teb, (unsigned int)old, (unsigned int)desired );
    if (desired & 0xffff)
        ios_shared_futex_wake( (const void *)(ULONG_PTR)(lock_addr + 2), 0 );
    else
        ios_shared_futex_wake( (const void *)(ULONG_PTR)lock_addr, 1 );
}

/* ml440 (#74): waiter-address registry — name the lock everyone is parked on.
 * ml439 proved the parked crowd receives ZERO alerts while a device-poll trio
 * monopolizes the ring, so the wakes are never SENT for them.  Both surviving
 * theories (dead SRW-lock holder vs per-ntdll-copy addr_waiters split) are
 * discriminated by the WAIT ADDRESS: RtlWaitOnAddress passes the lock word's
 * address as the cookie here.  Record it per parked thread; the monitor dumps
 * every >60s parker with the word at its address.  Decode offline:
 *   wine srw_lock = { short exclusive_waiters; ushort owners }
 *   FEX WritePriorityMutex = bit31 write-owned, bit30 read-waiter,
 *                            29:16 write-waiters, 15:0 read-owners
 * Many threads on ONE address = one poisoned lock; owners!=0 with no live
 * owner thread = dead holder confirmed. */
#define IOS_ALERT_WAITER_MAX 512
static struct
{
    void *tid;          /* slot owner; sticky across waits (lock-free claim) */
    const void *addr;   /* wait-on-address cookie; NULL = not currently parked */
    ULONGLONG since;    /* NtQuerySystemTime at park entry */
    int inf;            /* 1 = INFINITE wait */
} ios_alert_waiters[IOS_ALERT_WAITER_MAX];

static int ios_alert_waiter_slot( void *tid )
{
    int i, free_i;
    for (;;)
    {
        free_i = -1;
        for (i = 0; i < IOS_ALERT_WAITER_MAX; i++)
        {
            if (ios_alert_waiters[i].tid == tid) return i;
            if (free_i < 0 && !ios_alert_waiters[i].tid) free_i = i;
        }
        if (free_i < 0) return -1;
        if (!InterlockedCompareExchangePointer( &ios_alert_waiters[free_i].tid, tid, NULL ))
            return free_i;
        /* lost the race for free_i to another thread; rescan */
    }
}

/* ml443: x-ref for [census-hold] — return a thread's CURRENT alert-wait
 * registration even when younger than the 60s dump bar (ml442 showed the
 * stuck CodeInvalidationMutex holder cycling wake→recheck→re-park, so its
 * age never accumulates; the address is the discriminator we need). */
int ios_alert_waiter_lookup( unsigned int tid, const void **addr, int *age_s, int *inf )
{
    LARGE_INTEGER now;
    int i;
    for (i = 0; i < IOS_ALERT_WAITER_MAX; i++)
    {
        if (((unsigned int)(ULONG_PTR)ios_alert_waiters[i].tid & 0xffff) == (tid & 0xffff) &&
            ios_alert_waiters[i].addr)
        {
            NtQuerySystemTime( &now );
            *addr = ios_alert_waiters[i].addr;
            *age_s = (int)((now.QuadPart - (LONGLONG)ios_alert_waiters[i].since) / 10000000);
            *inf = ios_alert_waiters[i].inf;
            return 1;
        }
    }
    return 0;
}

/* iOS-Madeira ml1000: msync() IS NOT A READABILITY TEST, AND THIS IS WHERE THAT
 * KILLED A SESSION.
 *
 * ml441/ml442 guarded every probe below with
 * `if (!msync( page, 0x4000, MS_ASYNC ))' on the theory that Darwin returns
 * ENOMEM for an unmapped page, so a success meant the page could be read.  It
 * does not mean that.  msync answers a question about the MAPPING; it says
 * nothing about the PROTECTION, so a region that is mapped PROT_NONE -- which
 * is exactly what a guest DLL being unloaded or reprotected looks like for the
 * moment it takes -- passes the guard and then faults on the load.
 *
 * Device log w1.txt, line ~38948, after a long healthy session:
 *
 *   bus_handler BUS #1: pc=0x102fd0208 addr=0x7177558688 x18=0x0
 *                       insn=0xb8404528 (ldr w8,[x9],#4)
 *   sym pc=Madeira`ios_alert_waiter_dump+0x3d4
 *   bt[0] Madeira`ios_pump_sample+0x4c
 *   bt[1] Madeira`ios_pool_warmer_thread+0x6e4
 *   [bus-rgn] region=0x71774f0000+0xd8000 prot=0 max=7
 *   [bus-rgn] VERDICT <== ANONYMOUS, NEVER RESIDENT
 *
 * `prot=0' is the whole story: mapped, so msync said yes; unreadable, so the
 * load took a BUS.  The post-indexed `ldr w8,[x9],#4' is this function's own
 * w0/w1 pair -- the compiler folded `*(al)' and the `al + 4' address into one
 * post-increment -- and the thread is the pool warmer, which has no TEB, so
 * the fault could not be adopted and the process died.
 *
 * Every probe here now goes through mach_vm_read_overwrite into a local.  The
 * kernel does the permission check for us and reports failure as a return
 * value instead of a signal, which is the only form of "is this readable"
 * that is not a race against the guest in the first place: even a correct
 * protection test would be stale by the next instruction, and this one cannot
 * be, because the test IS the read. */
static int ios_safe_read( ULONG_PTR addr, void *buf, size_t len )
{
#ifdef __APPLE__
    mach_vm_size_t got = 0;
    if (!addr) return 0;
    return mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)addr, len,
                                   (mach_vm_address_t)buf, &got ) == KERN_SUCCESS && got == len;
#else
    if (!addr) return 0;
    memcpy( buf, (const void *)addr, len );
    return 1;
#endif
}

void ios_alert_waiter_dump(void)
{
    LARGE_INTEGER now;
    int i, parked = 0, over = 0, shown = 0;
    NtQuerySystemTime( &now );
    for (i = 0; i < IOS_ALERT_WAITER_MAX; i++)
    {
        if (!ios_alert_waiters[i].addr) continue;
        parked++;
        if ((now.QuadPart - (LONGLONG)ios_alert_waiters[i].since) / 10000000 >= 60) over++;
    }
    dprintf( 2, "[waiters] parked=%d over60s=%d rev=ml444\n", parked, over );

    /* ml444: an address with >=3 concurrent waiters is a contended lock whose
     * owning OBJECT we can't name offline (ml443: S=0x7c530f0098, 13 SRW-style
     * exclusive waiters, neighbor allocation of a GuestToHostMap).  Dump the
     * 0x140 bytes around it once per cycle — vtables/pointers inside identify
     * the object type offline. */
    {
        static int hot_dumps;
        const void *done[2] = { NULL, NULL };
        int d = 0;
        for (i = 0; i < IOS_ALERT_WAITER_MAX && d < 2 && hot_dumps < 12; i++)
        {
            const void *a = ios_alert_waiters[i].addr;
            int j, nsame = 0;
            if (!a || (ULONG_PTR)a <= 0x10000 || a == done[0] || a == done[1]) continue;
            for (j = 0; j < IOS_ALERT_WAITER_MAX; j++)
                if (ios_alert_waiters[j].addr == a) nsame++;
            if (nsame < 3) continue;
            done[d++] = a;
            hot_dumps++;
            {
                ULONG_PTR base = ((ULONG_PTR)a & ~0xfULL) - 0x100;
                int line;
                dprintf( 2, "[hot-lock] addr=%p waiters=%d dumping [%p,%p) rev=ml444\n",
                         a, nsame, (void *)base, (void *)(base + 0x140) );
                for (line = 0; line < 5; line++)
                {
                    ULONG_PTR row = base + line * 0x40;
                    unsigned long long w[8] = { 0 };
                    /* ml1000: one bounded copy-out replaces the msync pair AND
                     * the memcpy.  A row that straddles into an unreadable page
                     * simply does not print, which is what the old two-page
                     * msync was reaching for and did not achieve. */
                    if (!ios_safe_read( row, w, sizeof(w) )) continue;
                    dprintf( 2, "[hot-lock]  %p: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                             (void *)row, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7] );
                }
            }
        }
    }
    for (i = 0; i < IOS_ALERT_WAITER_MAX && shown < 32; i++)
    {
        const void *a = ios_alert_waiters[i].addr;
        void *tid = ios_alert_waiters[i].tid;
        LONGLONG age;
        unsigned int w0 = 0xdeaddead, w1 = 0xdeaddead;
        if (!a) continue;
        age = (now.QuadPart - (LONGLONG)ios_alert_waiters[i].since) / 10000000;
        if (age < 60) continue;
        shown++;
        /* Probe the lock word.  ml442: read the CONTAINING aligned word — SRW
         * and FEX WritePriorityMutex read-waits pass lock+2 (2-aligned), which
         * the old 4-aligned-only guard refused (ml441's deaddead trio).
         * ml1000: and read it OUT of the guest rather than through a pointer —
         * this pair of loads is what took the BUS in w1.txt.  w0/w1 keep their
         * 0xdeaddead poison when the read fails, which is the existing "could
         * not be read" spelling in this log line, so nothing downstream had to
         * learn a new one. */
        if (!((ULONG_PTR)a & 1) && (ULONG_PTR)a > 0x10000 && (ULONG_PTR)a < 0x8000000000ULL)
        {
            ULONG_PTR al = (ULONG_PTR)a & ~3ULL;
            unsigned int pair[2];
            if (ios_safe_read( al, pair, sizeof(pair) ))
            {
                w0 = pair[0];
                w1 = pair[1];
            }
            else if (ios_safe_read( al, &w0, sizeof(w0) ))
            {
                /* the second word is on a page we cannot read; the first is
                 * the one the verdict is made from */
            }
        }
        dprintf( 2, "[waiters]  tid=%04x addr=%p age=%ds %s w0=%08x w1=%08x\n",
                 (int)(ULONG_PTR)tid, a, (int)age,
                 ios_alert_waiters[i].inf ? "INF" : "TMO", w0, w1 );
    }
}

/* ml447 (#74): ORPHAN-LOCK detector.  ml446 proved the dead S-owner vanishes
 * entirely (registry row + TEB recycled) before the census can see the corpse
 * — so detect the ORPHANED LOCK instead of the dead owner: an SRW-backed
 * std::mutex that is (a) held-exclusive, (b) has >=3 parked exclusive waiters
 * (2-misaligned wait addrs = lock+2), and (c) is stamped by NO LIVE thread's
 * TEB Instrumentation[6] (every acquire stamps since ml446), for 3 consecutive
 * monitor cycles, has a dead owner with certainty — reap it.  The live-stamp
 * set is built by the monitor (registry + Mach liveness) and passed in. */
void ios_orphan_check( const unsigned long long *live_stamps, int nstamps )
{
    static struct { unsigned long long lock; int strikes; } susp[8];
    int i, j, k;
    for (i = 0; i < IOS_ALERT_WAITER_MAX; i++)
    {
        const void *a = ios_alert_waiters[i].addr;
        unsigned long long lock;
        unsigned int word;
        int nsame = 0, stamped = 0;
        if (!a || ((ULONG_PTR)a & 3) != 2 || (ULONG_PTR)a < 0x10000 || (ULONG_PTR)a >= 0x8000000000ULL) continue;
        lock = (unsigned long long)(ULONG_PTR)a - 2;
        for (j = 0; j < IOS_ALERT_WAITER_MAX; j++)
            if (ios_alert_waiters[j].addr == a) nsame++;
        if (nsame < 3) continue;
        /* ml1000: same msync-is-not-a-readability-test fix as
         * ios_alert_waiter_dump.  A lock word we cannot read cannot be judged,
         * so skip the candidate exactly as the old unmapped case did. */
        if (!ios_safe_read( (ULONG_PTR)lock, &word, sizeof(word) )) continue;
        if (!(word & 1))
        {
            /* released legitimately — clear any stale suspicion */
            for (j = 0; j < 8; j++)
                if (susp[j].lock == lock) { susp[j].lock = 0; susp[j].strikes = 0; }
            continue;
        }
        /* ml468: the word must be a COHERENT exclusively-held wine SRW before
         * we may reap it as one.  RtlAcquireSRWLockExclusive sets owners
         * (high 16) to exactly 1 and bit0 of exclusive_waiters; parked
         * exclusive waiters occupy bits 15:1 in steps of 2, so >=3 parked
         * threads imply a non-empty queue.  The ml467 run reaped 0x40010001
         * here — not an SRW at all but a live shared-owned FEX
         * WritePriorityMutex (read-owners=1, write-waiter=1; its read-waiters
         * park at lock+2 too, the lock-ID-rule trap) held by a running sweep
         * thread; zeroing it killed the run within a second. */
        if ((word >> 16) != 1 || ((word & 0xffff) >> 1) == 0)
        {
            static int incoherent_logs;
            if (incoherent_logs < 8)
            {
                incoherent_logs++;
                dprintf( 2, "[lock-orphan] SKIP %#llx word=%08x waiters=%d incoherent-as-SRW (FEX lock?) rev=ml468\n",
                         lock, word, nsame );
            }
            for (j = 0; j < 8; j++)
                if (susp[j].lock == lock) { susp[j].lock = 0; susp[j].strikes = 0; }
            continue;
        }
        for (k = 0; k < nstamps; k++) if (live_stamps[k] == lock) stamped = 1;
        for (j = 0; j < 8; j++) if (susp[j].lock == lock) break;
        if (stamped)
        {
            if (j < 8) { susp[j].lock = 0; susp[j].strikes = 0; }
            continue;
        }
        if (j == 8)   /* new suspect: claim a free slot */
        {
            for (j = 0; j < 8 && susp[j].lock; j++) ;
            if (j == 8) continue;
            susp[j].lock = lock;
            susp[j].strikes = 0;
        }
        susp[j].strikes++;
        dprintf( 2, "[lock-orphan] SRW %#llx word=%08x waiters=%d no-live-stamp strike=%d/3 rev=ml447\n",
                 lock, word, nsame, susp[j].strikes );
        if (susp[j].strikes >= 3)
        {
            ios_srw_reap_exclusive( lock, 0xDEADull );
            susp[j].lock = 0;
            susp[j].strikes = 0;
        }
    }
}


/***********************************************************************
 *             NtAlertThreadByThreadId (NTDLL.@)
 */
NTSTATUS WINAPI NtAlertThreadByThreadId( HANDLE tid )
{
    union tid_alert_entry *entry = get_tid_alert_entry( tid );

    TRACE( "%p\n", tid );
    /* ml950: counted for [srv-stats].  USE_FUTEX is defined for __APPLE__ at
     * the top of this file, so this path never touches the wineserver — the
     * [alert-storm] ping-pong is an os_sync_wake_by_address pair, not IPC. */
    ios_srv_nt_count( IOS_NT_ALERT_WAKE );

    if (!entry) return STATUS_INVALID_CID;

#ifdef USE_FUTEX
    {
        LONG *futex = &entry->futex;
        /* iOS-Madeira ml482 (#86): NtAlertThreadByThreadId itself needs no TEB —
         * it wakes a TARGET tid — but the two probes below read
         * NtCurrentTeb()->ClientId.UniqueThread, i.e. TEB+0x48. Threads created
         * directly by CEF/FEX have no TEB, so on those the probe (not the
         * function) null-dereferenced and killed the app at exactly the moment
         * the login-window popup brought new threads into this path (ml481:
         * [host-fault] sig=11 addr=0x48 at NtAlertThreadByThreadId+0x10c, the
         * last line of the log). Read the tid defensively; 0 means "unknown
         * sender", which is all the diagnostics ever needed. */
        TEB *self_teb = NtCurrentTeb();
        unsigned int self_tid = self_teb ? (unsigned int)(ULONG_PTR)self_teb->ClientId.UniqueThread : 0;
        /* iOS-Madeira ml400 (task #60): ring of recent alerts so a storming
         * waiter can name its pounder — see [alert-storm] in
         * NtWaitForAlertByThreadId. */
        LONG pos = InterlockedIncrement( &ios_alert_ring_pos );
        ios_alert_ring[pos & (IOS_ALERT_RING - 1)] =
            (self_tid << 16) | ((unsigned int)(ULONG_PTR)tid & 0xffff);
        /* ml407: did ANYONE (any ntdll copy) ever try to wake the parked pump? */
        if (tid && tid == ios_pump_alert_tid)
        {
            static LONG n;
            if (n < 40) { InterlockedIncrement( &n );
                ERR( "[alert-unix] ALERT-SENT from=%04x -> pump tid=%04x futex=%p rev=ml482\n",
                     (int)self_tid, (int)(ULONG_PTR)tid, entry ); }
        }
        if (!InterlockedExchange( futex, 1 ))
            futex_wake_one( futex );
        return STATUS_SUCCESS;
    }
#elif defined(HAVE_KQUEUE)
    {
        static const struct kevent signal_event =
        {
            .ident = 1,
            .filter = EVFILT_USER,
            .flags = 0,
            .fflags = NOTE_TRIGGER,
            .data = 0,
            .udata = NULL
        };
        kevent( entry->kq, &signal_event, 1, NULL, 0, NULL );
        return STATUS_SUCCESS;
    }
#else
    return NtSetEvent( entry->event, NULL );
#endif
}


#if defined(USE_FUTEX) || defined(HAVE_KQUEUE)
static LONGLONG get_absolute_timeout( const LARGE_INTEGER *timeout )
{
    LARGE_INTEGER now;

    if (timeout->QuadPart >= 0) return timeout->QuadPart;
    NtQuerySystemTime( &now );
    return now.QuadPart - timeout->QuadPart;
}

static LONGLONG update_timeout( ULONGLONG end )
{
    LARGE_INTEGER now;
    LONGLONG timeleft;

    NtQuerySystemTime( &now );
    timeleft = end - now.QuadPart;
    if (timeleft < 0) timeleft = 0;
    return timeleft;
}
#endif


/***********************************************************************
 *             NtWaitForAlertByThreadId (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForAlertByThreadId( const void *address, const LARGE_INTEGER *timeout )
{
    union tid_alert_entry *entry = get_tid_alert_entry( NtCurrentTeb()->ClientId.UniqueThread );
    /* iOS-Madeira ml406 (task #60): unix-side tap for beacon-marked threads
     * (TEB->Instrumentation[10] == 'PUMP', stamped by the EC chrome-ipc
     * wrappers).  The pump entered an alert-wait post-wake WITHOUT hitting
     * the EC-side [pump-op] wrapper — native-aarch64-ntdll routes bypass it,
     * but every PE route lands here.  Logs which alert-waits the marked
     * threads actually make, with the futex entry address (maps to a tid
     * offline: ((addr & 0xffff) / 4 + 1) * 4). */
    int ios_marked = (NtCurrentTeb()->Instrumentation[10] == (void *)(ULONG_PTR)0x504d5550);
    static LONG ios_alert_unix_n;

    /* ml407: remember the marked thread's tid so the ALERT side (which runs on
     * OTHER threads, possibly against a different PE ntdll copy) can report
     * whether anyone ever tries to wake it — the unix lib is the single shared
     * copy every route passes through. */
    if (ios_marked) ios_pump_alert_tid = NtCurrentTeb()->ClientId.UniqueThread;
    ios_srv_nt_count( IOS_NT_ALERT_WAIT );   /* ml950: futex path, no server */

    TRACE( "%p %s\n", address, debugstr_timeout( timeout ) );

    if (!entry) return STATUS_INVALID_CID;

    if (ios_marked && ios_alert_unix_n < 120)
    {
        InterlockedIncrement( &ios_alert_unix_n );
        ERR( "[alert-unix] tid=%04x WAIT addr=%p timeout=%s futex=%p\n",
             (int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread, address,
             timeout ? wine_dbgstr_longlong( timeout->QuadPart ) : "INF", (void *)entry );
    }

#ifdef USE_FUTEX
    {
        LONG *futex = &entry->futex;
        ULONGLONG end;
        int ret;
        int ios_wslot;

        if (timeout)
        {
            if (timeout->QuadPart == TIMEOUT_INFINITE)
                timeout = NULL;
            else
                end = get_absolute_timeout( timeout );
        }

        /* ml440 (#74): register this park; addr NULL uses sentinel 0x1 so the
         * park still counts.  Registered after INFINITE normalization so inf
         * is accurate. */
        ios_wslot = ios_alert_waiter_slot( NtCurrentTeb()->ClientId.UniqueThread );
        if (ios_wslot >= 0)
        {
            LARGE_INTEGER ios_wnow;
            NtQuerySystemTime( &ios_wnow );
            ios_alert_waiters[ios_wslot].since = ios_wnow.QuadPart;
            ios_alert_waiters[ios_wslot].inf = !timeout;
            ios_alert_waiters[ios_wslot].addr = address ? address : (const void *)0x1;
        }

        while (!InterlockedExchange( futex, 0 ))
        {
            if (timeout)
            {
                LONGLONG timeleft = update_timeout( end );
                struct timespec timespec;

                timespec.tv_sec = timeleft / (ULONGLONG)TICKSPERSEC;
                timespec.tv_nsec = (timeleft % TICKSPERSEC) * 100;
                ret = futex_wait( futex, 0, &timespec );
            }
            else
                ret = futex_wait( futex, 0, NULL );

            if (ret == -1 && errno == ETIMEDOUT)
            {
                if (ios_wslot >= 0) ios_alert_waiters[ios_wslot].addr = NULL;
                if (ios_marked && ios_alert_unix_n < 120) { InterlockedIncrement( &ios_alert_unix_n );
                    ERR( "[alert-unix] tid=%04x -> TIMEOUT\n",
                         (int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread ); }
                return STATUS_TIMEOUT;
            }
        }
        if (ios_wslot >= 0) ios_alert_waiters[ios_wslot].addr = NULL;
        if (ios_marked && ios_alert_unix_n < 120) { InterlockedIncrement( &ios_alert_unix_n );
            ERR( "[alert-unix] tid=%04x -> ALERTED\n",
                 (int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread ); }
        /* iOS-Madeira ml400 (task #60): detect an alert STORM — one thread
         * getting instant-ALERTED over and over (ml400: webhelper 00c8, 40+
         * consecutive on INFINITE waits).  Every 16th consecutive hit, dump
         * the last 16 alert-ring pairs; the from-tids name the pounder.
         * Recycled-tid theory: a stale waiter list in another pseudo-process
         * keeps alerting a dead thread's tid now owned by this victim. */
        {
            static int storm_n, dump_n;
            static void *storm_tid;
            void *cur = NtCurrentTeb()->ClientId.UniqueThread;
            if (cur == storm_tid) storm_n++;
            else { storm_tid = cur; storm_n = 1; }
            if (storm_n >= 16 && (storm_n & 15) == 0 && dump_n < 20)
            {
                LONG pos = ios_alert_ring_pos;
                int i;
                dump_n++;
                ERR( "[alert-storm] tid=%04x consecutive=%d ring(from->to):"
                     " %04x->%04x %04x->%04x %04x->%04x %04x->%04x"
                     " %04x->%04x %04x->%04x %04x->%04x %04x->%04x\n",
                     (int)(ULONG_PTR)cur, storm_n,
                     ios_alert_ring[(pos-0)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-0)&(IOS_ALERT_RING-1)] & 0xffff,
                     ios_alert_ring[(pos-1)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-1)&(IOS_ALERT_RING-1)] & 0xffff,
                     ios_alert_ring[(pos-2)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-2)&(IOS_ALERT_RING-1)] & 0xffff,
                     ios_alert_ring[(pos-3)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-3)&(IOS_ALERT_RING-1)] & 0xffff,
                     ios_alert_ring[(pos-4)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-4)&(IOS_ALERT_RING-1)] & 0xffff,
                     ios_alert_ring[(pos-5)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-5)&(IOS_ALERT_RING-1)] & 0xffff,
                     ios_alert_ring[(pos-6)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-6)&(IOS_ALERT_RING-1)] & 0xffff,
                     ios_alert_ring[(pos-7)&(IOS_ALERT_RING-1)] >> 16, ios_alert_ring[(pos-7)&(IOS_ALERT_RING-1)] & 0xffff );
            }
        }
        return STATUS_ALERTED;
    }
#elif defined(HAVE_KQUEUE)
    {
        ULONGLONG end;
        int ret;
        struct timespec timespec;
        struct kevent wait_event;

        if (timeout)
        {
            if (timeout->QuadPart == TIMEOUT_INFINITE)
                timeout = NULL;
            else
                end = get_absolute_timeout( timeout );
        }

        do
        {
            if (timeout)
            {
                LONGLONG timeleft = update_timeout( end );

                timespec.tv_sec = timeleft / (ULONGLONG)TICKSPERSEC;
                timespec.tv_nsec = (timeleft % TICKSPERSEC) * 100;
                if (timespec.tv_sec > 0x7FFFFFFF) timeout = NULL;
            }

            ret = kevent( entry->kq, NULL, 0, &wait_event, 1, timeout ? &timespec : NULL );
        } while (ret == -1 && errno == EINTR);

        switch (ret)
        {
        case 1:
            return STATUS_ALERTED;
        case 0:
            return STATUS_TIMEOUT;
        default:
            ERR( "kevent failed with error: %d (%s)\n", errno, strerror( errno ) );
            return STATUS_INVALID_HANDLE;
        }
    }
#else
    {
        NTSTATUS status = NtWaitForSingleObject( entry->event, FALSE, timeout );
        if (!status) return STATUS_ALERTED;
        return status;
    }
#endif
}


/***********************************************************************
 *           NtCreateTransaction (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateTransaction( HANDLE *handle, ACCESS_MASK mask, OBJECT_ATTRIBUTES *obj_attr, GUID *guid, HANDLE tm,
        ULONG options, ULONG isol_level, ULONG isol_flags, PLARGE_INTEGER timeout, UNICODE_STRING *description )
{
    FIXME( "%p, %#x, %p, %s, %p, 0x%08x, 0x%08x, 0x%08x, %p, %p stub.\n", handle, mask, obj_attr, debugstr_guid(guid), tm,
            options, isol_level, isol_flags, timeout, description );

    *handle = ULongToHandle(1);

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtCommitTransaction (NTDLL.@)
 */
NTSTATUS WINAPI NtCommitTransaction( HANDLE transaction, BOOLEAN wait )
{
    FIXME( "%p, %d stub.\n", transaction, wait );

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtRollbackTransaction (NTDLL.@)
 */
NTSTATUS WINAPI NtRollbackTransaction( HANDLE transaction, BOOLEAN wait )
{
    FIXME( "%p, %d stub.\n", transaction, wait );

    return STATUS_ACCESS_VIOLATION;
}

/***********************************************************************
 *           NtConvertBetweenAuxiliaryCounterAndPerformanceCounter (NTDLL.@)
 */
NTSTATUS WINAPI NtConvertBetweenAuxiliaryCounterAndPerformanceCounter( ULONG flag, ULONGLONG *from, ULONGLONG *to, ULONGLONG *error )
{
    FIXME( "%#x, %p, %p, %p.\n",  flag, from, to, error );

    if (!from) return STATUS_ACCESS_VIOLATION;

    return STATUS_NOT_SUPPORTED;
}
