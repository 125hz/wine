/*
 * Server-side event management
 *
 * Copyright (C) 1998 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "thread.h"
#include "request.h"
#include "security.h"

#ifdef WINE_IOS
/* iOS-Madeira ml952 fastsync: the shared cell table lives here (see the long
 * comment in build/ntdll-unix/shims/ios_fastsync.h).  This file is the single
 * definition; wine/dlls/ntdll/unix/sync.c references it across the archive
 * boundary, which works because the server and every guest thread are one
 * Mach task and one static link. */
#include "ios_fastsync.h"

struct madeira_sync_cell madeira_sync_cells[MADEIRA_SYNC_CELLS];

/* Allocator state.  Server-thread only: create_event() and the event_sync
 * destroy path both run on the server's single thread, so no lock. */
static int madeira_cell_next[MADEIRA_SYNC_CELLS];
static int madeira_cell_free_head = -1;
static int madeira_cell_high;              /* bump allocator watermark */
static int madeira_cell_live;              /* live cells, reported in the banner */
static int madeira_fastsync_on = -1;

static int madeira_fastsync_enabled(void)
{
    if (madeira_fastsync_on < 0)
    {
        /* ml982: the SERVER half is on for every mode except an explicit
         * "off", and the client half (the wake semantics) is gated separately
         * by the identical parse in ntdll/unix/sync.c -- see the four-mode
         * table at the head of ios_fastsync.h.
         *
         * Allocating a cell with no client participation is a pure relocation
         * of one bit: event_sync_signaled() reads the cell where it used to
         * read `signaled', event_sync_satisfied() clears the cell where it
         * used to clear `signaled', event_sync_signal() writes the cell where
         * it used to write `signaled', and with nothing else touching the word
         * every CAS in here succeeds first time.  What it buys is that the
         * word EXISTS at an address a guest thread can read, which is all the
         * read-only zero-timeout peek (MADEIRA_FS_POLLPEEK) needs -- and that
         * peek is a third of this port's server traffic.
         *
         * With "0"/"off"/"no" madeira_cell_alloc() hands back -1 for every
         * event, so event->cell is always -1, every hook in this file falls
         * through to the plain `signaled' bit and madeira_event_cell_index()
         * always answers -1: the pre-ml952 server, byte for byte. */
        const char *e = getenv( "MADEIRA_FASTSYNC" );
        madeira_fastsync_on = (e && (!strcmp( e, "0" ) || !strcmp( e, "off" ) ||
                                     !strcmp( e, "no" ))) ? 0 : 1;
    }
    return madeira_fastsync_on;
}

static void madeira_cell_bump_gen( struct madeira_sync_cell *cell )
{
    if (!++cell->gen) cell->gen = 1;   /* 0 is reserved for "never allocated" */
}

/* Returns a cell index, or -1 when the fast path is off or the table is full;
 * -1 simply means the event keeps the pre-fastsync, all-server behaviour. */
static int madeira_cell_alloc( int manual, int signaled )
{
    struct madeira_sync_cell *cell;
    int idx;

    if (!madeira_fastsync_enabled()) return -1;

    if (madeira_cell_free_head >= 0)
    {
        idx = madeira_cell_free_head;
        madeira_cell_free_head = madeira_cell_next[idx];
    }
    else if (madeira_cell_high < MADEIRA_SYNC_CELLS) idx = madeira_cell_high++;
    else return -1;

    cell = &madeira_sync_cells[idx];
    madeira_cell_bump_gen( cell );
    cell->manual      = !!manual;
    cell->srv_waiters = 0;
    cell->waiters     = 0;
    /* publish the state LAST: a client can only learn this index through a
     * get_inproc_sync_fd reply, which the server sends strictly after this. */
    __atomic_store_n( &cell->state, signaled ? MADEIRA_CELL_SET : MADEIRA_CELL_RESET,
                      __ATOMIC_SEQ_CST );
    madeira_cell_live++;
    return idx;
}

static void madeira_cell_free( int idx )
{
    struct madeira_sync_cell *cell = &madeira_sync_cells[idx];

    /* DISABLED first, so any client still holding a stale (index, gen) pair
     * takes the server path rather than mutating a recycled cell, then the
     * generation bump so that stale pair can never match again. */
    __atomic_store_n( &cell->state, MADEIRA_CELL_DISABLED, __ATOMIC_SEQ_CST );
    madeira_cell_bump_gen( cell );
    if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
        madeira_fast_wake( &cell->state, 1 );
    madeira_cell_next[idx] = madeira_cell_free_head;
    madeira_cell_free_head = idx;
    madeira_cell_live--;
}

int madeira_fastsync_cells_live(void) { return madeira_cell_live; }
#endif /* WINE_IOS */

static const WCHAR event_name[] = {'E','v','e','n','t'};

struct type_descr event_type =
{
    { event_name, sizeof(event_name) },   /* name */
    EVENT_ALL_ACCESS,                     /* valid_access */
    {                                     /* mapping */
        STANDARD_RIGHTS_READ | EVENT_QUERY_STATE,
        STANDARD_RIGHTS_WRITE | EVENT_MODIFY_STATE,
        STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
        EVENT_ALL_ACCESS
    },
};

struct event_sync
{
    struct object  obj;             /* object header */
    unsigned int   manual : 1;      /* is it a manual reset event? */
    unsigned int   signaled : 1;    /* event has been signaled */
#ifdef WINE_IOS
    int            cell;            /* ml952 fastsync cell index, -1 = none.
                                     * Only events reachable by handle get one;
                                     * the server-internal syncs created by
                                     * create_server_internal_sync() keep the
                                     * `signaled' bit above and never appear in
                                     * the shared table. */
#endif
};

static void event_sync_dump( struct object *obj, int verbose );
static int event_sync_signaled( struct object *obj, struct wait_queue_entry *entry );
static void event_sync_satisfied( struct object *obj, struct wait_queue_entry *entry );
static int event_sync_signal( struct object *obj, unsigned int access, int signal );
#ifdef WINE_IOS
static int event_sync_add_queue( struct object *obj, struct wait_queue_entry *entry );
static void event_sync_remove_queue( struct object *obj, struct wait_queue_entry *entry );
static void event_sync_destroy( struct object *obj );

/* Current state of an event_sync, cell or no cell.  This is the only reader of
 * `signaled' left for a cell event, and it only fires once the cell has been
 * disabled by a PulseEvent. */
static int event_sync_state( struct event_sync *event )
{
    if (event->cell >= 0)
    {
        int st = __atomic_load_n( &madeira_sync_cells[event->cell].state, __ATOMIC_SEQ_CST );
        if (st != MADEIRA_CELL_DISABLED) return st != MADEIRA_CELL_RESET;
    }
    return event->signaled;
}

/* One-way exit from the fast path, taken by the first PulseEvent on an object.
 * PulseEvent means "release everything waiting at this instant, then clear"; on
 * a futex word the set and the clear cannot be made atomic with respect to a
 * parked waiter's re-check, so a pulsed object stops using its cell rather than
 * being approximated.  The pre-pulse state is folded back into `signaled' so
 * the server is authoritative from here on. */
static void event_sync_disable_cell( struct event_sync *event )
{
    struct madeira_sync_cell *cell;
    int prev;

    if (event->cell < 0) return;
    cell = &madeira_sync_cells[event->cell];
    prev = __atomic_exchange_n( &cell->state, MADEIRA_CELL_DISABLED, __ATOMIC_SEQ_CST );
    if (prev != MADEIRA_CELL_DISABLED) event->signaled = (prev != MADEIRA_CELL_RESET);
    /* every parked client must wake, re-read DISABLED and go to the server */
    if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
        madeira_fast_wake( &cell->state, 1 );
}
#endif

static const struct object_ops event_sync_ops =
{
    sizeof(struct event_sync), /* size */
    &no_type,                  /* type */
    event_sync_dump,           /* dump */
#ifdef WINE_IOS
    /* ml952 fastsync: the add/remove hooks maintain cell->srv_waiters, which
     * is the flag a client setter reads to decide whether the server still has
     * to be told about a set.  The increment MUST be visible before the server
     * evaluates `signaled', and it is: wait_on() adds every queue entry and
     * only then does check_wait() call signaled. */
    event_sync_add_queue,      /* add_queue */
    event_sync_remove_queue,   /* remove_queue */
#else
    add_queue,                 /* add_queue */
    remove_queue,              /* remove_queue */
#endif
    event_sync_signaled,       /* signaled */
    event_sync_satisfied,      /* satisfied */
    event_sync_signal,         /* signal */
    no_get_fd,                 /* get_fd */
    default_get_sync,          /* get_sync */
    default_map_access,        /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    default_get_full_name,     /* get_full_name */
    no_lookup_name,            /* lookup_name */
    directory_link_name,       /* link_name */
    default_unlink_name,       /* unlink_name */
    no_open_file,              /* open_file */
    no_kernel_obj_list,        /* get_kernel_obj_list */
    no_close_handle,           /* close_handle */
#ifdef WINE_IOS
    event_sync_destroy         /* destroy */
#else
    no_destroy                 /* destroy */
#endif
};

static struct object *create_event_sync( int manual, int signaled )
{
    struct event_sync *event;

    if (get_inproc_device_fd() >= 0) return (struct object *)create_inproc_event_sync( manual, signaled );

    if (!(event = alloc_object( &event_sync_ops ))) return NULL;
    event->manual   = manual;
    event->signaled = signaled;
#ifdef WINE_IOS
    /* ml952: only handle-reachable events get a cell, and a full table just
     * means this one keeps the old all-server behaviour. */
    event->cell = madeira_cell_alloc( manual, signaled );
#endif

    return &event->obj;
}

struct event_sync *create_server_internal_sync( int manual, int signaled )
{
    struct event_sync *event;

    if (!(event = alloc_object( &event_sync_ops ))) return NULL;
    event->manual   = manual;
    event->signaled = signaled;
#ifdef WINE_IOS
    event->cell = -1;   /* internal syncs are never handed to a client */
#endif

    return event;
}

struct object *create_internal_sync( int manual, int signaled )
{
    if (get_inproc_device_fd() >= 0) return (struct object *)create_inproc_internal_sync( manual, signaled );
    return (struct object *)create_server_internal_sync( manual, signaled );
}

static void event_sync_dump( struct object *obj, int verbose )
{
    struct event_sync *event = (struct event_sync *)obj;
    assert( obj->ops == &event_sync_ops );
#ifdef WINE_IOS
    fprintf( stderr, "Event manual=%d signaled=%d cell=%d\n",
             event->manual, event_sync_state( event ), event->cell );
#else
    fprintf( stderr, "Event manual=%d signaled=%d\n",
             event->manual, event->signaled );
#endif
}

#ifdef WINE_IOS
static int event_sync_add_queue( struct object *obj, struct wait_queue_entry *entry )
{
    struct event_sync *event = (struct event_sync *)obj;

    assert( obj->ops == &event_sync_ops );
    if (event->cell >= 0)
        __atomic_add_fetch( &madeira_sync_cells[event->cell].srv_waiters, 1, __ATOMIC_SEQ_CST );
    return add_queue( obj, entry );
}

static void event_sync_remove_queue( struct object *obj, struct wait_queue_entry *entry )
{
    struct event_sync *event = (struct event_sync *)obj;
    /* ml962: remove_queue() ends in release_object( obj ), so `event' must not
     * be dereferenced after it -- read the index first.  (The outer `event'
     * object still holds a reference to this sync for as long as a wait entry
     * exists, so the release is not currently the last one; this is here so it
     * stays correct if that ever stops being true.) */
    int cell = event->cell;

    assert( obj->ops == &event_sync_ops );
    remove_queue( obj, entry );
    if (cell >= 0)
        __atomic_sub_fetch( &madeira_sync_cells[cell].srv_waiters, 1, __ATOMIC_SEQ_CST );
}

static void event_sync_destroy( struct object *obj )
{
    struct event_sync *event = (struct event_sync *)obj;

    assert( obj->ops == &event_sync_ops );
    if (event->cell >= 0) madeira_cell_free( event->cell );
    event->cell = -1;
}

/* ml952: release a claim taken by event_sync_signaled() for a wait-all that
 * then turned out not to be satisfiable.  Called from check_wait() through
 * object_sync_unclaim(); the ops check makes it a no-op for every other kind
 * of sync object, so no ops-table entry is needed. */
void madeira_event_sync_unclaim( struct object *obj )
{
    struct event_sync *event = (struct event_sync *)obj;
    struct madeira_sync_cell *cell;
    int st = MADEIRA_CELL_CLAIMED;

    if (obj->ops != &event_sync_ops) return;
    if (event->cell < 0 || event->manual) return;
    cell = &madeira_sync_cells[event->cell];
    if (__atomic_compare_exchange_n( &cell->state, &st, MADEIRA_CELL_SET, 0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ))
    {
        /* the token is up for grabs again; a client may be parked on it */
        if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
            madeira_fast_wake( &cell->state, 0 );
    }
}

/* ml962: the whole of MADEIRA_EVENT_OP_WAKE (see ios_fastsync.h).
 *
 * The client already CAS'd the cell to SET and only sent a request because
 * srv_waiters said the server still had somebody queued.  Signalling here
 * would be a SECOND set: if a fast waiter consumed the token in the meantime
 * the cell is back at RESET, and event_sync_signal()'s unconditional
 * exchange-to-SET would release a server-side waiter for a SetEvent that has
 * already been paid out.  So this runs wake_up() and nothing else, and lets
 * event_sync_signaled() decide from the cell word whether there is still a
 * token to hand over -- its CAS fails when there is not, and the queued
 * thread simply stays queued.
 *
 * wake_up() on an empty (or unsatisfiable) queue is a no-op, so the stale
 * srv_waiters reading that can make the client send this request when nothing
 * is queued any more costs a round trip and nothing else. */
void madeira_event_sync_wake_queue( struct object *obj )
{
    struct event_sync *event = (struct event_sync *)obj;

    if (obj->ops != &event_sync_ops) return;
    if (event->cell < 0) return;
    wake_up( &event->obj, !event->manual );
}
#endif /* WINE_IOS */

static int event_sync_signaled( struct object *obj, struct wait_queue_entry *entry )
{
    struct event_sync *event = (struct event_sync *)obj;
    assert( obj->ops == &event_sync_ops );
#ifdef WINE_IOS
    if (event->cell >= 0)
    {
        struct madeira_sync_cell *cell = &madeira_sync_cells[event->cell];
        /* seq_cst: this load is the server half of the Dekker pair whose other
         * half is the client's `store state; load srv_waiters' in NtSetEvent.
         * srv_waiters was already incremented by event_sync_add_queue(). */
        int st = __atomic_load_n( &cell->state, __ATOMIC_SEQ_CST );

        if (st == MADEIRA_CELL_DISABLED) return event->signaled;
        if (event->manual) return st != MADEIRA_CELL_RESET;
        if (st == MADEIRA_CELL_CLAIMED) return 1;   /* already claimed by us */
        if (st != MADEIRA_CELL_SET) return 0;
        /* CLAIM the auto-reset token so that no client CAS can steal it
         * between here and event_sync_satisfied().  If the CAS loses, a client
         * took it first and this waiter is simply not signaled. */
        return __atomic_compare_exchange_n( &cell->state, &st, MADEIRA_CELL_CLAIMED, 0,
                                            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST );
    }
#endif
    return event->signaled;
}

static void event_sync_satisfied( struct object *obj, struct wait_queue_entry *entry )
{
    struct event_sync *event = (struct event_sync *)obj;
    assert( obj->ops == &event_sync_ops );
#ifdef WINE_IOS
    if (event->cell >= 0)
    {
        struct madeira_sync_cell *cell = &madeira_sync_cells[event->cell];

        if (__atomic_load_n( &cell->state, __ATOMIC_SEQ_CST ) != MADEIRA_CELL_DISABLED)
        {
            /* consume the claim taken in event_sync_signaled(); a SetEvent
             * that landed on top of the claim is consumed by this same store,
             * which is what Windows does too -- one set, one release. */
            if (!event->manual)
                __atomic_store_n( &cell->state, MADEIRA_CELL_RESET, __ATOMIC_SEQ_CST );
            return;
        }
    }
#endif
    /* Reset if it's an auto-reset event */
    if (!event->manual) event->signaled = 0;
}

static int event_sync_signal( struct object *obj, unsigned int access, int signal )
{
    struct event_sync *event = (struct event_sync *)obj;
    assert( obj->ops == &event_sync_ops );

#ifdef WINE_IOS
    if (event->cell >= 0)
    {
        struct madeira_sync_cell *cell = &madeira_sync_cells[event->cell];

        if (__atomic_load_n( &cell->state, __ATOMIC_SEQ_CST ) != MADEIRA_CELL_DISABLED)
        {
            int prev;

            event->signaled = !!signal;   /* kept only for the DISABLED fallback */
            prev = __atomic_exchange_n( &cell->state,
                                        signal ? MADEIRA_CELL_SET : MADEIRA_CELL_RESET,
                                        __ATOMIC_SEQ_CST );
            if (prev == MADEIRA_CELL_DISABLED)  /* raced a pulse: put it back */
                __atomic_store_n( &cell->state, MADEIRA_CELL_DISABLED, __ATOMIC_SEQ_CST );
            else if (signal)
            {
                if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
                    madeira_fast_wake( &cell->state, event->manual );
                wake_up( &event->obj, !event->manual );
            }
            return 1;
        }
    }
#endif
    /* wake up all waiters if manual reset, a single one otherwise */
    if ((event->signaled = !!signal)) wake_up( &event->obj, !event->manual );
    return 1;
}

/* iOS-Madeira ml807: per-object history.
 *
 * The global ring answers cross-object ordering but WRAPS: a run produced 478
 * "no operations" verdicts that were all unsafe, because traffic on unrelated
 * events had overwritten the only history that mattered. Lifetime counters
 * cannot be overwritten at all, so "was this event EVER signalled" is answerable
 * however long the run goes; the small per-object ring adds detail for the
 * recent past. */
#define IOS_EVT_OBJ_RING 16
struct ios_evt_obj_rec
{
    unsigned int seq;
    unsigned int tid;
    unsigned int status;      /* wait-end status, else 0 */
    unsigned char op;
};
struct ios_evt_stats
{
    unsigned int n_create, n_set, n_reset, n_pulse;
    unsigned int n_wait_begin, n_wait_end, n_wait_timeout, n_wait_success;
    unsigned int last_set_tid, last_set_seq;
    unsigned int last_reset_tid, last_reset_seq;
    unsigned int ring_pos, ring_wrapped;
    struct ios_evt_obj_rec ring[IOS_EVT_OBJ_RING];
};

struct event
{
    struct object      obj;             /* object header */
    struct object     *sync;            /* event sync object */
    struct list        kernel_object;   /* list of kernel object pointers */
    struct ios_evt_stats ios;           /* ml807: never-overwritten lifetime history */
};

static void event_dump( struct object *obj, int verbose );
static struct object *event_get_sync( struct object *obj );
static int event_signal( struct object *obj, unsigned int access, int signal );
static struct list *event_get_kernel_obj_list( struct object *obj );
static void event_destroy( struct object *obj );

static const struct object_ops event_ops =
{
    sizeof(struct event),      /* size */
    &event_type,               /* type */
    event_dump,                /* dump */
    NULL,                      /* add_queue */
    NULL,                      /* remove_queue */
    NULL,                      /* signaled */
    NULL,                      /* satisfied */
    event_signal,              /* signal */
    no_get_fd,                 /* get_fd */
    event_get_sync,            /* get_sync */
    default_map_access,        /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    default_get_full_name,     /* get_full_name */
    no_lookup_name,            /* lookup_name */
    directory_link_name,       /* link_name */
    default_unlink_name,       /* unlink_name */
    no_open_file,              /* open_file */
    event_get_kernel_obj_list, /* get_kernel_obj_list */
    no_close_handle,           /* close_handle */
    event_destroy,             /* destroy */
};


static const WCHAR keyed_event_name[] = {'K','e','y','e','d','E','v','e','n','t'};

struct type_descr keyed_event_type =
{
    { keyed_event_name, sizeof(keyed_event_name) },   /* name */
    KEYEDEVENT_ALL_ACCESS | SYNCHRONIZE,              /* valid_access */
    {                                                 /* mapping */
        STANDARD_RIGHTS_READ | KEYEDEVENT_WAIT,
        STANDARD_RIGHTS_WRITE | KEYEDEVENT_WAKE,
        STANDARD_RIGHTS_EXECUTE,
        KEYEDEVENT_ALL_ACCESS
    },
};

struct keyed_event
{
    struct object  obj;             /* object header */
};

static void keyed_event_dump( struct object *obj, int verbose );
static int keyed_event_signaled( struct object *obj, struct wait_queue_entry *entry );

static const struct object_ops keyed_event_ops =
{
    sizeof(struct keyed_event),  /* size */
    &keyed_event_type,           /* type */
    keyed_event_dump,            /* dump */
    add_queue,                   /* add_queue */
    remove_queue,                /* remove_queue */
    keyed_event_signaled,        /* signaled */
    no_satisfied,                /* satisfied */
    no_signal,                   /* signal */
    no_get_fd,                   /* get_fd */
    default_get_sync,            /* get_sync */
    default_map_access,          /* map_access */
    default_get_sd,              /* get_sd */
    default_set_sd,              /* set_sd */
    default_get_full_name,       /* get_full_name */
    no_lookup_name,              /* lookup_name */
    directory_link_name,         /* link_name */
    default_unlink_name,         /* unlink_name */
    no_open_file,                /* open_file */
    no_kernel_obj_list,          /* get_kernel_obj_list */
    no_close_handle,             /* close_handle */
    no_destroy                   /* destroy */
};


struct event *create_event( struct object *root, const struct unicode_str *name,
                            unsigned int attr, int manual_reset, int initial_state,
                            const struct security_descriptor *sd )
{
    struct event *event;

    if ((event = create_named_object( root, &event_ops, name, attr, sd )))
    {
        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            /* initialize it if it didn't already exist */
            event->sync = NULL;
            list_init( &event->kernel_object );
            /* ml809: MUST zero the stats block here.
             *
             * alloc_object() uses mem_alloc(), not calloc, and initialises only
             * the struct object header -- everything a subclass adds is garbage
             * until it assigns it. ml807/ml808 left this block uninitialised, so
             * ring_pos started as a random value and the first recorded
             * operation wrote ring[garbage], off the end of the object and into
             * the server heap. The wineserver then stopped answering and every
             * client blocked forever in wine_server_call, the first being
             * NtCreateEvent in unix_init_startup_info -- i.e. the desktop never
             * came up, which looked nothing like an event-probe bug. */
            memset( &event->ios, 0, sizeof(event->ios) );

            if (!(event->sync = create_event_sync( manual_reset, initial_state )))
            {
                release_object( event );
                return NULL;
            }
        }
    }
    return event;
}

struct event *get_event_obj( struct process *process, obj_handle_t handle, unsigned int access )
{
    return (struct event *)get_handle_obj( process, handle, access, &event_ops );
}


/* iOS-Madeira ml805: a bounded history of what happens to each event object.
 *
 * The question this exists to answer: RenderThread 0 waits ~60s on a manual
 * event that is never signalled, then exits while still owning a critical
 * section, and eight threads deadlock behind it forever. Nothing so far
 * distinguishes "the producer never ran" from "it signalled a different object"
 * from "the event was reset or closed underneath the waiter".
 *
 * Keyed by OBJECT IDENTITY, never by handle or by a pointer captured from a
 * previous run -- both change. queue_ios.c's [srv-stuck] already resolves the
 * object a stuck thread waits on, and latches onto whatever that turns out to
 * be, so this needs no prior knowledge of which event matters.
 *
 * Bounded and overwriting: a hang produces unbounded operations on OTHER
 * events, and a probe that allocates or grows under a fault is how an earlier
 * one died on its own log text. */
#define IOS_EVT_RING_N 1024
struct ios_evt_rec
{
    void         *obj;        /* event wrapper -- the identity queue_ios.c resolves */
    void         *sync;       /* its sync object, which is what waiters queue on */
    unsigned int  tid;        /* thread that performed the operation */
    unsigned int  seq;
    unsigned char op;         /* ios_evt_op */
    signed char   state;      /* signalled state BEFORE the op, -1 unknown */
};
enum ios_evt_op { IOS_EVT_CREATE = 0, IOS_EVT_SET, IOS_EVT_RESET, IOS_EVT_PULSE,
                  IOS_EVT_DUP, IOS_EVT_CLOSE, IOS_EVT_WAIT_BEGIN, IOS_EVT_WAIT_END };
static const char * const ios_evt_op_name[] = { "create", "SET", "reset", "pulse", "dup", "close",
                                                "wait-begin", "wait-end" };

static struct ios_evt_rec ios_evt_ring[IOS_EVT_RING_N];
static unsigned int ios_evt_pos, ios_evt_seq, ios_evt_wrapped;

void ios_evt_record( void *obj, void *sync, int op, int state );   /* ml807: fwd decl */

/* ml807: called from thread.c's wait_on/end_wait.
 *
 * This is the record Sol asked for and the one most likely to settle the case:
 * when the first lock timeouts appear the render thread's CURRENT event wait is
 * only 8.7s old, while other threads have already blocked 60s on the section it
 * holds. Either it times out and re-enters the wait repeatedly, or this wait is
 * downstream of an earlier stall. A begin/end count with statuses separates
 * those; a single age sample cannot. */
void ios_evt_note_wait( struct object *obj, int begin, unsigned int status )
{
    if (!obj || obj->ops != &event_ops) return;
    ios_evt_record( obj, ((struct event *)obj)->sync,
                    begin ? IOS_EVT_WAIT_BEGIN : IOS_EVT_WAIT_END, (int)status );
}

/* ml805: identity test for handle.c, which cannot see event_ops. */
int ios_obj_is_event( struct object *obj )
{
    return obj && obj->ops == &event_ops;
}

/* ml805: the sync object a waiter would actually queue on. */
void *ios_evt_sync_of( struct object *obj )
{
    return ios_obj_is_event( obj ) ? ((struct event *)obj)->sync : NULL;
}

/* ml807: update the per-object stats that cannot be overwritten. */
static void ios_evt_stat( struct event *event, int op, unsigned int status, unsigned int seq )
{
    struct ios_evt_stats *st;
    struct ios_evt_obj_rec *rec;
    unsigned int tid = current ? current->id : 0;

    if (!event) return;
    st = &event->ios;
    switch (op)
    {
    case IOS_EVT_CREATE:     st->n_create++; break;
    case IOS_EVT_SET:        st->n_set++;   st->last_set_tid = tid;   st->last_set_seq = seq;   break;
    case IOS_EVT_RESET:      st->n_reset++; st->last_reset_tid = tid; st->last_reset_seq = seq; break;
    case IOS_EVT_PULSE:      st->n_pulse++; break;
    case IOS_EVT_WAIT_BEGIN: st->n_wait_begin++; break;
    case IOS_EVT_WAIT_END:
        st->n_wait_end++;
        if (status == STATUS_TIMEOUT) st->n_wait_timeout++; else st->n_wait_success++;
        break;
    default: break;
    }
    /* ml809: belt and braces. The out-of-bounds write above cost a build and a
     * run to find; a bounds check here makes any future uninitialised path
     * merely lose a record instead of corrupting the server heap. */
    if (st->ring_pos >= IOS_EVT_OBJ_RING) st->ring_pos = 0;
    rec = &st->ring[st->ring_pos];
    rec->seq = seq; rec->tid = tid; rec->status = status; rec->op = (unsigned char)op;
    if (++st->ring_pos == IOS_EVT_OBJ_RING) { st->ring_pos = 0; st->ring_wrapped = 1; }
}

void ios_evt_record( void *obj, void *sync, int op, int state )
{
    struct ios_evt_rec *r = &ios_evt_ring[ios_evt_pos];

    r->obj   = obj;
    r->sync  = sync;
    r->tid   = current ? current->id : 0;
    r->seq   = ++ios_evt_seq;
    r->op    = (unsigned char)op;
    r->state = (signed char)state;
    if (++ios_evt_pos == IOS_EVT_RING_N) { ios_evt_pos = 0; ios_evt_wrapped = 1; }
    ios_evt_stat( (struct event *)obj, op, (unsigned int)(state < 0 ? 0 : state), r->seq );
}

/* Print every recorded operation on ONE object, oldest first. Called from
 * [srv-stuck] with the object it independently resolved. */
int ios_evt_dump_for( void *obj )
{
    unsigned int i, n = 0;

    /* ml806: raw write, not stdio. The ml805 build proved (by disassembly) that
     * this function is CALLED, yet not one of its fprintf lines reached the log
     * while [srv-stuck]'s fprintfs from the same thread did. Until that is
     * explained, nothing here may depend on stdio: write(2) has no buffer, no
     * lock of its own and no FILE* to be wrong about. */
    { static const char m[] = "[evt-entry]\n"; ssize_t w = write( 2, m, sizeof(m) - 1 ); (void)w; }

    for (i = 0; i < IOS_EVT_RING_N; i++)
    {
        unsigned int idx = (ios_evt_pos + i) % IOS_EVT_RING_N;
        struct ios_evt_rec *r = &ios_evt_ring[idx];

        if (!r->seq || r->obj != obj) continue;
        fprintf( stderr, "[evt-hist] obj=%p sync=%p seq=%u tid=%04x %s state_before=%d\n",
                 r->obj, r->sync, r->seq, r->tid,
                 r->op < 6 ? ios_evt_op_name[r->op] : "?", r->state );
        n++;
    }
    /* ml807: lifetime counters FIRST -- these cannot wrap, so they answer
     * "was this event ever signalled" regardless of how long the run went. */
    if (((struct object *)obj)->ops == &event_ops)
    {
        struct ios_evt_stats *st = &((struct event *)obj)->ios;
        unsigned int k, shown = 0;

        fprintf( stderr, "[evt-life] obj=%p create=%u SET=%u reset=%u pulse=%u | "
                         "wait begin=%u end=%u timeout=%u success=%u | "
                         "last_set tid=%04x seq=%u | last_reset tid=%04x seq=%u%s\n",
                 obj, st->n_create, st->n_set, st->n_reset, st->n_pulse,
                 st->n_wait_begin, st->n_wait_end, st->n_wait_timeout, st->n_wait_success,
                 st->last_set_tid, st->last_set_seq, st->last_reset_tid, st->last_reset_seq,
                 st->n_set ? "" : "   <-- NEVER SET BY ANYONE, for the whole life of this object" );

        for (k = 0; k < IOS_EVT_OBJ_RING; k++)
        {
            unsigned int idx = (st->ring_pos + k) % IOS_EVT_OBJ_RING;
            struct ios_evt_obj_rec *rec = &st->ring[idx];
            if (!rec->seq) continue;
            fprintf( stderr, "[evt-life]   seq=%u tid=%04x %s status=%08x\n",
                     rec->seq, rec->tid,
                     rec->op < 8 ? ios_evt_op_name[rec->op] : "?", rec->status );
            shown++;
        }
        if (shown && st->ring_wrapped)
            fprintf( stderr, "[evt-life]   (per-object ring wrapped; counters above are still exact)\n" );
    }

    if (!n)
        fprintf( stderr, "[evt-hist] obj=%p: no recorded operations in the GLOBAL ring (%u entries%s). "
                         "%s\n",
                 obj, ios_evt_wrapped ? IOS_EVT_RING_N : ios_evt_pos,
                 ios_evt_wrapped ? ", WRAPPED" : "",
                 ios_evt_wrapped
                     ? "The ring WRAPPED, so this does NOT mean the producer never ran -- older "
                       "operations were overwritten and this verdict is UNSAFE"
                     : "The ring never wrapped, so this event genuinely was never set, reset, "
                       "duplicated or closed by anyone" );
    else
        fprintf( stderr, "[evt-hist] obj=%p: %u operations above%s\n", obj, n,
                 ios_evt_wrapped ? " (ring WRAPPED -- older history lost)" : "" );
    return (int)n;
}

void set_event( struct event *event )
{
    ios_evt_record( event, event->sync, IOS_EVT_SET, -1 );
    signal_sync( event->sync );
}

void reset_event( struct event *event )
{
    ios_evt_record( event, event->sync, IOS_EVT_RESET, -1 );
    reset_sync( event->sync );
}

static void event_dump( struct object *obj, int verbose )
{
    struct event *event = (struct event *)obj;
    assert( obj->ops == &event_ops );
    event->sync->ops->dump( event->sync, verbose );
}

static struct object *event_get_sync( struct object *obj )
{
    struct event *event = (struct event *)obj;
    assert( obj->ops == &event_ops );
    return grab_object( event->sync );
}

static int event_signal( struct object *obj, unsigned int access, int signal )
{
    struct event *event = (struct event *)obj;
    assert( obj->ops == &event_ops );

    assert( event->sync->ops == &event_sync_ops ); /* never called with inproc syncs */
    assert( signal == -1 ); /* always called from signal_object */

    if (!(access & EVENT_MODIFY_STATE))
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }

    return event_sync_signal( event->sync, 0, 1 );
}

static struct list *event_get_kernel_obj_list( struct object *obj )
{
    struct event *event = (struct event *)obj;
    return &event->kernel_object;
}

static void event_destroy( struct object *obj )
{
    struct event *event = (struct event *)obj;
    assert( obj->ops == &event_ops );

    if (event->sync) release_object( event->sync );
}

#ifdef WINE_IOS
/* ml952: the handle -> cell lookup behind DECL_HANDLER(get_inproc_sync_fd).
 * Returns -1 for anything that is not a live cell-backed event. */
int madeira_event_cell_index( struct object *obj, int *manual )
{
    struct event *event;
    struct event_sync *sync;

    if (obj->ops != &event_ops) return -1;
    event = (struct event *)obj;
    if (!event->sync || event->sync->ops != &event_sync_ops) return -1;
    sync = (struct event_sync *)event->sync;
    if (sync->cell < 0) return -1;
    if (__atomic_load_n( &madeira_sync_cells[sync->cell].state,
                         __ATOMIC_SEQ_CST ) == MADEIRA_CELL_DISABLED) return -1;
    *manual = sync->manual;
    return sync->cell;
}

/* ml982: the self-heal half of the client-side watchdog, reached through
 * MADEIRA_EVENT_OP_DISABLE (see ios_fastsync.h).  Takes ONE event out of the
 * fast path for good, by exactly the route PulseEvent already uses.  Returns 0
 * for an object that has no cell, which is not an error -- the client may have
 * raced a pulse or a re-learn and asking twice must be harmless. */
int madeira_event_disable_cell( struct object *obj )
{
    struct event *event;

    if (obj->ops != &event_ops) return 0;
    event = (struct event *)obj;
    if (!event->sync || event->sync->ops != &event_sync_ops) return 0;
    event_sync_disable_cell( (struct event_sync *)event->sync );
    return 1;
}
#endif

struct keyed_event *create_keyed_event( struct object *root, const struct unicode_str *name,
                                        unsigned int attr, const struct security_descriptor *sd )
{
    struct keyed_event *event;

    if ((event = create_named_object( root, &keyed_event_ops, name, attr, sd )))
    {
        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            /* initialize it if it didn't already exist */
        }
    }
    return event;
}

struct keyed_event *get_keyed_event_obj( struct process *process, obj_handle_t handle, unsigned int access )
{
    return (struct keyed_event *)get_handle_obj( process, handle, access, &keyed_event_ops );
}

static void keyed_event_dump( struct object *obj, int verbose )
{
    fputs( "Keyed event\n", stderr );
}

static enum select_opcode matching_op( enum select_opcode op )
{
    return op ^ (SELECT_KEYED_EVENT_WAIT ^ SELECT_KEYED_EVENT_RELEASE);
}

static int keyed_event_signaled( struct object *obj, struct wait_queue_entry *entry )
{
    struct wait_queue_entry *ptr;
    struct process *process;
    enum select_opcode select_op;

    assert( obj->ops == &keyed_event_ops );

    process = get_wait_queue_thread( entry )->process;
    select_op = get_wait_queue_select_op( entry );
    if (select_op != SELECT_KEYED_EVENT_WAIT && select_op != SELECT_KEYED_EVENT_RELEASE) return 1;

    LIST_FOR_EACH_ENTRY( ptr, &obj->wait_queue, struct wait_queue_entry, entry )
    {
        if (ptr == entry) continue;
        if (get_wait_queue_thread( ptr )->process != process) continue;
        if (get_wait_queue_select_op( ptr ) != matching_op( select_op )) continue;
        if (get_wait_queue_key( ptr ) != get_wait_queue_key( entry )) continue;
        if (wake_thread_queue_entry( ptr )) return 1;
    }
    return 0;
}

/* create an event */
DECL_HANDLER(create_event)
{
    struct event *event;
    struct unicode_str name;
    struct object *root;
    const struct security_descriptor *sd;
    const struct object_attributes *objattr = get_req_object_attributes( &sd, &name, &root );

    if (!objattr) return;

    if ((event = create_event( root, &name, objattr->attributes,
                               req->manual_reset, req->initial_state, sd )))
    {
        /* ml805: record identity at birth, so a later [evt-hist] dump can say
         * whether the object a stuck waiter is queued on was ever touched. */
        ios_evt_record( event, event->sync, IOS_EVT_CREATE, req->initial_state );
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current->process, event, req->access, objattr->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current->process, event,
                                                          req->access, objattr->attributes );
        release_object( event );
    }

    if (root) release_object( root );
}

/* open a handle to an event */
DECL_HANDLER(open_event)
{
    struct unicode_str name = get_req_unicode_str();

    reply->handle = open_object( current->process, req->rootdir, req->access,
                                 &event_ops, &name, req->attributes );
}

/* do an event operation */
DECL_HANDLER(event_op)
{
    struct event_sync *sync;
    struct event *event;

#ifdef WINE_IOS
    /* ml982: the one opcode a WAITER may send.  It is answered before the
     * EVENT_MODIFY_STATE check below because the thread that notices a
     * fast-path incoherence is by construction a thread that was WAITING on
     * the object, and SYNCHRONIZE is the only right it is required to hold.
     * See MADEIRA_EVENT_OP_DISABLE in ios_fastsync.h for why this is not a
     * state modification. */
    if (req->op == MADEIRA_EVENT_OP_DISABLE)
    {
        if (!(event = get_event_obj( current->process, req->handle, SYNCHRONIZE ))) return;
        if (event->sync && event->sync->ops == &event_sync_ops)
        {
            madeira_event_disable_cell( &event->obj );
            reply->state = ((struct event_sync *)event->sync)->signaled;
        }
        release_object( event );
        return;
    }
#endif

    if (!(event = get_event_obj( current->process, req->handle, EVENT_MODIFY_STATE ))) return;
    assert( event->sync->ops == &event_sync_ops ); /* never called with inproc syncs */
    sync = (struct event_sync *)event->sync;

#ifdef WINE_IOS
    reply->state = event_sync_state( sync );
#else
    reply->state = sync->signaled;
#endif
    switch(req->op)
    {
    case PULSE_EVENT:
#ifdef WINE_IOS
        /* ml952: a pulsed event leaves the fast path for good -- see
         * event_sync_disable_cell(). */
        event_sync_disable_cell( sync );
#endif
        set_event( event );
        reset_event( event );
        break;
    case SET_EVENT:
        set_event( event );
        break;
    case RESET_EVENT:
        reset_event( event );
        break;
#ifdef WINE_IOS
    case MADEIRA_EVENT_OP_WAKE:
        /* ml962: the cell is already authoritative, only the server's own
         * queue still has to look at it.  See madeira_event_sync_wake_queue(). */
        madeira_event_sync_wake_queue( event->sync );
        break;
#endif
    default:
        set_error( STATUS_INVALID_PARAMETER );
        break;
    }
    release_object( event );
}

/* return details about the event */
DECL_HANDLER(query_event)
{
    struct event_sync *sync;
    struct event *event;

    if (!(event = get_event_obj( current->process, req->handle, EVENT_QUERY_STATE ))) return;
    assert( event->sync->ops == &event_sync_ops ); /* never called with inproc syncs */
    sync = (struct event_sync *)event->sync;

    reply->manual_reset = sync->manual;
#ifdef WINE_IOS
    reply->state = event_sync_state( sync );
#else
    reply->state = sync->signaled;
#endif

    release_object( event );
}

/* create a keyed event */
DECL_HANDLER(create_keyed_event)
{
    struct keyed_event *event;
    struct unicode_str name;
    struct object *root;
    const struct security_descriptor *sd;
    const struct object_attributes *objattr = get_req_object_attributes( &sd, &name, &root );

    if (!objattr) return;

    if ((event = create_keyed_event( root, &name, objattr->attributes, sd )))
    {
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current->process, event, req->access, objattr->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current->process, event,
                                                          req->access, objattr->attributes );
        release_object( event );
    }
    if (root) release_object( root );
}

/* open a handle to a keyed event */
DECL_HANDLER(open_keyed_event)
{
    struct unicode_str name = get_req_unicode_str();

    reply->handle = open_object( current->process, req->rootdir, req->access,
                                 &keyed_event_ops, &name, req->attributes );
}
