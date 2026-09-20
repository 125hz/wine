/*
 * Server-side event management
 *
 * Copyright (C) 1998 Alexandre Julliard
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

#include "config.h"

#include <assert.h>
#include <stdio.h>
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

/* ml990: the generation lives in the high half of `sg'.  Only this thread
 * writes it, so a plain load is enough to find the current value; the bump is
 * always published together with a new state in one 64-bit store, which is
 * what makes a client's state CAS also a generation check. */
static unsigned int madeira_cell_next_gen( const struct madeira_sync_cell *cell )
{
    unsigned int gen = MADEIRA_SG_GEN( __atomic_load_n( &cell->sg, __ATOMIC_RELAXED ) );

    if (!++gen) gen = 1;               /* 0 is reserved for "never allocated" */
    return gen;
}

/* Rebuild `sg' with a new state, keeping whatever generation is there now.
 * Used by every server-side write that is not an alloc or a free.  The CAS
 * loop is not there to protect the generation (this thread is its only writer)
 * but to make the operation a proper 64-bit RMW rather than a mixed-size
 * store racing the clients' 64-bit CASes. */
static int madeira_cell_xchg_state( struct madeira_sync_cell *cell, int want )
{
    uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );

    while (!__atomic_compare_exchange_n( &cell->sg, &sg,
                                         MADEIRA_SG( MADEIRA_SG_GEN( sg ), want ), 1,
                                         __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ))
        ;
    return MADEIRA_SG_STATE( sg );
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
    cell->manual      = !!manual;
    cell->srv_waiters = 0;
    cell->waiters     = 0;
    /* publish the generation and the state TOGETHER, and LAST: a client can
     * only learn this index through a get_inproc_sync_fd reply, which the
     * server sends strictly after this, and a client that still holds the
     * PREVIOUS generation can never CAS against the word this store makes. */
    __atomic_store_n( &cell->sg,
                      MADEIRA_SG( madeira_cell_next_gen( cell ),
                                  signaled ? MADEIRA_CELL_SET : MADEIRA_CELL_RESET ),
                      __ATOMIC_SEQ_CST );
    madeira_cell_live++;
    return idx;
}

static void madeira_cell_free( int idx )
{
    struct madeira_sync_cell *cell = &madeira_sync_cells[idx];

    /* ml990: ONE store retires the old generation and puts the cell in
     * DISABLED.  Through ml982 these were two stores with the DISABLED first,
     * which left a window in which a stale (index, gen) pair still matched;
     * now a client holding the old generation cannot match the word at all,
     * whichever of the two halves it looks at.
     *
     * DISABLED rather than simply "the next generation" because the low half
     * is the futex word: a parked waiter is released by this store's value
     * change as well as by the explicit wake below. */
    __atomic_store_n( &cell->sg,
                      MADEIRA_SG( madeira_cell_next_gen( cell ), MADEIRA_CELL_DISABLED ),
                      __ATOMIC_SEQ_CST );
    if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
        madeira_fast_wake( madeira_cell_futex( cell ), 1 );
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
        int st = MADEIRA_SG_STATE( __atomic_load_n( &madeira_sync_cells[event->cell].sg,
                                                    __ATOMIC_SEQ_CST ) );
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
    prev = madeira_cell_xchg_state( cell, MADEIRA_CELL_DISABLED );
    if (prev != MADEIRA_CELL_DISABLED) event->signaled = (prev != MADEIRA_CELL_RESET);
    /* every parked client must wake, re-read DISABLED and go to the server */
    if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
        madeira_fast_wake( madeira_cell_futex( cell ), 1 );
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
    uint64_t sg;

    if (obj->ops != &event_sync_ops) return;
    if (event->cell < 0 || event->manual) return;
    cell = &madeira_sync_cells[event->cell];
    /* ml990: the CLAIM this releases was taken by event_sync_signaled() on the
     * same generation a moment ago, so the expected word is fully determined
     * by the current one; rebuilding it from a fresh load keeps the CAS a
     * 64-bit RMW without ever guessing a generation. */
    sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
    if (MADEIRA_SG_STATE( sg ) != MADEIRA_CELL_CLAIMED) return;
    if (__atomic_compare_exchange_n( &cell->sg, &sg,
                                     MADEIRA_SG( MADEIRA_SG_GEN( sg ), MADEIRA_CELL_SET ), 0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ))
    {
        /* the token is up for grabs again; a client may be parked on it */
        if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
            madeira_fast_wake( madeira_cell_futex( cell ), 0 );
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
        uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );
        int st = MADEIRA_SG_STATE( sg );

        if (st == MADEIRA_CELL_DISABLED) return event->signaled;
        if (event->manual) return st != MADEIRA_CELL_RESET;
        if (st == MADEIRA_CELL_CLAIMED) return 1;   /* already claimed by us */
        if (st != MADEIRA_CELL_SET) return 0;
        /* CLAIM the auto-reset token so that no client CAS can steal it
         * between here and event_sync_satisfied().  If the CAS loses, a client
         * took it first and this waiter is simply not signaled. */
        return __atomic_compare_exchange_n( &cell->sg, &sg,
                                            MADEIRA_SG( MADEIRA_SG_GEN( sg ), MADEIRA_CELL_CLAIMED ), 0,
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

        if (MADEIRA_SG_STATE( __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST ) ) != MADEIRA_CELL_DISABLED)
        {
            /* consume the claim taken in event_sync_signaled(); a SetEvent
             * that landed on top of the claim is consumed by this same write,
             * which is what Windows does too -- one set, one release. */
            if (!event->manual) madeira_cell_xchg_state( cell, MADEIRA_CELL_RESET );
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

        if (MADEIRA_SG_STATE( __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST ) ) != MADEIRA_CELL_DISABLED)
        {
            int prev;

            event->signaled = !!signal;   /* kept only for the DISABLED fallback */
            prev = madeira_cell_xchg_state( cell, signal ? MADEIRA_CELL_SET : MADEIRA_CELL_RESET );
            if (prev == MADEIRA_CELL_DISABLED)  /* raced a pulse: put it back */
                madeira_cell_xchg_state( cell, MADEIRA_CELL_DISABLED );
            else if (signal)
            {
                if (__atomic_load_n( &cell->waiters, __ATOMIC_SEQ_CST ))
                    madeira_fast_wake( madeira_cell_futex( cell ), event->manual );
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

struct event
{
    struct object      obj;             /* object header */
    struct object     *sync;            /* event sync object */
    struct list        kernel_object;   /* list of kernel object pointers */
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

void set_event( struct event *event )
{
    signal_sync( event->sync );
}

void reset_event( struct event *event )
{
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
    if (MADEIRA_SG_STATE( __atomic_load_n( &madeira_sync_cells[sync->cell].sg,
                                           __ATOMIC_SEQ_CST ) ) == MADEIRA_CELL_DISABLED) return -1;
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
