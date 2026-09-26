/*
 * NTDLL directory and file functions
 *
 * Copyright 1993 Erik Bos
 * Copyright 2003 Eric Pouech
 * Copyright 1996, 2004 Alexandre Julliard
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

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif
#include <poll.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_ATTR_H
#include <sys/attr.h>
#endif
#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#elif defined(MAJOR_IN_SYSMACROS)
# include <sys/sysmacros.h>
#endif
#ifdef HAVE_SYS_VNODE_H
/* Work around a conflict with Solaris' system list defined in sys/list.h. */
#define list SYSLIST
#define list_next SYSLIST_NEXT
#define list_prev SYSLIST_PREV
#define list_head SYSLIST_HEAD
#define list_tail SYSLIST_TAIL
#define list_move_tail SYSLIST_MOVE_TAIL
#define list_remove SYSLIST_REMOVE
#include <sys/vnode.h>
#undef list
#undef list_next
#undef list_prev
#undef list_head
#undef list_tail
#undef list_move_tail
#undef list_remove
#endif
#ifdef HAVE_LINUX_IOCTL_H
#include <linux/ioctl.h>
#endif
#ifdef HAVE_LINUX_MAJOR_H
# include <linux/major.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif
#ifdef HAVE_SYS_EXTATTR_H
#undef XATTR_ADDITIONAL_OPTIONS
#include <sys/extattr.h>
#endif
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif
#include <time.h>
#include <unistd.h>

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winioctl.h"
#include "winternl.h"
#include "ddk/ntddk.h"
#include "ddk/ntddser.h"
#include "ddk/ntifs.h"
#include "ddk/wdm.h"
#define WINE_MOUNTMGR_EXTENSIONS
#include "ddk/mountmgr.h"
#include "wine/server.h"
#include "wine/list.h"
#include "wine/debug.h"
#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(file);
WINE_DECLARE_DEBUG_CHANNEL(winediag);

#define MAX_DOS_DRIVES 26

/* just in case... */
#undef VFAT_IOCTL_READDIR_BOTH
#undef EXT2_IOC_GETFLAGS
#undef EXT4_CASEFOLD_FL

#ifdef linux

/* We want the real kernel dirent structure, not the libc one */
typedef struct
{
    long d_ino;
    long d_off;
    unsigned short d_reclen;
    char d_name[256];
} KERNEL_DIRENT;

/* Define the VFAT ioctl to get both short and long file names */
#define VFAT_IOCTL_READDIR_BOTH  _IOR('r', 1, KERNEL_DIRENT [2] )

/* Define the ext2 ioctl for handling extra attributes */
#define EXT2_IOC_GETFLAGS _IOR('f', 1, long)

/* Case-insensitivity attribute */
#define EXT4_CASEFOLD_FL 0x40000000

#ifndef O_DIRECTORY
# define O_DIRECTORY 0200000 /* must be directory */
#endif

#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif

#endif  /* linux */

#define IS_SEPARATOR(ch)   ((ch) == '\\' || (ch) == '/')

#define INVALID_NT_CHARS   '*','?','<','>','|','"'
#define INVALID_DOS_CHARS  INVALID_NT_CHARS,'+','=',',',';','[',']',' ','\345'

#define MAX_DIR_ENTRY_LEN 255  /* max length of a directory entry in chars */

#define MAX_IGNORED_FILES 4

#ifndef XATTR_USER_PREFIX
# define XATTR_USER_PREFIX "user."
#endif
#ifndef XATTR_USER_PREFIX_LEN
# define XATTR_USER_PREFIX_LEN (sizeof(XATTR_USER_PREFIX) - 1)
#endif

#define SAMBA_XATTR_DOS_ATTRIB  XATTR_USER_PREFIX "DOSATTRIB"
#define XATTR_ATTRIBS_MASK      (FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)

#define XATTR_REPARSE XATTR_USER_PREFIX "WINEREPARSE"

struct file_identity
{
    dev_t dev;
    ino_t ino;
};

static struct file_identity ignored_files[MAX_IGNORED_FILES];
static unsigned int ignored_files_count;

union file_directory_info
{
    ULONG                              next;
    FILE_DIRECTORY_INFORMATION         dir;
    FILE_BOTH_DIRECTORY_INFORMATION    both;
    FILE_FULL_DIRECTORY_INFORMATION    full;
    FILE_ID_BOTH_DIRECTORY_INFORMATION id_both;
    FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION extd_both;
    FILE_ID_FULL_DIRECTORY_INFORMATION id_full;
    FILE_ID_GLOBAL_TX_DIR_INFORMATION  id_tx;
    FILE_NAMES_INFORMATION             names;
};

struct dir_data_buffer
{
    struct dir_data_buffer *next;    /* next buffer in the list */
    unsigned int            size;    /* total size of the buffer */
    unsigned int            pos;     /* current position in the buffer */
    char                    data[1];
};

struct dir_data_names
{
    const WCHAR *long_name;          /* long file name in Unicode */
    const WCHAR *short_name;         /* short file name in Unicode */
    const char  *unix_name;          /* Unix file name in host encoding */
};

struct dir_data
{
    unsigned int            size;    /* size of the names array */
    unsigned int            count;   /* count of used entries in the names array */
    unsigned int            pos;     /* current reading position in the names array */
    struct file_identity    id;      /* directory file identity */
    struct dir_data_names  *names;   /* directory file names */
    struct dir_data_buffer *buffer;  /* head of data buffers list */
    UNICODE_STRING          mask;    /* the mask used when creating the cache entry */
};

static const unsigned int dir_data_buffer_initial_size = 4096;
static const unsigned int dir_data_cache_initial_size  = 256;
static const unsigned int dir_data_names_initial_size  = 64;

static struct dir_data **dir_data_cache;
static unsigned int dir_data_cache_size;

static BOOL show_dot_files;
static mode_t start_umask;

static const WCHAR nt_prefixW[] = {'\\','?','?','\\'};
static const WCHAR dos_prefixW[] = {'\\','?','?','\\','A',':','\\'};
static const WCHAR unc_prefixW[] = {'\\','?','?','\\','U','N','C','\\'};
static const WCHAR unix_prefixW[] = {'\\','?','?','\\','u','n','i','x'};

/* at some point we may want to allow Winelib apps to set this */
static const BOOL is_case_sensitive = FALSE;

static pthread_mutex_t dir_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mnt_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef WINE_IOS
/***********************************************************************
 * iOS-Madeira ml910 — [fs-stats] and the NT-path resolution caches.
 *
 * The sampling profiler put a 32-bit D3D9 title's serial main thread at
 * fstatat 17-28%, getattrlistat 5-9%, __openat 5-9%, lstat ~3%, listxattr
 * ~3%, __getdirentries64 ~1.5% of all CPU, for SUCCESSFUL lookups (only 64
 * NtCreateFile failures in a whole 3-minute run).  The app container volume
 * is case-SENSITIVE APFS, so every Windows path whose on-disk spelling
 * differs in case misses lookup_unix_name()'s exact-case shortcut and then
 * pays, per component: fstatat (exact case) + getattrlistat (FSID, on EVERY
 * call) + openat + fdopendir + a full getdirentries scan.  That is ~5
 * syscalls per component of a ~7-deep path, per open, forever, because
 * nothing upstream remembers the answer.
 *
 * Three pieces live here:
 *   1. counters/timers behind relaxed atomics, reported as [fs-stats] every
 *      10 s (same cadence as [prof]) from whichever thread first crosses the
 *      deadline — one CAS elects the printer, no locks anywhere;
 *   2. ios_pc_*: the resolved-name cache, key = <parent unix path>/<ASCII
 *      case-folded requested name>, value = the actual on-disk spelling.
 *      Used both for a whole remaining path (lookup_unix_name) and for a
 *      single component (find_file_in_dir);
 *   3. ios_cs_memo: get_dir_case_sensitivity() memoised per directory path,
 *      which removes the per-call getattrlistat entirely.
 *
 * Every cache hit is re-validated with one fstatat, so a stale entry costs a
 * failed stat and falls through to the upstream scan.  See the correctness
 * notes at each cache.
 */

#define IOS_FSA(v,n)  __atomic_fetch_add( &(v), (unsigned long long)(n), __ATOMIC_RELAXED )
#define IOS_FSL(v)    __atomic_load_n( &(v), __ATOMIC_RELAXED )

enum ios_fs_op { IOS_OP_OPEN, IOS_OP_CREATE, IOS_OP_QATTR, IOS_OP_QFULL,
                 IOS_OP_QINFO, IOS_OP_QDIR, IOS_OP_READ, IOS_OP_COUNT };
static const char * const ios_fs_opname[IOS_OP_COUNT] =
    { "open", "create", "qattr", "qfull", "qinfo", "qdir", "read" };
static unsigned long long ios_fs_opn[IOS_OP_COUNT];
static unsigned long long ios_fs_opus[IOS_OP_COUNT];

enum ios_fs_sc { IOS_SC_FSTATAT, IOS_SC_GETATTRLISTAT, IOS_SC_GETATTRLIST, IOS_SC_LSTAT,
                 IOS_SC_STAT, IOS_SC_FSTAT, IOS_SC_LISTXATTR, IOS_SC_GETXATTR,
                 IOS_SC_OPENAT, IOS_SC_DIRSCAN, IOS_SC_READDIR, IOS_SC_COUNT };
static const char * const ios_fs_scname[IOS_SC_COUNT] =
    { "fstatat", "getattrlistat", "getattrlist", "lstat", "stat", "fstat",
      "listxattr", "getxattr", "openat", "dirscan", "readdir" };
static unsigned long long ios_fs_sc[IOS_SC_COUNT];

/* read shape */
static unsigned long long ios_fs_read_bytes, ios_fs_read_sync, ios_fs_read_srv, ios_fs_read_pos;
/* lookup shape */
#define IOS_FS_DEPTH_MAX 8
static unsigned long long ios_fs_depth[IOS_FS_DEPTH_MAX + 1];
static unsigned long long ios_fs_exact, ios_fs_scan;
static unsigned long long ios_fs_pc_hit, ios_fs_pc_miss, ios_fs_pc_stale, ios_fs_pc_put, ios_fs_pc_evict;
/* ml912: negative entries + why a component lookup never even asked the cache */
static unsigned long long ios_fs_pc_nhit, ios_fs_pc_nput, ios_fs_pc_nstale;
static unsigned long long ios_fs_pc_m_root, ios_fs_pc_m_key, ios_fs_pc_m_nostamp;
static unsigned long long ios_fs_cs_hit, ios_fs_cs_miss;
/* ml912: where the NtCreateFile/NtOpenFile microseconds actually go */
static unsigned long long ios_fs_open_lk_us, ios_fs_open_lk_n, ios_fs_open_lk_fail;
static unsigned long long ios_fs_open_srv_us, ios_fs_open_srv_n;
static unsigned long long ios_fs_xa_hit, ios_fs_xa_miss, ios_fs_xa_skip, ios_fs_xa_write;
/* ml913: whole-path negative cache */
static unsigned long long ios_fs_np_hit, ios_fs_np_put, ios_fs_np_stale, ios_fs_np_evict;
/* ml915: directory-contents cache.  hit/miss are probes, scan is a table
 * actually built, stale/inval/evict/big are the four ways one dies. */
static unsigned long long ios_fs_dc_hit, ios_fs_dc_miss, ios_fs_dc_scan;
static unsigned long long ios_fs_dc_stale, ios_fs_dc_inval, ios_fs_dc_evict, ios_fs_dc_big;
/* ml915: the whole-path fast path built on the table -- `fast` answered a
 * never-seen-before name in one fstatat, `fexact` short-circuited an open of
 * a file that is there, `fmiss` had no parent resolution or no table yet. */
static unsigned long long ios_fs_dc_fast, ios_fs_dc_fexact, ios_fs_dc_fmiss;
/* live gauges, maintained under ios_dc_lock and read relaxed by the report */
static unsigned int ios_dc_ndirs, ios_dc_nents, ios_dc_bytes;
/* ml915: how many of `lookup`'s microseconds bought a failing open */
static unsigned long long ios_fs_open_lk_fail_us;

static inline unsigned long long ios_fs_now_us(void)
{
    struct timespec ts;
    if (clock_gettime( CLOCK_MONOTONIC, &ts )) return 0;
    return (unsigned long long)ts.tv_sec * 1000000ull + (unsigned long long)ts.tv_nsec / 1000;
}

/* ---- lookup phase timers ------------------------------------------- */
/*
 * ml913: `lookup=1970ms/1190` said the path walk owned 20% of a core but not
 * WHERE.  These phases are DISJOINT and each brackets the narrowest possible
 * region, so what is left over after subtracting them from the measured
 * nt_to_unix_file_name time is genuinely "everything that is not one of
 * these" — malloc, the WCHAR->UTF-8 conversions, the syntax scan, the DOS
 * prefix assembly.  Two clock_gettime() calls per phase; on Darwin that is a
 * commpage read (~20 ns) against syscalls that measure in tens of µs.
 *
 *   prefix  nt_to_unix_file_name_no_root before lookup_unix_name: the DOS
 *           prefix parse, the config_dir/dosdevices assembly, get_dos_device
 *           and the non-drive prefix lstat.
 *   wneg    the whole-path NEGATIVE cache probe and its one validating stat.
 *   wdir    ml915: the parent-resolution probe, its one validating stat and
 *           the two directory-table probes that answer the leaf.
 *   wpath   the whole-path exact-case shortcut stat + the whole-path
 *           POSITIVE cache probe and its validating stat.
 *   exact   find_file_in_dir's per-component exact-case fstatat.
 *   pcache  find_file_in_dir's per-component positive probe + validation.
 *   neg     find_file_in_dir's per-component negative validation stat.
 *   scan    find_file_in_dir's real work: case-sensitivity, openat,
 *           fdopendir, the getdirentries walk, closedir.
 *   reparse lookup_unix_name's `<name>?` handling minus the nested
 *           find_file_in_dir (which lands in the phases above).
 */
enum ios_fs_ph { IOS_PH_PREFIX, IOS_PH_WNEG, IOS_PH_WDIR, IOS_PH_WPATH, IOS_PH_EXACT,
                 IOS_PH_PCACHE, IOS_PH_NEG, IOS_PH_SCAN, IOS_PH_REPARSE, IOS_PH_COUNT };
static const char * const ios_fs_phname[IOS_PH_COUNT] =
    { "prefix", "wneg", "wdir", "wpath", "exact", "pcache", "neg", "scan", "reparse" };
static unsigned long long ios_fs_ph[IOS_PH_COUNT];

static inline void ios_ph_add( int p, unsigned long long t0 )
{
    unsigned long long t1 = ios_fs_now_us();
    IOS_FSA( ios_fs_ph[p], t1 > t0 ? t1 - t0 : 0 );
}

/* ---- syscall counting wrappers ------------------------------------ */
/* Thin, always-inlined, one relaxed add each.  Defined as function-like
 * macros AFTER every system header, so no declaration is ever rewritten. */

static inline int ios_c_fstatat( int fd, const char *p, struct stat *st, int fl )
{ IOS_FSA( ios_fs_sc[IOS_SC_FSTATAT], 1 ); return fstatat( fd, p, st, fl ); }
static inline int ios_c_lstat( const char *p, struct stat *st )
{ IOS_FSA( ios_fs_sc[IOS_SC_LSTAT], 1 ); return lstat( p, st ); }
static inline int ios_c_stat( const char *p, struct stat *st )
{ IOS_FSA( ios_fs_sc[IOS_SC_STAT], 1 ); return stat( p, st ); }
static inline int ios_c_fstat( int fd, struct stat *st )
{ IOS_FSA( ios_fs_sc[IOS_SC_FSTAT], 1 ); return fstat( fd, st ); }
static inline int ios_c_openat( int fd, const char *p, int fl )
{ IOS_FSA( ios_fs_sc[IOS_SC_OPENAT], 1 ); return openat( fd, p, fl ); }
static inline DIR *ios_c_fdopendir( int fd )
{ IOS_FSA( ios_fs_sc[IOS_SC_DIRSCAN], 1 ); return fdopendir( fd ); }
static inline struct dirent *ios_c_readdir( DIR *d )
{ IOS_FSA( ios_fs_sc[IOS_SC_READDIR], 1 ); return readdir( d ); }

#define fstatat(a,b,c,d)  ios_c_fstatat((a),(b),(c),(d))
#define lstat(a,b)        ios_c_lstat((a),(b))
#define stat(a,b)         ios_c_stat((a),(b))
#define fstat(a,b)        ios_c_fstat((a),(b))
#define openat(a,b,c)     ios_c_openat((a),(b),(c))
#define fdopendir(a)      ios_c_fdopendir((a))
#define readdir(a)        ios_c_readdir((a))

#ifdef HAVE_GETATTRLIST
static inline int ios_c_getattrlistat( int fd, const char *p, void *al, void *buf, size_t sz, unsigned long o )
{ IOS_FSA( ios_fs_sc[IOS_SC_GETATTRLISTAT], 1 ); return getattrlistat( fd, p, al, buf, sz, o ); }
static inline int ios_c_getattrlist( const char *p, void *al, void *buf, size_t sz, unsigned long o )
{ IOS_FSA( ios_fs_sc[IOS_SC_GETATTRLIST], 1 ); return getattrlist( p, al, buf, sz, o ); }
#define getattrlistat(a,b,c,d,e,f) ios_c_getattrlistat((a),(b),(c),(d),(e),(f))
#define getattrlist(a,b,c,d,e)     ios_c_getattrlist((a),(b),(c),(d),(e))
#endif

#ifdef __APPLE__
static inline ssize_t ios_c_listxattr( const char *p, char *b, size_t s, int o )
{ IOS_FSA( ios_fs_sc[IOS_SC_LISTXATTR], 1 ); return listxattr( p, b, s, o ); }
static inline ssize_t ios_c_flistxattr( int fd, char *b, size_t s, int o )
{ IOS_FSA( ios_fs_sc[IOS_SC_LISTXATTR], 1 ); return flistxattr( fd, b, s, o ); }
static inline ssize_t ios_c_getxattr( const char *p, const char *n, void *v, size_t s, u_int32_t po, int o )
{ IOS_FSA( ios_fs_sc[IOS_SC_GETXATTR], 1 ); return getxattr( p, n, v, s, po, o ); }
static inline ssize_t ios_c_fgetxattr( int fd, const char *n, void *v, size_t s, u_int32_t po, int o )
{ IOS_FSA( ios_fs_sc[IOS_SC_GETXATTR], 1 ); return fgetxattr( fd, n, v, s, po, o ); }
#define listxattr(a,b,c,d)      ios_c_listxattr((a),(b),(c),(d))
#define flistxattr(a,b,c,d)     ios_c_flistxattr((a),(b),(c),(d))
#define getxattr(a,b,c,d,e,f)   ios_c_getxattr((a),(b),(c),(d),(e),(f))
#define fgetxattr(a,b,c,d,e,f)  ios_c_fgetxattr((a),(b),(c),(d),(e),(f))
#endif

static int ios_np_disabled(void);   /* ml914: defined with the cache below */
static int ios_dc_disabled(void);   /* ml915: defined with the cache below */

/* ---- the 10 s [fs-stats] report ----------------------------------- */

#define IOS_FS_PERIOD_US 10000000ull

static unsigned long long ios_fs_deadline;   /* µs, 0 = not armed yet */
static unsigned long long ios_fs_window_t0;
static int ios_fs_off = -1;                  /* -1 unknown, 1 disabled */

static int ios_fs_disabled(void)
{
    int v = __atomic_load_n( &ios_fs_off, __ATOMIC_RELAXED );
    if (v < 0)
    {
        const char *s = getenv( "MADEIRA_FSSTATS" );
        v = (s && s[0] == '0') ? 1 : 0;
        __atomic_store_n( &ios_fs_off, v, __ATOMIC_RELAXED );
    }
    return v;
}

static unsigned long long ios_fs_delta( unsigned long long cur, unsigned long long *prev )
{
    unsigned long long d = cur - *prev;
    *prev = cur;
    return d;
}

static void ios_fs_report( unsigned long long now )
{
    /* Only ever entered by the single thread that won the deadline CAS, so
     * these "previous window" snapshots need no protection of their own. */
    static unsigned long long p_opn[IOS_OP_COUNT], p_opus[IOS_OP_COUNT], p_sc[IOS_SC_COUNT];
    static unsigned long long p_bytes, p_sync, p_srv, p_pos, p_depth[IOS_FS_DEPTH_MAX + 1];
    static unsigned long long p_exact, p_scan, p_hit, p_miss, p_stale, p_put, p_evict;
    static unsigned long long p_nhit, p_nput, p_nstale, p_mroot, p_mkey, p_mstamp;
    static unsigned long long p_lkus, p_lkn, p_lkfail, p_lkfus, p_srvus, p_srvn;
    static unsigned long long p_dchit, p_dcmiss, p_dcscan, p_dcstale, p_dcinval, p_dcevict, p_dcbig;
    static unsigned long long p_dcfast, p_dcfex, p_dcfmiss;
    static unsigned long long p_cshit, p_csmiss, p_xahit, p_xamiss, p_xaskip, p_xawr;
    static unsigned long long p_ph[IOS_PH_COUNT];
    static unsigned long long p_nphit, p_npput, p_npstale, p_npevict;
    unsigned long long d_lkus, d_srvus, d_lkfail, d_lkfus, d_ph[IOS_PH_COUNT], d_phsum;
    char line[700];
    int i, n = 0;
    unsigned long long win_us = now - ios_fs_window_t0;
    unsigned long long d_opn[IOS_OP_COUNT], d_opus[IOS_OP_COUNT], d_sc[IOS_SC_COUNT];
    unsigned long long d_depth[IOS_FS_DEPTH_MAX + 1];
    unsigned long long d_bytes, d_sync, d_srv, d_pos;

    ios_fs_window_t0 = now;
    if (!win_us) win_us = 1;

#define IOS_D(cur,prev)  (ios_fs_delta( IOS_FSL(cur), &(prev) ))

    for (i = 0; i < IOS_OP_COUNT; i++)
    {
        d_opn[i]  = IOS_D( ios_fs_opn[i],  p_opn[i] );
        d_opus[i] = IOS_D( ios_fs_opus[i], p_opus[i] );
        n += snprintf( line + n, sizeof(line) - n, " %s=%llu/%llu.%03llums",
                       ios_fs_opname[i], d_opn[i], d_opus[i] / 1000, d_opus[i] % 1000 );
    }
    dprintf( 2, "[fs-stats] ml910 %llu.%llus%s\n", win_us / 1000000, (win_us % 1000000) / 100000, line );

    /* ml912: split the open= figure.  lookup = nt_to_unix_file_name (the pure
     * in-process path walk: fstatat/openat/readdir), server = the create_file
     * wineserver round trip that does the real open(); the remainder is
     * NtCreateFile's own bookkeeping.  A failed lookup never reaches the
     * server at all, so `lkfail` says how much of `lookup` bought nothing. */
    d_lkus  = IOS_D( ios_fs_open_lk_us,  p_lkus );
    d_srvus = IOS_D( ios_fs_open_srv_us, p_srvus );
    /* ml915: fail_avg_us is the number the directory-contents cache exists to
     * move -- the mean cost of ONE open that ends in "not found".  Before it,
     * q66 measured 2060 us of that; one fstatat plus a hash probe is ~155. */
    d_lkfail = IOS_D( ios_fs_open_lk_fail,    p_lkfail );
    d_lkfus  = IOS_D( ios_fs_open_lk_fail_us, p_lkfus );
    dprintf( 2, "[fs-stats]   open: lookup=%llu.%03llums/%llu (fail=%llu fail_avg_us=%llu) "
                "server=%llu.%03llums/%llu other=%llu.%03llums\n",
             d_lkus / 1000, d_lkus % 1000, IOS_D( ios_fs_open_lk_n, p_lkn ),
             d_lkfail, d_lkfail ? d_lkfus / d_lkfail : 0,
             d_srvus / 1000, d_srvus % 1000, IOS_D( ios_fs_open_srv_n, p_srvn ),
             (d_opus[IOS_OP_OPEN] + d_opus[IOS_OP_CREATE] > d_lkus + d_srvus
              ? d_opus[IOS_OP_OPEN] + d_opus[IOS_OP_CREATE] - d_lkus - d_srvus : 0) / 1000,
             (d_opus[IOS_OP_OPEN] + d_opus[IOS_OP_CREATE] > d_lkus + d_srvus
              ? d_opus[IOS_OP_OPEN] + d_opus[IOS_OP_CREATE] - d_lkus - d_srvus : 0) % 1000 );

    /* ml913: and inside `lookup`, which phase.  These cover every
     * nt_to_unix_file_name in the process, not only the ones NtCreateFile
     * timed, so the sum can exceed `lookup` slightly; `rest` is what is left
     * of `lookup` after them — conversions, mallocs, the syntax scan. */
    n = 0;
    d_phsum = 0;
    for (i = 0; i < IOS_PH_COUNT; i++)
    {
        d_ph[i] = IOS_D( ios_fs_ph[i], p_ph[i] );
        d_phsum += d_ph[i];
        n += snprintf( line + n, sizeof(line) - n, " %s=%llu.%03llums",
                       ios_fs_phname[i], d_ph[i] / 1000, d_ph[i] % 1000 );
    }
    dprintf( 2, "[fs-stats]   phase:%s rest=%llu.%03llums | wholeneg=%s h%llu/p%llu/s%llu/e%llu\n",
             line, (d_lkus > d_phsum ? d_lkus - d_phsum : 0) / 1000,
             (d_lkus > d_phsum ? d_lkus - d_phsum : 0) % 1000,
             ios_np_disabled() ? "OFF(MADEIRA_FS_NEGCACHE=1 enables)"
                               : "ON(MADEIRA_FS_NEGCACHE=0 disables)",
             IOS_D( ios_fs_np_hit, p_nphit ), IOS_D( ios_fs_np_put, p_npput ),
             IOS_D( ios_fs_np_stale, p_npstale ), IOS_D( ios_fs_np_evict, p_npevict ) );

    /* ml915: dirs/entries/bytes are the LIVE table, the rest are per-window
     * deltas.  scans is how many directories were read end to end in this
     * window; once a directory is in the table that number stays at 0 and
     * hits climb, which is the whole claim this cache makes. */
    dprintf( 2, "[fs-stats]   dircache=%s: dirs=%u entries=%u bytes=%u hits=%llu misses=%llu "
                "scans=%llu evict=%llu stale=%llu inval=%llu big=%llu\n",
             ios_dc_disabled() ? "OFF(MADEIRA_FS_DIRCACHE unset or =1 enables)"
                               : "ON(MADEIRA_FS_DIRCACHE=0 disables)",
             IOS_FSL( ios_dc_ndirs ), IOS_FSL( ios_dc_nents ), IOS_FSL( ios_dc_bytes ),
             IOS_D( ios_fs_dc_hit, p_dchit ), IOS_D( ios_fs_dc_miss, p_dcmiss ),
             IOS_D( ios_fs_dc_scan, p_dcscan ), IOS_D( ios_fs_dc_evict, p_dcevict ),
             IOS_D( ios_fs_dc_stale, p_dcstale ), IOS_D( ios_fs_dc_inval, p_dcinval ),
             IOS_D( ios_fs_dc_big, p_dcbig ) );
    dprintf( 2, "[fs-stats]   dirfast: notfound=%llu exact=%llu nocache=%llu\n",
             IOS_D( ios_fs_dc_fast, p_dcfast ), IOS_D( ios_fs_dc_fexact, p_dcfex ),
             IOS_D( ios_fs_dc_fmiss, p_dcfmiss ) );

    d_bytes = IOS_D( ios_fs_read_bytes, p_bytes );
    d_sync  = IOS_D( ios_fs_read_sync,  p_sync );
    d_srv   = IOS_D( ios_fs_read_srv,   p_srv );
    d_pos   = IOS_D( ios_fs_read_pos,   p_pos );
    dprintf( 2, "[fs-stats]   read: %lluKB avg=%lluB positioned=%llu streamed=%llu srv=%llu\n",
             d_bytes / 1024, d_opn[IOS_OP_READ] ? d_bytes / d_opn[IOS_OP_READ] : 0,
             d_pos, d_sync, d_srv );

    n = 0;
    for (i = 0; i < IOS_SC_COUNT; i++)
    {
        d_sc[i] = IOS_D( ios_fs_sc[i], p_sc[i] );
        n += snprintf( line + n, sizeof(line) - n, " %s=%llu", ios_fs_scname[i], d_sc[i] );
    }
    dprintf( 2, "[fs-stats]   sys:%s\n", line );

    n = 0;
    for (i = 0; i <= IOS_FS_DEPTH_MAX; i++)
    {
        d_depth[i] = IOS_D( ios_fs_depth[i], p_depth[i] );
        n += snprintf( line + n, sizeof(line) - n, "%s%llu", i ? "/" : "", d_depth[i] );
    }
    dprintf( 2, "[fs-stats]   lookup: depth[0..%d+]=%s exact=%llu scan=%llu "
                "pcache=h%llu/m%llu/s%llu/p%llu/e%llu neg=h%llu/p%llu/s%llu "
                "noask=root%llu/key%llu/stamp%llu cs=h%llu/m%llu xattr=h%llu/m%llu/skip%llu/wr%llu\n",
             IOS_FS_DEPTH_MAX, line, IOS_D( ios_fs_exact, p_exact ), IOS_D( ios_fs_scan, p_scan ),
             IOS_D( ios_fs_pc_hit, p_hit ), IOS_D( ios_fs_pc_miss, p_miss ), IOS_D( ios_fs_pc_stale, p_stale ),
             IOS_D( ios_fs_pc_put, p_put ), IOS_D( ios_fs_pc_evict, p_evict ),
             IOS_D( ios_fs_pc_nhit, p_nhit ), IOS_D( ios_fs_pc_nput, p_nput ),
             IOS_D( ios_fs_pc_nstale, p_nstale ),
             IOS_D( ios_fs_pc_m_root, p_mroot ), IOS_D( ios_fs_pc_m_key, p_mkey ),
             IOS_D( ios_fs_pc_m_nostamp, p_mstamp ),
             IOS_D( ios_fs_cs_hit, p_cshit ), IOS_D( ios_fs_cs_miss, p_csmiss ),
             IOS_D( ios_fs_xa_hit, p_xahit ), IOS_D( ios_fs_xa_miss, p_xamiss ),
             IOS_D( ios_fs_xa_skip, p_xaskip ), IOS_D( ios_fs_xa_write, p_xawr ) );
#undef IOS_D
}

/* Piggy-backed on every instrumented NT entry point; one relaxed load in the
 * common case, one CAS per window for the thread that gets to print. */
static void ios_fs_note( int op, unsigned long long t0, unsigned long long t1 )
{
    unsigned long long due;

    if (ios_fs_disabled()) return;
    IOS_FSA( ios_fs_opn[op], 1 );
    IOS_FSA( ios_fs_opus[op], t1 > t0 ? t1 - t0 : 0 );

    due = __atomic_load_n( &ios_fs_deadline, __ATOMIC_RELAXED );
    if (!due)
    {
        unsigned long long zero = 0;
        if (__atomic_compare_exchange_n( &ios_fs_deadline, &zero, t1 + IOS_FS_PERIOD_US, 0,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
            ios_fs_window_t0 = t1;
        return;
    }
    if (t1 < due) return;
    if (!__atomic_compare_exchange_n( &ios_fs_deadline, &due, t1 + IOS_FS_PERIOD_US, 0,
                                      __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
        return;                                  /* somebody else is printing this window */
    ios_fs_report( t1 );
}

/* ---- resolved-name cache ------------------------------------------ */
/*
 * key   = "<absolute parent unix path>/<ASCII case-folded requested name>"
 *         where <requested name> is either one component (find_file_in_dir)
 *         or the whole remaining path with '\' already turned into '/'
 *         (lookup_unix_name).
 * value = the on-disk spelling that upstream's readdir scan resolved to.
 *
 * Only populated for root_fd == AT_FDCWD, i.e. the absolute-path lookups
 * that every DOS drive path takes; a relative lookup against an open
 * directory handle would need the fd's identity in the key and fds get
 * recycled, so those keep the upstream path unchanged.
 *
 * Correctness: a hit is only ever believed after fstatat() confirms the
 * cached name still exists, and the cache is only populated when the
 * exact-case attempt FAILED, so an exact-case file created later still wins
 * (upstream's shortcut runs first and we never get asked).  The one thing a
 * stale entry can do is name a file that a case-only rename recreated under
 * a different spelling — but a rename removes the old name, so the fstatat
 * fails and we fall through to the upstream scan.  Two files that differ
 * only in case remain resolved in readdir order, exactly as upstream.
 */
/* Direct-mapped and hard-bounded: 8192 buckets, one entry each, key and
 * value malloc'd, so the table itself is ~200 KB and a fully populated
 * cache ~2 MB.  A collision replaces (the [fs-stats] `e` counter reports
 * the eviction rate, so the size can be tuned from a real run). */
#define IOS_PC_BUCKETS 8192                    /* power of two */
#define IOS_PC_KEYMAX  512
#define IOS_PC_VALMAX  384

/*
 * ml912: NEGATIVE entries.  The l39 device log says the positive half of this
 * cache was solving the wrong problem: in 10 s the game did 8347 opens, EVERY
 * one of them ended on a component that does not exist, and the two directory
 * scans each of those costs (the name itself, then upstream's `<name>?`
 * reparse probe) were 16665 openat + 16665 fdopendir + 303415 readdir.  A
 * readdir scan that finds nothing is exactly the case the positive cache
 * cannot represent, which is why `p` was 0: ios_pc_put() only ever runs on a
 * scan that matched, and no scan in that window matched.
 *
 * A negative entry records "directory D contained no case-insensitive match
 * for N", stamped with D's (dev, ino, mtime).  Adding or removing an entry
 * updates a directory's mtime on APFS, so one fstatat() of D re-validates the
 * whole answer: ~20 syscalls become 1.  The stamp is taken BEFORE the scan
 * starts, never after — if the directory gains an entry mid-scan we may miss
 * it, but then the stored mtime is already older than the live one and the
 * next lookup falls through and rescans.  Same-second coarse mtimes are not a
 * hazard here because we compare the nanosecond field too.
 */
struct ios_pc_neg
{
    dev_t dev;
    ino_t ino;
    long long mtime;                           /* ns; 0 = not a negative entry */
};

struct ios_pc_ent
{
    unsigned long long hash;                   /* 0 = empty */
    char *key;
    char *val;                                 /* NULL = negative entry */
    struct ios_pc_neg neg;
};
static struct ios_pc_ent ios_pc[IOS_PC_BUCKETS];
static pthread_mutex_t ios_pc_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long long ios_fnv( const char *s, size_t len )
{
    unsigned long long h = 14695981039346656037ull;
    size_t i;
    for (i = 0; i < len; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ull; }
    return h ? h : 1;
}

/* copy src[0..len) into dst, ASCII-lowercasing from index `fold_from` on */
static int ios_pc_key( char *dst, size_t dstsize, const char *src, size_t len, size_t fold_from )
{
    size_t i;
    if (len + 1 > dstsize) return 0;
    for (i = 0; i < len; i++)
    {
        char c = src[i];
        if (i >= fold_from && c >= 'A' && c <= 'Z') c += 'a' - 'A';
        dst[i] = c;
    }
    dst[len] = 0;
    return 1;
}

/* 0 = miss, 1 = positive hit (out filled), 2 = negative hit (neg filled) */
static int ios_pc_lookup( const char *key, char *out, size_t outsize, struct ios_pc_neg *neg )
{
    unsigned long long h = ios_fnv( key, strlen(key) );
    struct ios_pc_ent *e = &ios_pc[h & (IOS_PC_BUCKETS - 1)];
    int found = 0;

    mutex_lock( &ios_pc_lock );
    if (e->hash == h && e->key && !strcmp( e->key, key ))
    {
        if (!e->val)
        {
            *neg = e->neg;
            found = 2;
        }
        else if (strlen(e->val) < outsize)
        {
            memcpy( out, e->val, strlen(e->val) + 1 );
            found = 1;
        }
    }
    mutex_unlock( &ios_pc_lock );
    return found;
}

static int ios_pc_get( const char *key, char *out, size_t outsize )
{
    struct ios_pc_neg dummy;
    return ios_pc_lookup( key, out, outsize, &dummy ) == 1;
}

/* val != NULL: the on-disk spelling.  val == NULL: a negative entry stamped
 * with *neg (the parent directory's identity and mtime at scan time). */
static void ios_pc_store( const char *key, const char *val, const struct ios_pc_neg *neg )
{
    unsigned long long h = ios_fnv( key, strlen(key) );
    struct ios_pc_ent *e = &ios_pc[h & (IOS_PC_BUCKETS - 1)];
    size_t klen = strlen(key), vlen = val ? strlen(val) : 0;
    char *k, *v = NULL;

    if (val && (!vlen || vlen >= IOS_PC_VALMAX)) return;
    if (!(k = malloc( klen + 1 ))) return;
    if (val && !(v = malloc( vlen + 1 ))) { free( k ); return; }
    memcpy( k, key, klen + 1 );
    if (val) memcpy( v, val, vlen + 1 );

    mutex_lock( &ios_pc_lock );
    if (e->hash && (e->hash != h || !e->key || strcmp( e->key, key ))) IOS_FSA( ios_fs_pc_evict, 1 );
    free( e->key );
    free( e->val );
    e->key = k;
    e->val = v;
    if (neg) e->neg = *neg;
    else memset( &e->neg, 0, sizeof(e->neg) );
    e->hash = h;
    mutex_unlock( &ios_pc_lock );
    if (val) IOS_FSA( ios_fs_pc_put, 1 );
    else IOS_FSA( ios_fs_pc_nput, 1 );
}

static void ios_pc_put( const char *key, const char *val )
{
    ios_pc_store( key, val, NULL );
}

/* ---- whole-path negative cache ------------------------------------- */
/*
 * ml913: the per-component negative cache (above) removed the directory
 * SCANS, and the l41 log proves it: dirscan 548 -> 8, readdir 300k -> 2k.
 * What it could not remove is the walk itself.  A failing open still cost
 * 10.6 fstatat — one whole-path shortcut, one exact-case stat per existing
 * component, then, for BOTH the leaf and upstream's `<leaf>?` reparse probe,
 * an exact-case stat plus a negative-entry validation stat.  At ~155 µs per
 * fstatat in this sandbox (see the report below) that is the entire 1.67 ms.
 *
 * So cache the whole answer, not the pieces.  Key = the full unix path in
 * the EXACT spelling the caller asked for (the NT path after DOS-prefix and
 * WoW64 redirection).  ml914: this key used to be case-FOLDED, on the theory
 * that two NT spellings of one file could share an entry.  They cannot: the
 * resolver prefers the exact case at every component, so on a case-sensitive
 * volume "Foo/bar" and "foo/bar" are allowed to be different files and a
 * folded key hands one's absence to the other -- NOT_FOUND for a file that
 * exists.  Programs repeat their own spelling, so the hit rate is unchanged.
 * Value = the
 * resolved path of the DEEPEST DIRECTORY THAT DOES EXIST plus its identity
 * and nanosecond mtime, and the status the walk produced:
 *
 *   STATUS_OBJECT_NAME_NOT_FOUND   the parent exists, the leaf does not
 *   STATUS_OBJECT_PATH_NOT_FOUND   an intermediate component is missing
 *
 * One fstatat() of that directory re-validates the whole absence: creating,
 * renaming or linking anything into a directory bumps its mtime on APFS, so
 * the first component that was missing cannot appear without the stamp
 * changing.  Statting BY PATH (not by a remembered fd) also covers any
 * ancestor being replaced: the path then resolves to a different inode, or
 * not at all, and the entry is rejected.
 *
 * Two guards on when an entry may be used:
 *   - NAME_NOT_FOUND is disposition-dependent (FILE_CREATE/OPEN_IF want the
 *     constructed unix name back with STATUS_NO_SUCH_FILE), so it is only
 *     honoured for FILE_OPEN/FILE_OVERWRITE.  PATH_NOT_FOUND is returned for
 *     every disposition, exactly as the walk would.  (A create disposition
 *     never RECORDS a NAME_NOT_FOUND either: the walk turns it into
 *     STATUS_NO_SUCH_FILE before the record site sees it.)
 *   - open_reparse changes what the `<leaf>?` probe does with a match, so
 *     entries are neither recorded nor used for it.
 *   - the stamp must have been read BEFORE the work that proved the name
 *     absent; see ios_dir_stamp_ok below.
 *
 * ml915: this cache is now ON by default and MADEIRA_FS_NEGCACHE=0 turns it
 * off (it was default-off while it was unproven; it has since passed the
 * fs-x86.exe host model and phases 1-6 on device).  With the
 * directory-contents cache below doing the heavy lifting it is no longer the
 * main win, but a repeated probe of the same absent path is still answered
 * here without even reaching find_file_in_dir, so it stays as cheap
 * insurance.  With it off, the other caches are untouched.
 *
 * Sizing: a title probing package paths across many directories generates
 * thousands of distinct misses, and unlike the positive cache EVERY miss is
 * cacheable.  16384 direct-mapped buckets, 48 bytes each (768 KB resident),
 * key and directory in one malloc so a bucket is one allocation; a collision
 * replaces and bumps `e`, same discipline as ios_pc.
 */
#define IOS_NP_BUCKETS 16384                   /* power of two */

struct ios_np_ent
{
    unsigned long long hash;                   /* 0 = empty */
    char *mem;                                 /* "<folded full path>\0<deepest existing dir>\0" */
    unsigned int dir_off;                      /* offset of the directory string in mem */
    unsigned int status;
    struct ios_pc_neg dir;                     /* that directory's dev/ino/ns-mtime */
};
static struct ios_np_ent ios_np[IOS_NP_BUCKETS];
static pthread_mutex_t ios_np_lock = PTHREAD_MUTEX_INITIALIZER;

/* 1 = found; *dir gets the directory path to validate, *st its stamp */
static int ios_np_get( const char *key, char *dir, size_t dirsize,
                       struct ios_pc_neg *st, unsigned int *status )
{
    unsigned long long h = ios_fnv( key, strlen(key) );
    struct ios_np_ent *e = &ios_np[h & (IOS_NP_BUCKETS - 1)];
    int found = 0;

    mutex_lock( &ios_np_lock );
    if (e->hash == h && e->mem && !strcmp( e->mem, key ))
    {
        const char *d = e->mem + e->dir_off;
        size_t dlen = strlen( d );
        if (dlen < dirsize)
        {
            memcpy( dir, d, dlen + 1 );
            *st = e->dir;
            *status = e->status;
            found = 1;
        }
    }
    mutex_unlock( &ios_np_lock );
    return found;
}

static void ios_np_put( const char *key, const char *dir,
                        const struct ios_pc_neg *st, unsigned int status )
{
    unsigned long long h;
    struct ios_np_ent *e;
    size_t klen = strlen( key ), dlen = strlen( dir );
    char *mem;

    if (!st->mtime || !dlen || klen >= IOS_PC_KEYMAX || dlen >= IOS_PC_KEYMAX) return;
    if (!(mem = malloc( klen + dlen + 2 ))) return;
    memcpy( mem, key, klen + 1 );
    memcpy( mem + klen + 1, dir, dlen + 1 );

    h = ios_fnv( key, klen );
    e = &ios_np[h & (IOS_NP_BUCKETS - 1)];
    mutex_lock( &ios_np_lock );
    if (e->hash && (e->hash != h || !e->mem || strcmp( e->mem, key ))) IOS_FSA( ios_fs_np_evict, 1 );
    free( e->mem );
    e->mem = mem;
    e->dir_off = (unsigned int)(klen + 1);
    e->status = status;
    e->dir = *st;
    e->hash = h;
    mutex_unlock( &ios_np_lock );
    IOS_FSA( ios_fs_np_put, 1 );
}

/* ml914: the first IOS_NP_LOG DISTINCT keys a whole-path negative entry
 * actually denied, one line each, so a device log shows WHAT was reported
 * missing rather than only how often.  Printed under the same enablement as
 * [fs-stats], and only when the cache is on. */
#define IOS_NP_LOG 16
static char *ios_np_logged[IOS_NP_LOG];
static int ios_np_logged_n;

static void ios_np_log_hit( const char *key, const char *dir )
{
    int i, take = 0;
    char *copy;

    if (__atomic_load_n( &ios_np_logged_n, __ATOMIC_RELAXED ) >= IOS_NP_LOG) return;
    if (!(copy = malloc( strlen( key ) + 1 ))) return;
    strcpy( copy, key );

    mutex_lock( &ios_np_lock );
    if (ios_np_logged_n < IOS_NP_LOG)
    {
        take = 1;
        for (i = 0; i < ios_np_logged_n; i++)
            if (!strcmp( ios_np_logged[i], key )) { take = 0; break; }
        if (take) ios_np_logged[ios_np_logged_n++] = copy;
    }
    mutex_unlock( &ios_np_lock );

    if (!take) { free( copy ); return; }
    dprintf( 2, "[fs-neg] hit key=%s stamp_dir=%s\n", key, dir );
}

/* ml913: set by find_file_in_dir whenever it learns the identity and mtime of
 * the directory it was asked to search, and consumed by lookup_unix_name when
 * it records a whole-path negative entry — so recording one normally costs no
 * syscall of its own.  Cleared on entry to find_file_in_dir, so a stale value
 * from an earlier component can never be attributed to a later one.
 *
 * ml914 correctness rule: a whole-path negative entry may only ever be
 * stamped with a directory mtime that was read BEFORE the work that proved
 * the name absent.  Then any create/rename/link landing in that directory
 * after the read necessarily gives it a different mtime and the entry is
 * rejected; one landing before it is seen by the (case-insensitive) scan
 * that follows, so no entry is recorded at all.  ios_dir_stamp_ok says
 * whether the stamp currently held satisfies that rule: it is set only at
 * the pre-scan fstat() and at a per-component negative entry's successful
 * revalidation (where the proof and the stamp are the same syscall), never
 * on the plain "we happened to stat this directory" paths. */
static __thread struct ios_pc_neg ios_dir_stamp;
static __thread int ios_dir_stamp_ok;

/* ml914: MADEIRA_FS_NEGCACHE gates the whole-path negative cache and only
 * that one -- the per-directory case memo, the per-component resolved-name/
 * negative cache and the directory-contents cache are unaffected either way.
 * ml915: DEFAULT ON: =0 disables, unset or =1 enables.  [fs-stats] prints
 * which. */
static int ios_np_off_mode = -1;

static int ios_np_disabled(void)
{
    int v = __atomic_load_n( &ios_np_off_mode, __ATOMIC_RELAXED );
    if (v < 0)
    {
        const char *s = getenv( "MADEIRA_FS_NEGCACHE" );
        v = (s && s[0] == '0') ? 1 : 0;
        __atomic_store_n( &ios_np_off_mode, v, __ATOMIC_RELAXED );
    }
    return v;
}

/* ---- get_dir_case_sensitivity memo --------------------------------- */
/*
 * One 64-bit word per slot: (tag << 2) | 2 | answer, 0 = empty.  A single
 * relaxed load/store, so readers can never see a torn entry and no lock is
 * needed.  Keyed by (root_fd, directory path) rather than by st_dev because
 * we have the path for free and no stat at all: upstream burns a
 * getattrlistat on EVERY call just to re-derive the FSID before consulting
 * its own per-device cache, and that is the 5-9% getattrlistat in [prof].
 * A path's volume can only change by (un)mounting, which cannot happen
 * inside the app container.
 */
#define IOS_CS_SLOTS 512
static unsigned long long ios_cs_memo[IOS_CS_SLOTS];

/* ---- DOS-attribute / reparse xattr memo ----------------------------- */
/*
 * get_file_info()/fd_get_file_info() ask for two named xattrs on every
 * attribute query, and on macOS/iOS each xattr_get() first does a
 * listxattr() ("faster than getxattr", upstream) — so two syscalls per
 * query for files that, here, essentially never carry either attribute.
 *
 * Two changes: ONE listxattr answers both names, and its answer is memoised
 * per (dev, ino, ctime).  Setting or removing an xattr bumps ctime on APFS,
 * so the memo self-invalidates; an inode recycled with a bit-identical
 * nanosecond ctime is the only false hit and cannot be constructed in
 * practice.  MADEIRA_FS_NOXATTR=1 additionally skips the listxattr outright
 * until something in this process writes one of the two attributes — a
 * measurement knob, off by default, because xattrs written by an EARLIER
 * run would be invisible to it.
 */
#define IOS_XA_SLOTS 1024
#define IOS_XA_REPARSE 1
#define IOS_XA_DOSATTR 2
struct ios_xa_ent { dev_t dev; ino_t ino; long long ctime; int bits; };
static struct ios_xa_ent ios_xa_memo[IOS_XA_SLOTS];
static pthread_mutex_t ios_xa_lock = PTHREAD_MUTEX_INITIALIZER;
static int ios_xa_written;        /* something set one of our xattrs this run */
static int ios_xa_skip_mode = -1;

static long long ios_stat_ctime( const struct stat *st )
{
    long long v = (long long)st->st_ctime * 1000000000ll;
#ifdef HAVE_STRUCT_STAT_ST_CTIM
    v += st->st_ctim.tv_nsec;
#elif defined(HAVE_STRUCT_STAT_ST_CTIMESPEC)
    v += st->st_ctimespec.tv_nsec;
#endif
    return v;
}

/* ml912: nanosecond mtime, the stamp a negative cache entry is validated
 * against.  Never 0 for a real directory, so 0 doubles as "no stamp". */
static long long ios_stat_mtime( const struct stat *st )
{
    long long v = (long long)st->st_mtime * 1000000000ll;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
    v += st->st_mtim.tv_nsec;
#elif defined(HAVE_STRUCT_STAT_ST_MTIMESPEC)
    v += st->st_mtimespec.tv_nsec;
#endif
    return v ? v : 1;
}

/* ---- directory-contents cache -------------------------------------- */
/*
 * ml915: the two negative caches above answer "this NAME is not there", one
 * entry per name.  The q66 device log says that is the wrong shape for what a
 * 32-bit UE3 title does while it loads a level: ~4800 FAILING opens per 10 s,
 * 9.9 s of every 10 s spent inside lookup_unix_name, ~2.06 ms per failing
 * lookup -- and the names are almost all DISTINCT (an engine probing
 * localised and variant package spellings: <pkg>_INT.upk, <pkg>_LOC_INT.upk,
 * <pkg>.xxx, one set per language directory).  A per-NAME entry is written
 * once and never read again, so essentially every probe still paid a full
 * case-insensitive scan of a directory holding thousands of entries.
 *
 * So cache the DIRECTORY, not the name.  The first scan of a directory is
 * read into an in-memory table -- the exact on-disk spellings plus a hash of
 * each name's case-folded UTF-16 form -- keyed by the directory's (dev, ino)
 * and stamped with its nanosecond mtime AND ctime.  After that, ANY name in
 * that directory, present or absent, is answered by one fstatat of the
 * directory (to re-validate the stamp) plus a hash probe.  4800 distinct
 * misses cost 4800 fstatat instead of 4800 getdirentries walks.
 *
 * Semantics are upstream's, unchanged:
 *   - the exact-case fstatat at the top of find_file_in_dir still runs first
 *     and still wins, so a file whose spelling the caller got right is never
 *     resolved through here;
 *   - the table is only consulted where upstream would have scanned, i.e.
 *     AFTER the is_legal_8dot3_name and get_dir_case_sensitivity gates;
 *   - a candidate is confirmed with a real wcsnicmp against the stored
 *     spelling, and the hash is taken over ntdll_towupper() of the same
 *     UTF-16 form that wcsnicmp folds, so equal-under-wcsnicmp implies equal
 *     hash: an empty probe really does mean "nothing in this directory
 *     matches", which is what makes a miss sound;
 *   - entries are kept in readdir order and the LOWEST-indexed match wins,
 *     which is the entry upstream's loop would have stopped on, so two files
 *     differing only in case resolve exactly as they do today;
 *   - 8.3 short-name lookups bypass the table.  They interleave a second
 *     match rule (hash_short_file_name) with the first inside one readdir
 *     pass, and on this platform they are vanishingly rare anyway (no
 *     VFAT_IOCTL_READDIR_BOTH, so the name must be >= 8 chars with '~' at
 *     index 4).  Such a lookup still BUILDS the table for everyone else.
 *
 * Invalidation is the stamp.  Creating, renaming, linking or unlinking a name
 * in a directory moves its mtime and its ctime on APFS, so the next probe
 * sees a different stamp, drops the table and rescans.  The stamp is always
 * read from the directory fd BEFORE the getdirentries walk, so a change that
 * lands during the scan can only make the table look stale -- never the other
 * way round.  That is the same rule ios_pc's negative entries and ios_np
 * follow (see ios_dir_stamp_ok).  Because a timestamp cannot be relied on to
 * advance WITHIN one clock tick, the create paths in this process also drop
 * the table for the directory they wrote into, by path
 * (ios_dc_invalidate_path from NtCreateFile/NtDeleteFile/rename/link), so a
 * create-then-open in the same tick can never read a table older than the
 * create.
 *
 * Bounds: at most 64 directories and 4 MB in total; at most 1 MB and 65536
 * names for a single directory (a bigger one is scanned and simply not
 * cached).  When a new table does not fit, tables are dropped least-recently-
 * used first to get under the directory count and largest-first to get under
 * the byte budget, so one huge directory cannot hold the budget hostage.  A
 * 3000-entry directory costs ~40 bytes per name, ~120 KB.
 *
 * Concurrency: one mutex over the whole table, taken for the probe and for
 * the install, exactly as ios_pc/ios_np do.  A probe copies the spelling out
 * under the lock, so no entry can be freed while a caller still points at it;
 * the scan that builds a table runs entirely outside the lock.
 *
 * MADEIRA_FS_DIRCACHE=0 disables it; unset or =1 enables.
 */
#define IOS_DC_MAX_DIRS      64
#define IOS_DC_MAX_BYTES     (4u * 1024 * 1024)
#define IOS_DC_MAX_DIR_BYTES (1u * 1024 * 1024)
#define IOS_DC_MAX_NAMES     65536u
#define IOS_DC_NOIDX         (~0u)

struct ios_dc_stamp
{
    dev_t dev;
    ino_t ino;
    long long mtime;                           /* ns; 0 = no usable stamp */
    long long ctime;                           /* ns */
};

struct ios_dc_ent
{
    unsigned int hash;                         /* over ntdll_towupper of the UTF-16 form */
    unsigned int off;                          /* byte offset into ->names */
    unsigned int wlen;                         /* what ntdll_umbstowcs returned */
};

struct ios_dc_dir
{
    struct ios_dc_stamp st;                    /* st.mtime == 0 => slot unused */
    struct ios_dc_ent *ents;                   /* readdir order */
    unsigned int *slots;                       /* open-addressed ents indices */
    char *names;                               /* NUL-terminated d_names */
    char *path;                                /* absolute unix path, or NULL */
    unsigned int n, nslots, names_len, bytes;
    unsigned long long lru;
};

static struct ios_dc_dir ios_dc[IOS_DC_MAX_DIRS];
static pthread_mutex_t ios_dc_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long ios_dc_clock;
static int ios_dc_off_mode = -1;

static int ios_dc_disabled(void)
{
    int v = __atomic_load_n( &ios_dc_off_mode, __ATOMIC_RELAXED );
    if (v < 0)
    {
        const char *s = getenv( "MADEIRA_FS_DIRCACHE" );
        v = (s && s[0] == '0') ? 1 : 0;
        __atomic_store_n( &ios_dc_off_mode, v, __ATOMIC_RELAXED );
    }
    return v;
}

static void ios_dc_stamp_of( struct ios_dc_stamp *st, const struct stat *s )
{
    st->dev = s->st_dev;
    st->ino = s->st_ino;
    st->mtime = S_ISDIR( s->st_mode ) ? ios_stat_mtime( s ) : 0;
    st->ctime = ios_stat_ctime( s );
}

/* FNV-1a over the case-folded UTF-16 form.  MUST fold with the same function
 * ntdll_wcsnicmp() does, or a name that compares equal could hash elsewhere
 * and a miss would be a lie. */
static unsigned int ios_dc_hash( const WCHAR *w, unsigned int len )
{
    unsigned int h = 2166136261u, i;

    for (i = 0; i < len; i++)
    {
        h ^= (unsigned int)ntdll_towupper( w[i] );
        h *= 16777619u;
    }
    return h;
}

/* both callers hold ios_dc_lock */
static void ios_dc_drop( unsigned int i )
{
    struct ios_dc_dir *d = &ios_dc[i];

    if (!d->st.mtime) return;
    ios_dc_bytes -= d->bytes;
    ios_dc_nents -= d->n;
    ios_dc_ndirs--;
    free( d->ents );
    free( d->slots );
    free( d->names );
    free( d->path );
    memset( d, 0, sizeof(*d) );
}

/* by_size = 0: least recently used.  by_size = 1: largest. */
static unsigned int ios_dc_victim( int by_size )
{
    unsigned int i, best = IOS_DC_MAX_DIRS;

    for (i = 0; i < IOS_DC_MAX_DIRS; i++)
    {
        if (!ios_dc[i].st.mtime) continue;
        if (best == IOS_DC_MAX_DIRS) best = i;
        else if (by_size ? (ios_dc[i].bytes > ios_dc[best].bytes)
                         : (ios_dc[i].lru < ios_dc[best].lru)) best = i;
    }
    return best;
}

/* takes ownership of *nd; frees its buffers if there is no room for it */
static void ios_dc_install( struct ios_dc_dir *nd )
{
    unsigned int i, v, slot = IOS_DC_MAX_DIRS;

    mutex_lock( &ios_dc_lock );

    for (i = 0; i < IOS_DC_MAX_DIRS; i++)               /* replace our own older table */
        if (ios_dc[i].st.mtime && ios_dc[i].st.dev == nd->st.dev &&
            ios_dc[i].st.ino == nd->st.ino) { ios_dc_drop( i ); break; }

    while (ios_dc_ndirs >= IOS_DC_MAX_DIRS)
    {
        if ((v = ios_dc_victim( 0 )) >= IOS_DC_MAX_DIRS) break;
        ios_dc_drop( v );
        IOS_FSA( ios_fs_dc_evict, 1 );
    }
    while (ios_dc_bytes + nd->bytes > IOS_DC_MAX_BYTES)
    {
        if ((v = ios_dc_victim( 1 )) >= IOS_DC_MAX_DIRS) break;
        ios_dc_drop( v );
        IOS_FSA( ios_fs_dc_evict, 1 );
    }
    if (ios_dc_ndirs < IOS_DC_MAX_DIRS && ios_dc_bytes + nd->bytes <= IOS_DC_MAX_BYTES)
        for (i = 0; i < IOS_DC_MAX_DIRS; i++) if (!ios_dc[i].st.mtime) { slot = i; break; }

    if (slot < IOS_DC_MAX_DIRS)
    {
        ios_dc[slot] = *nd;
        ios_dc[slot].lru = ++ios_dc_clock;
        ios_dc_bytes += nd->bytes;
        ios_dc_nents += nd->n;
        ios_dc_ndirs++;
        memset( nd, 0, sizeof(*nd) );
    }
    mutex_unlock( &ios_dc_lock );

    free( nd->ents );
    free( nd->slots );
    free( nd->names );
    free( nd->path );
    memset( nd, 0, sizeof(*nd) );
}

/*  2 = a match whose BYTES are exactly `exact` (only asked for when non-NULL)
 *  1 = the directory is cached and holds a match (spelling copied to `out`)
 *  0 = the directory is cached and holds NO match: the name is absent
 * -1 = nothing usable is cached: the caller must scan
 *
 * `exact` exists because this resolver prefers the caller's own spelling over
 * readdir order at every component: a caller that needs to act on a match
 * rather than merely rule one out has to know which of the two it got. */
static int ios_dc_lookup( const struct ios_dc_stamp *st, const WCHAR *name, unsigned int length,
                          const char *exact, char *out, size_t outsize )
{
    WCHAR wbuf[MAX_DIR_ENTRY_LEN];
    struct ios_dc_dir *d = NULL;
    unsigned int i, h, slot, idx, best = IOS_DC_NOIDX;
    int ret = -1, found_exact = 0;

    if (!st->mtime) return -1;
    h = ios_dc_hash( name, length );

    mutex_lock( &ios_dc_lock );
    for (i = 0; i < IOS_DC_MAX_DIRS; i++)
        if (ios_dc[i].st.mtime && ios_dc[i].st.dev == st->dev && ios_dc[i].st.ino == st->ino)
        { d = &ios_dc[i]; break; }

    if (!d)
    {
        mutex_unlock( &ios_dc_lock );
        IOS_FSA( ios_fs_dc_miss, 1 );
        return -1;
    }
    if (d->st.mtime != st->mtime || d->st.ctime != st->ctime)
    {
        /* something was created, renamed or removed in there: the whole table
         * is worthless, and keeping it would only delay the rescan. */
        ios_dc_drop( i );
        mutex_unlock( &ios_dc_lock );
        IOS_FSA( ios_fs_dc_stale, 1 );
        IOS_FSA( ios_fs_dc_miss, 1 );
        return -1;
    }

    d->lru = ++ios_dc_clock;
    for (slot = h & (d->nslots - 1); (idx = d->slots[slot]) != IOS_DC_NOIDX;
         slot = (slot + 1) & (d->nslots - 1))
    {
        const struct ios_dc_ent *e = &d->ents[idx];
        const char *nm;

        if (e->hash != h || e->wlen != length) continue;
        nm = d->names + e->off;
        if ((unsigned int)ntdll_umbstowcs( nm, strlen(nm), wbuf, MAX_DIR_ENTRY_LEN ) != length) continue;
        if (wcsnicmp( wbuf, name, length )) continue;
        if (exact && !strcmp( nm, exact )) found_exact = 1;
        if (idx < best) best = idx;             /* readdir order: lowest wins */
    }

    if (best == IOS_DC_NOIDX) ret = 0;
    else
    {
        const char *s = d->names + d->ents[best].off;
        size_t len = strlen( s );
        if (len < outsize) { memcpy( out, s, len + 1 ); ret = found_exact ? 2 : 1; }
    }
    mutex_unlock( &ios_dc_lock );
    IOS_FSA( ios_fs_dc_hit, 1 );
    return ret;
}

/* ---- building one, from the scan find_file_in_dir was going to do anyway -- */

struct ios_dc_build
{
    struct ios_dc_ent *ents;
    char *names;
    unsigned int n, cap, names_len, names_cap;
    int failed;
};

/* `w`/`wlen` are exactly what the caller's own ntdll_umbstowcs() produced for
 * this entry, so the table can never disagree with the live scan. */
static void ios_dc_build_add( struct ios_dc_build *b, const char *name, const WCHAR *w, unsigned int wlen )
{
    size_t nlen = strlen( name );

    if (b->failed) return;
    if (b->n >= IOS_DC_MAX_NAMES) { b->failed = 1; IOS_FSA( ios_fs_dc_big, 1 ); return; }
    if (b->n == b->cap)
    {
        unsigned int cap = b->cap ? b->cap * 2 : 256;
        struct ios_dc_ent *p = realloc( b->ents, cap * sizeof(*p) );
        if (!p) { b->failed = 1; return; }
        b->ents = p;
        b->cap = cap;
    }
    if (b->names_len + nlen + 1 > b->names_cap)
    {
        unsigned int cap = b->names_cap ? b->names_cap : 4096;
        char *p;
        while (cap < b->names_len + nlen + 1) cap *= 2;
        if (!(p = realloc( b->names, cap ))) { b->failed = 1; return; }
        b->names = p;
        b->names_cap = cap;
    }
    b->ents[b->n].hash = ios_dc_hash( w, wlen );
    b->ents[b->n].off  = b->names_len;
    b->ents[b->n].wlen = wlen;
    b->n++;
    memcpy( b->names + b->names_len, name, nlen + 1 );
    b->names_len += (unsigned int)(nlen + 1);
    if (b->names_len + b->n * (unsigned int)sizeof(struct ios_dc_ent) > IOS_DC_MAX_DIR_BYTES)
    {
        b->failed = 1;                          /* too big to be worth 1/4 of the budget */
        IOS_FSA( ios_fs_dc_big, 1 );
    }
}

static void ios_dc_build_abort( struct ios_dc_build *b )
{
    free( b->ents );
    free( b->names );
    memset( b, 0, sizeof(*b) );
}

static void ios_dc_build_finish( struct ios_dc_build *b, const struct ios_dc_stamp *st, const char *path )
{
    struct ios_dc_dir nd;
    unsigned int nslots = 8, i;

    if (b->failed || !st->mtime) { ios_dc_build_abort( b ); return; }

    while (nslots < b->n * 2) nslots *= 2;      /* load factor <= 1/2 => a probe always terminates */
    memset( &nd, 0, sizeof(nd) );
    if (!(nd.slots = malloc( nslots * sizeof(unsigned int) ))) { ios_dc_build_abort( b ); return; }
    memset( nd.slots, 0xff, nslots * sizeof(unsigned int) );
    for (i = 0; i < b->n; i++)
    {
        unsigned int s = b->ents[i].hash & (nslots - 1);
        while (nd.slots[s] != IOS_DC_NOIDX) s = (s + 1) & (nslots - 1);
        nd.slots[s] = i;
    }
    nd.st = *st;
    nd.ents = b->ents;
    nd.names = b->names;
    nd.n = b->n;
    nd.nslots = nslots;
    nd.names_len = b->names_len;
    if (path && (nd.path = malloc( strlen( path ) + 1 ))) strcpy( nd.path, path );
    nd.bytes = (unsigned int)(b->n * sizeof(struct ios_dc_ent) + nslots * sizeof(unsigned int) +
                              b->names_len + (nd.path ? strlen( nd.path ) + 1 : 0) + sizeof(nd));
    memset( b, 0, sizeof(*b) );
    ios_dc_install( &nd );
}

/* ml915: belt for the brace the stamp already is.  A create that lands inside
 * the same timestamp tick as the stamp we hold would be invisible to it, so
 * every path in THIS process that adds or removes a name drops the table for
 * the directory it wrote into.  Matching is on the resolved unix path, which
 * is the same spelling find_file_in_dir cached the table under; a directory
 * reached through a relative root_fd has no stored path and relies on the
 * stamp alone. */
static void ios_dc_invalidate_path( const char *unix_file )
{
    const char *slash;
    size_t dlen;
    unsigned int i;

    if (!unix_file || ios_dc_disabled()) return;
    if (!(slash = strrchr( unix_file, '/' ))) return;
    dlen = (size_t)(slash - unix_file);
    if (!dlen) dlen = 1;                        /* "/name" -> "/" */

    mutex_lock( &ios_dc_lock );
    for (i = 0; i < IOS_DC_MAX_DIRS; i++)
        if (ios_dc[i].st.mtime && ios_dc[i].path && !ios_dc[i].path[dlen] &&
            !strncmp( ios_dc[i].path, unix_file, dlen ))
        {
            ios_dc_drop( i );
            IOS_FSA( ios_fs_dc_inval, 1 );
            break;
        }
    mutex_unlock( &ios_dc_lock );
}
#endif  /* WINE_IOS */

/* check if a given Unicode char is OK in a DOS short name */
static inline BOOL is_invalid_dos_char( WCHAR ch )
{
    static const WCHAR invalid_chars[] = { INVALID_DOS_CHARS,'~','.',0 };
    if (ch > 0x7f) return TRUE;
    return wcschr( invalid_chars, ch ) != NULL;
}

/* check if the device can be a mounted volume */
static inline BOOL is_valid_mounted_device( const struct stat *st )
{
#if defined(linux) || defined(__sun__)
    return S_ISBLK( st->st_mode );
#else
    /* disks are char devices on *BSD */
    return S_ISCHR( st->st_mode );
#endif
}

static inline void ignore_file( const char *name )
{
    struct stat st;
    assert( ignored_files_count < MAX_IGNORED_FILES );
    if (!stat( name, &st ))
    {
        ignored_files[ignored_files_count].dev = st.st_dev;
        ignored_files[ignored_files_count].ino = st.st_ino;
        ignored_files_count++;
    }
}

static inline BOOL is_same_file( const struct file_identity *file, const struct stat *st )
{
    return st->st_dev == file->dev && st->st_ino == file->ino;
}

static inline BOOL is_ignored_file( const struct stat *st )
{
    unsigned int i;

    for (i = 0; i < ignored_files_count; i++)
        if (is_same_file( &ignored_files[i], st )) return TRUE;
    return FALSE;
}

static inline unsigned int dir_info_align( unsigned int len )
{
    return (len + 7) & ~7;
}

static inline unsigned int dir_info_size( FILE_INFORMATION_CLASS class, unsigned int len )
{
    switch (class)
    {
    case FileDirectoryInformation:
        return offsetof( FILE_DIRECTORY_INFORMATION, FileName[len] );
    case FileBothDirectoryInformation:
        return offsetof( FILE_BOTH_DIRECTORY_INFORMATION, FileName[len] );
    case FileFullDirectoryInformation:
        return offsetof( FILE_FULL_DIRECTORY_INFORMATION, FileName[len] );
    case FileIdBothDirectoryInformation:
        return offsetof( FILE_ID_BOTH_DIRECTORY_INFORMATION, FileName[len] );
    case FileIdExtdBothDirectoryInformation:
        return offsetof( FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION, FileName[len] );
    case FileIdFullDirectoryInformation:
        return offsetof( FILE_ID_FULL_DIRECTORY_INFORMATION, FileName[len] );
    case FileIdGlobalTxDirectoryInformation:
        return offsetof( FILE_ID_GLOBAL_TX_DIR_INFORMATION, FileName[len] );
    case FileNamesInformation:
        return offsetof( FILE_NAMES_INFORMATION, FileName[len] );
    default:
        assert(0);
        return 0;
    }
}

static BOOL is_wildcard( WCHAR c )
{
    return c == '*' || c == '?' || c == '>' || c == '<' || c == '\"';
}

static inline BOOL has_wildcard( const UNICODE_STRING *mask )
{
    int i;

    if (!mask) return TRUE;
    for (i = 0; i < mask->Length / sizeof(WCHAR); i++)
        if (is_wildcard( mask->Buffer[i] )) return TRUE;

    return FALSE;
}

NTSTATUS errno_to_status( int err )
{
    TRACE( "errno = %d\n", err );
    switch (err)
    {
    case EAGAIN:    return STATUS_SHARING_VIOLATION;
    case EBADF:     return STATUS_INVALID_HANDLE;
    case EBUSY:     return STATUS_DEVICE_BUSY;
    case ENOSPC:    return STATUS_DISK_FULL;
    case EPERM:
    case EROFS:
    case EACCES:    return STATUS_ACCESS_DENIED;
    case ENOTDIR:   return STATUS_OBJECT_PATH_NOT_FOUND;
    case ENOENT:    return STATUS_OBJECT_NAME_NOT_FOUND;
    case EISDIR:    return STATUS_INVALID_DEVICE_REQUEST;
    case EMFILE:
    case ENFILE:    return STATUS_TOO_MANY_OPENED_FILES;
    case EINVAL:    return STATUS_INVALID_PARAMETER;
    case ENOTEMPTY: return STATUS_DIRECTORY_NOT_EMPTY;
    case EPIPE:     return STATUS_PIPE_DISCONNECTED;
    case EIO:       return STATUS_DEVICE_NOT_READY;
#ifdef ENOMEDIUM
    case ENOMEDIUM: return STATUS_NO_MEDIA_IN_DEVICE;
#endif
    case ENXIO:     return STATUS_NO_SUCH_DEVICE;
    case ENOTTY:
    case EOPNOTSUPP:return STATUS_NOT_SUPPORTED;
    case ECONNRESET:return STATUS_PIPE_DISCONNECTED;
    case EFAULT:    return STATUS_ACCESS_VIOLATION;
    case ESPIPE:    return STATUS_ILLEGAL_FUNCTION;
    case ELOOP:     return STATUS_REPARSE_POINT_NOT_RESOLVED;
#ifdef ETIME /* Missing on FreeBSD */
    case ETIME:     return STATUS_IO_TIMEOUT;
#endif
    case ENOEXEC:   /* ?? */
    case EEXIST:    /* ?? */
    default:
        FIXME( "Converting errno %d to STATUS_UNSUCCESSFUL\n", err );
        return STATUS_UNSUCCESSFUL;
    }
}


static int xattr_fremove( int filedes, const char *name )
{
#ifdef HAVE_SYS_XATTR_H
# ifdef XATTR_ADDITIONAL_OPTIONS
    return fremovexattr( filedes, name, 0 );
# else
    return fremovexattr( filedes, name );
# endif
#elif defined(HAVE_SYS_EXTATTR_H)
    return extattr_delete_fd( filedes, EXTATTR_NAMESPACE_USER, &name[XATTR_USER_PREFIX_LEN] );
#else
    errno = ENOSYS;
    return -1;
#endif
}


static int xattr_fset( int filedes, const char *name, const void *value, size_t size )
{
#ifdef HAVE_SYS_XATTR_H
# ifdef XATTR_ADDITIONAL_OPTIONS
    return fsetxattr( filedes, name, value, size, 0, 0 );
# else
    return fsetxattr( filedes, name, value, size, 0 );
# endif
#elif defined(HAVE_SYS_EXTATTR_H)
    return extattr_set_fd( filedes, EXTATTR_NAMESPACE_USER, &name[XATTR_USER_PREFIX_LEN],
                           value, size );
#else
    errno = ENOSYS;
    return -1;
#endif
}


/* On macOS, getxattr() is significantly slower than listxattr()
 * (even for files with no extended attributes).
 */
#ifdef __APPLE__
static BOOL xattr_exists( const char **path, int *filedes, const char *name )
{
    char xattrs[1024];
    ssize_t i = 0, ret;

    if (path)
        ret = listxattr( *path, xattrs, sizeof(xattrs), 0 );
    else
        ret = flistxattr( *filedes, xattrs, sizeof(xattrs), 0 );
    if (ret == -1)
        return errno == ERANGE;

    while (i < ret)
    {
        if (!strcmp( name, &xattrs[i] ))
            return TRUE;
        i += strlen(&xattrs[i]) + 1;
    }

    errno = ENOATTR;
    return FALSE;
}
#endif


static int xattr_get( const char *path, const char *name, void *value, size_t size )
{
#ifdef __APPLE__
    if (!xattr_exists( &path, NULL, name ))
        return -1;
#endif

#ifdef HAVE_SYS_XATTR_H
# ifdef XATTR_ADDITIONAL_OPTIONS
    return getxattr( path, name, value, size, 0, 0 );
# else
    return getxattr( path, name, value, size );
# endif
#elif defined(HAVE_SYS_EXTATTR_H)
    return extattr_get_file( path, EXTATTR_NAMESPACE_USER, &name[XATTR_USER_PREFIX_LEN],
                             value, size );
#else
    errno = ENOSYS;
    return -1;
#endif
}


static int xattr_fget( int filedes, const char *name, void *value, size_t size )
{
#ifdef __APPLE__
    if (!xattr_exists( NULL, &filedes, name ))
        return -1;
#endif

#ifdef HAVE_SYS_XATTR_H
# ifdef XATTR_ADDITIONAL_OPTIONS
    return fgetxattr( filedes, name, value, size, 0, 0 );
# else
    return fgetxattr( filedes, name, value, size );
# endif
#elif defined(HAVE_SYS_EXTATTR_H)
    return extattr_get_fd( filedes, EXTATTR_NAMESPACE_USER, &name[XATTR_USER_PREFIX_LEN],
                           value, size );
#else
    errno = ENOSYS;
    return -1;
#endif
}


#ifdef WINE_IOS
/* ml910: fetch one named xattr without the listxattr() pre-probe, for the
 * callers that already know from ios_xa_bits() that the name is there. */
static int ios_xattr_get_raw( const char *path, const char *name, void *value, size_t size )
{
    return getxattr( path, name, value, size, 0, 0 );
}

static int ios_xattr_fget_raw( int filedes, const char *name, void *value, size_t size )
{
    return fgetxattr( filedes, name, value, size, 0, 0 );
}

static int ios_xa_skip_enabled(void)
{
    int v = __atomic_load_n( &ios_xa_skip_mode, __ATOMIC_RELAXED );
    if (v < 0)
    {
        const char *s = getenv( "MADEIRA_FS_NOXATTR" );
        v = (s && s[0] == '1') ? 1 : 0;
        __atomic_store_n( &ios_xa_skip_mode, v, __ATOMIC_RELAXED );
    }
    return v;
}

/***********************************************************************
 *           ios_xa_bits
 *
 * Which of XATTR_REPARSE / SAMBA_XATTR_DOS_ATTRIB does this file carry?
 * ONE listxattr() answers both questions (upstream asks twice, and on
 * macOS/iOS each xattr_get() is itself a listxattr()), and the answer is
 * memoised per (dev, ino, ctime) — setting or removing an xattr bumps
 * ctime, so the memo cannot go stale under us.
 *
 * Returns a bit mask, or -1 when the answer is unknown and the caller
 * should fall back to asking for each name directly.
 */
static int ios_xa_bits( const char *path, int filedes, const struct stat *st )
{
    char names[2048];
    ssize_t r, i;
    long long ct = ios_stat_ctime( st );
    unsigned slot = (unsigned)((((unsigned long long)st->st_ino * 1099511628211ull) >> 16)
                               & (IOS_XA_SLOTS - 1));
    struct ios_xa_ent *e = &ios_xa_memo[slot];
    int bits = 0;

    if (ios_xa_skip_enabled() && !__atomic_load_n( &ios_xa_written, __ATOMIC_RELAXED ))
    {
        IOS_FSA( ios_fs_xa_skip, 1 );
        return 0;
    }

    mutex_lock( &ios_xa_lock );
    if (e->ino == st->st_ino && e->dev == st->st_dev && e->ctime == ct)
    {
        bits = e->bits;
        mutex_unlock( &ios_xa_lock );
        IOS_FSA( ios_fs_xa_hit, 1 );
        return bits;
    }
    mutex_unlock( &ios_xa_lock );
    IOS_FSA( ios_fs_xa_miss, 1 );

    r = path ? listxattr( path, names, sizeof(names), 0 )
             : flistxattr( filedes, names, sizeof(names), 0 );
    if (r < 0)
    {
        if (errno == ERANGE) return -1;    /* name list too long: ask directly */
        return 0;                          /* ENOTSUP or gone: nothing to read */
    }
    for (i = 0; i < r; i += (ssize_t)strlen( &names[i] ) + 1)
    {
        if (!strcmp( &names[i], XATTR_REPARSE )) bits |= IOS_XA_REPARSE;
        else if (!strcmp( &names[i], SAMBA_XATTR_DOS_ATTRIB )) bits |= IOS_XA_DOSATTR;
    }

    mutex_lock( &ios_xa_lock );
    e->dev   = st->st_dev;
    e->ino   = st->st_ino;
    e->ctime = ct;
    e->bits  = bits;
    mutex_unlock( &ios_xa_lock );
    return bits;
}
#endif  /* WINE_IOS */


/* get space from the current directory data buffer, allocating a new one if necessary */
static void *get_dir_data_space( struct dir_data *data, unsigned int size )
{
    struct dir_data_buffer *buffer = data->buffer;
    void *ret;

    if (!buffer || size > buffer->size - buffer->pos)
    {
        unsigned int new_size = buffer ? buffer->size * 2 : dir_data_buffer_initial_size;
        if (new_size < size) new_size = size;
        if (!(buffer = malloc( offsetof( struct dir_data_buffer, data[new_size] ) ))) return NULL;
        buffer->pos  = 0;
        buffer->size = new_size;
        buffer->next = data->buffer;
        data->buffer = buffer;
    }
    ret = buffer->data + buffer->pos;
    buffer->pos += size;
    return ret;
}

/* add a string to the directory data buffer */
static const char *add_dir_data_nameA( struct dir_data *data, const char *name )
{
    /* keep buffer data WCHAR-aligned */
    char *ptr = get_dir_data_space( data, (strlen( name ) + sizeof(WCHAR)) & ~(sizeof(WCHAR) - 1) );
    if (ptr) strcpy( ptr, name );
    return ptr;
}

/* add a Unicode string to the directory data buffer */
static const WCHAR *add_dir_data_nameW( struct dir_data *data, const WCHAR *name )
{
    WCHAR *ptr = get_dir_data_space( data, (wcslen( name ) + 1) * sizeof(WCHAR) );
    if (ptr) wcscpy( ptr, name );
    return ptr;
}

/* add an entry to the directory names array */
static BOOL add_dir_data_names( struct dir_data *data, const WCHAR *long_name,
                                const WCHAR *short_name, const char *unix_name )
{
    static const WCHAR empty[1];
    struct dir_data_names *names = data->names;

    if (data->count >= data->size)
    {
        unsigned int new_size = max( data->size * 2, dir_data_names_initial_size );

        if (!(names = realloc( names, new_size * sizeof(*names) ))) return FALSE;
        data->size  = new_size;
        data->names = names;
    }

    if (short_name[0])
    {
        if (!(names[data->count].short_name = add_dir_data_nameW( data, short_name ))) return FALSE;
    }
    else names[data->count].short_name = empty;

    if (!(names[data->count].long_name = add_dir_data_nameW( data, long_name ))) return FALSE;
    if (!(names[data->count].unix_name = add_dir_data_nameA( data, unix_name ))) return FALSE;
    data->count++;
    return TRUE;
}

/* free the complete directory data structure */
static void free_dir_data( struct dir_data *data )
{
    struct dir_data_buffer *buffer, *next;

    if (!data) return;

    for (buffer = data->buffer; buffer; buffer = next)
    {
        next = buffer->next;
        free( buffer );
    }
    free( data->names );
    free( data->mask.Buffer );
    free( data );
}


/* support for a directory queue for filesystem searches */

struct dir_name
{
    struct list entry;
    char name[1];
};

static NTSTATUS add_dir_to_queue( struct list *queue, const char *name )
{
    int len = strlen( name ) + 1;
    struct dir_name *dir = malloc( offsetof( struct dir_name, name[len] ));
    if (!dir) return STATUS_NO_MEMORY;
    strcpy( dir->name, name );
    list_add_tail( queue, &dir->entry );
    return STATUS_SUCCESS;
}

static NTSTATUS next_dir_in_queue( struct list *queue, char *name )
{
    struct list *head = list_head( queue );
    if (head)
    {
        struct dir_name *dir = LIST_ENTRY( head, struct dir_name, entry );
        strcpy( name, dir->name );
        list_remove( &dir->entry );
        free( dir );
        return STATUS_SUCCESS;
    }
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static void flush_dir_queue( struct list *queue )
{
    struct list *head;

    while ((head = list_head( queue )))
    {
        struct dir_name *dir = LIST_ENTRY( head, struct dir_name, entry );
        list_remove( &dir->entry );
        free( dir );
    }
}


#ifdef __ANDROID__

static char *unescape_field( char *str )
{
    char *in, *out;

    for (in = out = str; *in; in++, out++)
    {
        *out = *in;
        if (in[0] == '\\')
        {
            if (in[1] == '\\')
            {
                out[0] = '\\';
                in++;
            }
            else if (in[1] == '0' && in[2] == '4' && in[3] == '0')
            {
                out[0] = ' ';
                in += 3;
            }
            else if (in[1] == '0' && in[2] == '1' && in[3] == '1')
            {
                out[0] = '\t';
                in += 3;
            }
            else if (in[1] == '0' && in[2] == '1' && in[3] == '2')
            {
                out[0] = '\n';
                in += 3;
            }
            else if (in[1] == '1' && in[2] == '3' && in[3] == '4')
            {
                out[0] = '\\';
                in += 3;
            }
        }
    }
    *out = '\0';

    return str;
}

static inline char *get_field( char **str )
{
    char *ret;

    ret = strsep( str, " \t" );
    if (*str) *str += strspn( *str, " \t" );

    return ret;
}
/************************************************************************
 *                    getmntent_replacement
 *
 * getmntent replacement for Android.
 *
 * NB returned static buffer is not thread safe; protect with mnt_mutex.
 */
static struct mntent *getmntent_replacement( FILE *f )
{
    static struct mntent entry;
    static char buf[4096];
    char *p, *start;

    do
    {
        if (!fgets( buf, sizeof(buf), f )) return NULL;
        p = strchr( buf, '\n' );
        if (p) *p = '\0';
        else /* Partially unread line, move file ptr to end */
        {
            char tmp[1024];
            while (fgets( tmp, sizeof(tmp), f ))
                if (strchr( tmp, '\n' )) break;
        }
        start = buf + strspn( buf, " \t" );
    } while (start[0] == '\0' || start[0] == '#');

    p = get_field( &start );
    entry.mnt_fsname = p ? unescape_field( p ) : (char *)"";

    p = get_field( &start );
    entry.mnt_dir = p ? unescape_field( p ) : (char *)"";

    p = get_field( &start );
    entry.mnt_type = p ? unescape_field( p ) : (char *)"";

    p = get_field( &start );
    entry.mnt_opts = p ? unescape_field( p ) : (char *)"";

    p = get_field( &start );
    entry.mnt_freq = p ? atoi(p) : 0;

    p = get_field( &start );
    entry.mnt_passno = p ? atoi(p) : 0;

    return &entry;
}
#define getmntent getmntent_replacement
#endif

/***********************************************************************
 *           parse_mount_entries
 *
 * Parse mount entries looking for a given device. Helper for get_default_drive_device.
 */

#ifdef sun
#include <sys/vfstab.h>
static char *parse_vfstab_entries( FILE *f, dev_t dev, ino_t ino)
{
    struct vfstab entry;
    struct stat st;
    char *device;

    while (! getvfsent( f, &entry ))
    {
        /* don't even bother stat'ing network mounts, there's no meaningful device anyway */
        if (!strcmp( entry.vfs_fstype, "nfs" ) ||
            !strcmp( entry.vfs_fstype, "smbfs" ) ||
            !strcmp( entry.vfs_fstype, "ncpfs" )) continue;

        if (stat( entry.vfs_mountp, &st ) == -1) continue;
        if (st.st_dev != dev || st.st_ino != ino) continue;
        if (!strcmp( entry.vfs_fstype, "fd" ))
        {
            if ((device = strstr( entry.vfs_mntopts, "dev=" )))
            {
                char *p = strchr( device + 4, ',' );
                if (p) *p = 0;
                return device + 4;
            }
        }
        else
            return entry.vfs_special;
    }
    return NULL;
}
#endif

#ifdef linux
static char *parse_mount_entries( FILE *f, dev_t dev, ino_t ino )
{
    struct mntent *entry;
    struct stat st;
    char *device;

    while ((entry = getmntent( f )))
    {
        /* don't even bother stat'ing network mounts, there's no meaningful device anyway */
        if (!strcmp( entry->mnt_type, "nfs" ) ||
            !strcmp( entry->mnt_type, "cifs" ) ||
            !strcmp( entry->mnt_type, "smbfs" ) ||
            !strcmp( entry->mnt_type, "ncpfs" )) continue;

        if (stat( entry->mnt_dir, &st ) == -1) continue;
        if (st.st_dev != dev || st.st_ino != ino) continue;
        if (!strcmp( entry->mnt_type, "supermount" ))
        {
            if ((device = strstr( entry->mnt_opts, "dev=" )))
            {
                char *p = strchr( device + 4, ',' );
                if (p) *p = 0;
                return device + 4;
            }
        }
        else if (!stat( entry->mnt_fsname, &st ) && S_ISREG(st.st_mode))
        {
            /* if device is a regular file check for a loop mount */
            if ((device = strstr( entry->mnt_opts, "loop=" )))
            {
                char *p = strchr( device + 5, ',' );
                if (p) *p = 0;
                return device + 5;
            }
        }
        else
            return entry->mnt_fsname;
    }
    return NULL;
}
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
#include <fstab.h>
static char *parse_mount_entries( FILE *f, dev_t dev, ino_t ino )
{
    struct fstab *entry;
    struct stat st;

    while ((entry = getfsent()))
    {
        /* don't even bother stat'ing network mounts, there's no meaningful device anyway */
        if (!strcmp( entry->fs_vfstype, "nfs" ) ||
            !strcmp( entry->fs_vfstype, "smbfs" ) ||
            !strcmp( entry->fs_vfstype, "ncpfs" )) continue;

        if (stat( entry->fs_file, &st ) == -1) continue;
        if (st.st_dev != dev || st.st_ino != ino) continue;
        return entry->fs_spec;
    }
    return NULL;
}
#endif

#ifdef sun
#include <sys/mnttab.h>
static char *parse_mount_entries( FILE *f, dev_t dev, ino_t ino )
{
    struct mnttab entry;
    struct stat st;
    char *device;


    while (( ! getmntent( f, &entry) ))
    {
        /* don't even bother stat'ing network mounts, there's no meaningful device anyway */
        if (!strcmp( entry.mnt_fstype, "nfs" ) ||
            !strcmp( entry.mnt_fstype, "smbfs" ) ||
            !strcmp( entry.mnt_fstype, "ncpfs" )) continue;

        if (stat( entry.mnt_mountp, &st ) == -1) continue;
        if (st.st_dev != dev || st.st_ino != ino) continue;
        if (!strcmp( entry.mnt_fstype, "fd" ))
        {
            if ((device = strstr( entry.mnt_mntopts, "dev=" )))
            {
                char *p = strchr( device + 4, ',' );
                if (p) *p = 0;
                return device + 4;
            }
        }
        else
            return entry.mnt_special;
    }
    return NULL;
}
#endif

/***********************************************************************
 *           get_default_drive_device
 *
 * Return the default device to use for a given drive mount point.
 */
static char *get_default_drive_device( const char *root )
{
    char *ret = NULL;

#ifdef linux
    FILE *f;
    char *device = NULL;
    int fd, res = -1;
    struct stat st;

    /* try to open it first to force it to get mounted */
    if ((fd = open( root, O_RDONLY | O_DIRECTORY )) != -1)
    {
        res = fstat( fd, &st );
        close( fd );
    }
    /* now try normal stat just in case */
    if (res == -1) res = stat( root, &st );
    if (res == -1) return NULL;

    mutex_lock( &mnt_mutex );

#ifdef __ANDROID__
    if ((f = fopen( "/proc/mounts", "r" )))
    {
        device = parse_mount_entries( f, st.st_dev, st.st_ino );
        fclose( f );
    }
#else
    if ((f = fopen( "/etc/mtab", "r" )))
    {
        device = parse_mount_entries( f, st.st_dev, st.st_ino );
        fclose( f );
    }
    /* look through fstab too in case it's not mounted (for instance if it's an audio CD) */
    if (!device && (f = fopen( "/etc/fstab", "r" )))
    {
        device = parse_mount_entries( f, st.st_dev, st.st_ino );
        fclose( f );
    }
#endif
    if (device) ret = strdup( device );
    mutex_unlock( &mnt_mutex );

#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__ ) || defined(__DragonFly__)
    char *device = NULL;
    int fd, res = -1;
    struct stat st;

    /* try to open it first to force it to get mounted */
    if ((fd = open( root, O_RDONLY )) != -1)
    {
        res = fstat( fd, &st );
        close( fd );
    }
    /* now try normal stat just in case */
    if (res == -1) res = stat( root, &st );
    if (res == -1) return NULL;

    mutex_lock( &mnt_mutex );

    /* The FreeBSD parse_mount_entries doesn't require a file argument, so just
     * pass NULL.  Leave the argument in for symmetry.
     */
    device = parse_mount_entries( NULL, st.st_dev, st.st_ino );
    if (device) ret = strdup( device );
    mutex_unlock( &mnt_mutex );

#elif defined( sun )
    FILE *f;
    char *device = NULL;
    int fd, res = -1;
    struct stat st;

    /* try to open it first to force it to get mounted */
    if ((fd = open( root, O_RDONLY )) != -1)
    {
        res = fstat( fd, &st );
        close( fd );
    }
    /* now try normal stat just in case */
    if (res == -1) res = stat( root, &st );
    if (res == -1) return NULL;

    mutex_lock( &mnt_mutex );

    if ((f = fopen( "/etc/mnttab", "r" )))
    {
        device = parse_mount_entries( f, st.st_dev, st.st_ino);
        fclose( f );
    }
    /* look through fstab too in case it's not mounted (for instance if it's an audio CD) */
    if (!device && (f = fopen( "/etc/vfstab", "r" )))
    {
        device = parse_vfstab_entries( f, st.st_dev, st.st_ino );
        fclose( f );
    }
    if (device) ret = strdup( device );
    mutex_unlock( &mnt_mutex );

#elif defined(__APPLE__)
    struct statfs *mntStat;
    struct stat st;
    int i;
    int mntSize;
    dev_t dev;
    ino_t ino;
    static const char path_bsd_device[] = "/dev/disk";
    int res;

    res = stat( root, &st );
    if (res == -1) return NULL;

    dev = st.st_dev;
    ino = st.st_ino;

    mutex_lock( &mnt_mutex );

    mntSize = getmntinfo(&mntStat, MNT_NOWAIT);

    for (i = 0; i < mntSize && !ret; i++)
    {
        if (stat(mntStat[i].f_mntonname, &st ) == -1) continue;
        if (st.st_dev != dev || st.st_ino != ino) continue;

        /* FIXME add support for mounted network drive */
        if ( strncmp(mntStat[i].f_mntfromname, path_bsd_device, strlen(path_bsd_device)) == 0)
        {
            /* set return value to the corresponding raw BSD node */
            ret = malloc( strlen(mntStat[i].f_mntfromname) + 2 /* 2 : r and \0 */ );
            if (ret)
            {
                strcpy(ret, "/dev/r");
                strcat(ret, mntStat[i].f_mntfromname+sizeof("/dev/")-1);
            }
        }
    }
    mutex_unlock( &mnt_mutex );
#else
    static int warned;
    if (!warned++) FIXME( "auto detection of DOS devices not supported on this platform\n" );
#endif
    return ret;
}


/***********************************************************************
 *           get_device_mount_point
 *
 * Return the current mount point for a device.
 */
static char *get_device_mount_point( dev_t dev )
{
    char *ret = NULL;

#ifdef linux
    FILE *f;

    mutex_lock( &mnt_mutex );

#ifdef __ANDROID__
    if ((f = fopen( "/proc/mounts", "r" )))
#else
    if ((f = fopen( "/etc/mtab", "r" )))
#endif
    {
        struct mntent *entry;
        struct stat st;
        char *p, *device;

        while ((entry = getmntent( f )))
        {
            /* don't even bother stat'ing network mounts, there's no meaningful device anyway */
            if (!strcmp( entry->mnt_type, "nfs" ) ||
                !strcmp( entry->mnt_type, "cifs" ) ||
                !strcmp( entry->mnt_type, "smbfs" ) ||
                !strcmp( entry->mnt_type, "ncpfs" )) continue;

            if (!strcmp( entry->mnt_type, "supermount" ))
            {
                if ((device = strstr( entry->mnt_opts, "dev=" )))
                {
                    device += 4;
                    if ((p = strchr( device, ',' ))) *p = 0;
                }
            }
            else if (!stat( entry->mnt_fsname, &st ) && S_ISREG(st.st_mode))
            {
                /* if device is a regular file check for a loop mount */
                if ((device = strstr( entry->mnt_opts, "loop=" )))
                {
                    device += 5;
                    if ((p = strchr( device, ',' ))) *p = 0;
                }
            }
            else device = entry->mnt_fsname;

            if (device && !stat( device, &st ) && S_ISBLK(st.st_mode) && st.st_rdev == dev)
            {
                ret = strdup( entry->mnt_dir );
                break;
            }
        }
        fclose( f );
    }
    mutex_unlock( &mnt_mutex );
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    struct statfs *entry;
    struct stat st;
    int i, size;

    mutex_lock( &mnt_mutex );

    size = getmntinfo( &entry, MNT_NOWAIT );
    for (i = 0; i < size; i++)
    {
        if (stat( entry[i].f_mntfromname, &st ) == -1) continue;
        if (S_ISBLK(st.st_mode) && st.st_rdev == dev)
        {
            ret = strdup( entry[i].f_mntonname );
            break;
        }
    }
    mutex_unlock( &mnt_mutex );
#else
    static int warned;
    if (!warned++) FIXME( "unmounting devices not supported on this platform\n" );
#endif
    return ret;
}


#if defined(HAVE_GETATTRLIST) && defined(ATTR_VOL_CAPABILITIES) && \
    defined(VOL_CAPABILITIES_FORMAT) && defined(VOL_CAP_FMT_CASE_SENSITIVE)

static pthread_mutex_t fs_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

struct get_fsid
{
    ULONG size;
    dev_t dev;
    fsid_t fsid;
};

struct fs_cache
{
    dev_t dev;
    fsid_t fsid;
    BOOLEAN case_sensitive;
} fs_cache[64];

struct vol_caps
{
    ULONG size;
    vol_capabilities_attr_t caps;
};

/***********************************************************************
 *           look_up_fs_cache
 *
 * Checks if the specified file system is in the cache.
 */
static struct fs_cache *look_up_fs_cache( dev_t dev )
{
    int i;
    for (i = 0; i < ARRAY_SIZE( fs_cache ); i++)
        if (fs_cache[i].dev == dev)
            return fs_cache+i;
    return NULL;
}

/***********************************************************************
 *           add_fs_cache
 *
 * Adds the specified file system to the cache.
 */
static void add_fs_cache( dev_t dev, fsid_t fsid, BOOLEAN case_sensitive )
{
    int i;
    struct fs_cache *entry = look_up_fs_cache( dev );
    static int once = 0;
    if (entry)
    {
        /* Update the cache */
        entry->fsid = fsid;
        entry->case_sensitive = case_sensitive;
        return;
    }

    /* Add a new entry */
    for (i = 0; i < ARRAY_SIZE( fs_cache ); i++)
        if (fs_cache[i].dev == 0)
        {
            /* This entry is empty, use it */
            fs_cache[i].dev = dev;
            fs_cache[i].fsid = fsid;
            fs_cache[i].case_sensitive = case_sensitive;
            return;
        }

    /* Cache is out of space, warn */
    if (!once++)
        WARN( "FS cache is out of space, expect performance problems\n" );
}

/***********************************************************************
 *           get_dir_case_sensitivity_attr
 *
 * Checks if the volume containing the specified directory is case
 * sensitive or not. Uses getattrlist(2)/getattrlistat(2).
 */
static int get_dir_case_sensitivity_attr( int root_fd, const char *dir )
{
    BOOLEAN ret = FALSE;
    char *mntpoint;
    struct attrlist attr;
    struct vol_caps caps;
    struct get_fsid get_fsid;
    struct fs_cache *entry;

    /* First get the FS ID of the volume */
    attr.bitmapcount = ATTR_BIT_MAP_COUNT;
    attr.reserved = 0;
    attr.commonattr = ATTR_CMN_DEVID|ATTR_CMN_FSID;
    attr.volattr = attr.dirattr = attr.fileattr = attr.forkattr = 0;
    get_fsid.size = 0;
    if (getattrlistat( root_fd, dir, &attr, &get_fsid, sizeof(get_fsid), 0 ) != 0 ||
        get_fsid.size != sizeof(get_fsid))
        return -1;

    /* Try to look it up in the cache */
    mutex_lock( &fs_cache_mutex );
    entry = look_up_fs_cache( get_fsid.dev );
    if (entry && !memcmp( &entry->fsid, &get_fsid.fsid, sizeof(fsid_t) ))
    {
        /* Cache lookup succeeded */
        ret = entry->case_sensitive;
        goto done;
    }

    /* Cache is stale at this point, we have to update it */
    mntpoint = get_device_mount_point( get_fsid.dev );
    /* Now look up the case-sensitivity */
    attr.commonattr = 0;
    attr.volattr = ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES;
    if (getattrlist( mntpoint, &attr, &caps, sizeof(caps), 0 ) < 0)
    {
        free( mntpoint );
        add_fs_cache( get_fsid.dev, get_fsid.fsid, TRUE );
        ret = TRUE;
        goto done;
    }
    free( mntpoint );
    if (caps.size == sizeof(caps) &&
        (caps.caps.valid[VOL_CAPABILITIES_FORMAT] &
         (VOL_CAP_FMT_CASE_SENSITIVE | VOL_CAP_FMT_CASE_PRESERVING)) ==
        (VOL_CAP_FMT_CASE_SENSITIVE | VOL_CAP_FMT_CASE_PRESERVING))
    {
        if ((caps.caps.capabilities[VOL_CAPABILITIES_FORMAT] &
            VOL_CAP_FMT_CASE_SENSITIVE) != VOL_CAP_FMT_CASE_SENSITIVE)
            ret = FALSE;
        else
            ret = TRUE;
        /* Update the cache */
        add_fs_cache( get_fsid.dev, get_fsid.fsid, ret );
        goto done;
    }

done:
    mutex_unlock( &fs_cache_mutex );
    return ret;
}
#endif

/***********************************************************************
 *           get_dir_case_sensitivity_stat
 *
 * Checks if the volume containing the specified directory is case
 * sensitive or not. Uses (f)statfs(2), statvfs(2), fstatat(2), or ioctl(2).
 */
static BOOLEAN get_dir_case_sensitivity_stat( int root_fd, const char *dir )
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    struct statfs stfs;
    int fd;

    if ((fd = openat( root_fd, dir, O_RDONLY )) == -1) return TRUE;
    if (fstatfs( fd, &stfs ) == -1)
    {
        close( fd );
        return TRUE;
    }
    close( fd );
    /* Assume these file systems are always case insensitive.*/
    if (!strcmp( stfs.f_fstypename, "fusefs" ) &&
        !strncmp( stfs.f_mntfromname, "ciopfs", 5 ))
        return FALSE;
    /* msdosfs was case-insensitive since FreeBSD 8, if not earlier */
    if (!strcmp( stfs.f_fstypename, "msdosfs" ) ||
        /* older CIFS protocol versions uppercase filename on the client,
         * newer versions should be case-insensitive on the server anyway */
        !strcmp( stfs.f_fstypename, "smbfs" ))
        return FALSE;
    /* no ntfs-3g: modern fusefs has no way to report the filesystem on FreeBSD
     * no cd9660 or udf, they're case-sensitive on FreeBSD
     */
#ifdef __APPLE__
    if (!strcmp( stfs.f_fstypename, "msdos" ) ||
        !strcmp( stfs.f_fstypename, "cd9660" ) ||
        !strcmp( stfs.f_fstypename, "udf" ) ||
        !strcmp( stfs.f_fstypename, "ntfs" ))
        return FALSE;
#ifdef _DARWIN_FEATURE_64_BIT_INODE
     if (!strcmp( stfs.f_fstypename, "hfs" ) && (stfs.f_fssubtype == 0 ||
                                                 stfs.f_fssubtype == 1 ||
                                                 stfs.f_fssubtype == 128))
        return FALSE;
#else
     /* The field says "reserved", but a quick look at the kernel source
      * tells us that this "reserved" field is really the same as the
      * "fssubtype" field from the inode64 structure (see munge_statfs()
      * in <xnu-source>/bsd/vfs/vfs_syscalls.c).
      */
     if (!strcmp( stfs.f_fstypename, "hfs" ) && (stfs.f_reserved1 == 0 ||
                                                 stfs.f_reserved1 == 1 ||
                                                 stfs.f_reserved1 == 128))
        return FALSE;
#endif
#endif
    return TRUE;

#elif defined(__linux__)
    BOOLEAN sens = TRUE;
    struct statfs stfs;
    struct stat st;
    int fd, flags;

    if ((fd = openat( root_fd, dir, O_RDONLY | O_NONBLOCK )) == -1)
        return TRUE;

    if (ioctl( fd, EXT2_IOC_GETFLAGS, &flags ) != -1 && (flags & EXT4_CASEFOLD_FL))
    {
        sens = FALSE;
    }
    else if (fstatfs( fd, &stfs ) == 0 &&                          /* CIOPFS is case insensitive.  Instead of */
             stfs.f_type == 0x65735546 /* FUSE_SUPER_MAGIC */ &&   /* parsing mtab to discover if the FUSE FS */
             fstatat( fd, ".ciopfs", &st, AT_NO_AUTOMOUNT ) == 0)  /* is CIOPFS, look for .ciopfs in the dir. */
    {
        sens = FALSE;
    }

    close( fd );
    return sens;
#else
    return TRUE;
#endif
}


/***********************************************************************
 *           get_dir_case_sensitivity
 *
 * Checks if the volume containing the specified directory is case
 * sensitive or not. Uses multiple methods, depending on platform.
 */
static BOOLEAN get_dir_case_sensitivity( int root_fd, const char *dir )
{
#ifdef WINE_IOS
    /* ml910: memoise per directory path.  Upstream's cache is keyed by
     * st_dev but it re-derives that device with a getattrlistat() on EVERY
     * call before it may consult the cache, which [prof] measured at 5-9% of
     * all CPU.  One relaxed 64-bit load answers it here with no syscall at
     * all.  Restricted to AT_FDCWD so a recycled directory fd can never make
     * a relative path inherit another directory's answer. */
    unsigned long long h = 0, w = 0;
    unsigned slot = 0;
    BOOLEAN ret;

    if (root_fd == AT_FDCWD)
    {
        h = ios_fnv( dir, strlen(dir) ) >> 2;      /* 62-bit tag */
        slot = (unsigned)(h & (IOS_CS_SLOTS - 1));
        w = __atomic_load_n( &ios_cs_memo[slot], __ATOMIC_RELAXED );
        if (w && (w >> 2) == h)
        {
            IOS_FSA( ios_fs_cs_hit, 1 );
            return (BOOLEAN)(w & 1);
        }
        IOS_FSA( ios_fs_cs_miss, 1 );
    }
#endif
#if defined(HAVE_GETATTRLIST) && defined(ATTR_VOL_CAPABILITIES) && \
    defined(VOL_CAPABILITIES_FORMAT) && defined(VOL_CAP_FMT_CASE_SENSITIVE)
    {
        int case_sensitive = get_dir_case_sensitivity_attr( root_fd, dir );
#ifdef WINE_IOS
        if (case_sensitive != -1)
        {
            if (root_fd == AT_FDCWD)
                __atomic_store_n( &ios_cs_memo[slot], (h << 2) | 2 | (case_sensitive ? 1 : 0),
                                  __ATOMIC_RELAXED );
            return case_sensitive;
        }
#else
        if (case_sensitive != -1) return case_sensitive;
#endif
    }
#endif
#ifdef WINE_IOS
    ret = get_dir_case_sensitivity_stat( root_fd, dir );
    if (root_fd == AT_FDCWD)
        __atomic_store_n( &ios_cs_memo[slot], (h << 2) | 2 | (ret ? 1 : 0), __ATOMIC_RELAXED );
    return ret;
#else
    return get_dir_case_sensitivity_stat( root_fd, dir );
#endif
}


/***********************************************************************
 *           is_hidden_file
 *
 * Check if the specified file should be hidden based on its unix path and the show dot files option.
 */
static BOOL is_hidden_file( const char *name )
{
    const char *p;

    if (show_dot_files) return FALSE;

    p = name + strlen( name );
    while (p > name && p[-1] == '/') p--;
    while (p > name && p[-1] != '/') p--;
    if (*p++ != '.') return FALSE;
    if (!*p || *p == '/') return FALSE;  /* "." directory */
    if (*p++ != '.') return TRUE;
    if (!*p || *p == '/') return FALSE;  /* ".." directory */
    return TRUE;
}


/***********************************************************************
 *           hash_short_file_name
 *
 * Transform a Unix file name into a hashed DOS name. If the name is not a valid
 * DOS name, it is replaced by a hashed version that fits in 8.3 format.
 * 'buffer' must be at least 12 characters long.
 * Returns length of short name in bytes; short name is NOT null-terminated.
 */
static ULONG hash_short_file_name( const WCHAR *name, int length, LPWSTR buffer )
{
    static const char hash_chars[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

    LPCWSTR p, ext, end = name + length;
    LPWSTR dst;
    unsigned short hash;
    int i;

    /* Compute the hash code of the file name */
    /* If you know something about hash functions, feel free to */
    /* insert a better algorithm here... */
    if (!is_case_sensitive)
    {
        for (p = name, hash = 0xbeef; p < end - 1; p++)
            hash = (hash<<3) ^ (hash>>5) ^ towlower(*p) ^ (towlower(p[1]) << 8);
        hash = (hash<<3) ^ (hash>>5) ^ towlower(*p); /* Last character */
    }
    else
    {
        for (p = name, hash = 0xbeef; p < end - 1; p++)
            hash = (hash << 3) ^ (hash >> 5) ^ *p ^ (p[1] << 8);
        hash = (hash << 3) ^ (hash >> 5) ^ *p;  /* Last character */
    }

    /* Find last dot for start of the extension */
    p = name;
    while (*p == '.') ++p;
    for (p = p + 1, ext = NULL; p < end - 1; p++) if (*p == '.') ext = p;

    /* Copy first 4 chars, replacing invalid chars with '_' */
    for (i = 4, p = name, dst = buffer; i > 0; p++)
    {
        if (p == end || p == ext) break;
        if (*p == '.') continue;
        *dst++ = is_invalid_dos_char(*p) ? '_' : *p;
        i--;
    }
    /* Pad to 5 chars with '~' */
    while (i-- >= 0) *dst++ = '~';

    /* Insert hash code converted to 3 ASCII chars */
    *dst++ = hash_chars[(hash >> 10) & 0x1f];
    *dst++ = hash_chars[(hash >> 5) & 0x1f];
    *dst++ = hash_chars[hash & 0x1f];

    /* Copy the first 3 chars of the extension (if any) */
    if (ext)
    {
        *dst++ = '.';
        for (i = 3, ext++; (i > 0) && ext < end; i--, ext++)
            *dst++ = is_invalid_dos_char(*ext) ? '_' : *ext;
    }
    return dst - buffer;
}


/***********************************************************************
 *           match_filename_part
 *
 * Recursive helper for match_filename().
 *
 */
static BOOLEAN match_filename_part( const WCHAR *name, const WCHAR *name_end, const WCHAR *mask, const WCHAR *mask_end )
{
    WCHAR c;

    while (name < name_end && mask < mask_end)
    {
        switch(*mask)
        {
        case '*':
            mask++;
            while (mask < mask_end && *mask == '*') mask++;  /* Skip consecutive '*' */
            if (mask == mask_end) return TRUE; /* end of mask is all '*', so match */

            while (name < name_end)
            {
                c = *mask == '"' ? '.' : *mask;
                if (!is_wildcard(c))
                {
                    if (is_case_sensitive)
                        while (name < name_end && (*name != c)) name++;
                    else
                        while (name < name_end && (towupper(*name) != towupper(c))) name++;
                }
                if (match_filename_part( name, name_end, mask, mask_end )) return TRUE;
                ++name;
            }
            break;
        case '<':
        {
            const WCHAR *next_dot;
            BOOL had_dot = FALSE;

            ++mask;
            while (name < name_end)
            {
                next_dot = name;
                while (next_dot < name_end && *next_dot != '.') ++next_dot;
                if (next_dot == name_end && had_dot) break;
                if (next_dot < name_end)
                {
                    had_dot = TRUE;
                    ++next_dot;
                }
                if (mask < mask_end)
                {
                    while (name < next_dot)
                    {
                        c = *mask == '"' ? '.' : *mask;
                        if (!is_wildcard(c))
                        {
                            if (is_case_sensitive)
                                while (name < next_dot && (*name != c)) name++;
                            else
                                while (name < next_dot && (towupper(*name) != towupper(c))) name++;
                        }
                        if (match_filename_part( name, name_end, mask, mask_end )) return TRUE;
                        ++name;
                    }
                }
                name = next_dot;
            }
            break;
        }
        case '?':
            mask++;
            name++;
            break;
        case '>':
            mask++;
            if (*name == '.')
            {
                while (mask < mask_end && *mask == '>') mask++;
                if (mask == mask_end) name++;
            }
            else name++;
            break;
        default:
            c = *mask == '"' ? '.' : *mask;
            if (is_case_sensitive && c != *name) return FALSE;
            if (!is_case_sensitive && towupper(c) != towupper(*name)) return FALSE;
            mask++;
            name++;
            break;
        }
    }
    while (mask < mask_end && (*mask == '*' || *mask == '<' || *mask == '"' || *mask == '>'))
        mask++;
    return (name == name_end && mask == mask_end);
}


/***********************************************************************
 *           match_filename
 *
 * Check a file name against a mask.
 *
 */
static BOOLEAN match_filename( const WCHAR *name, int length, const UNICODE_STRING *mask_str )
{
    /* Special handling for parent directory. */
    if (length == 2 && name[0] == '.' && name[1] == '.') --length;

    return match_filename_part( name, name + length, mask_str->Buffer,
                                mask_str->Buffer + mask_str->Length / sizeof(WCHAR));
}


/***********************************************************************
 *           is_legal_8dot3_name
 *
 * Simplified version of RtlIsNameLegalDOS8Dot3.
 */
static BOOLEAN is_legal_8dot3_name( const WCHAR *name, int len )
{
    static const WCHAR invalid_chars[] = { INVALID_DOS_CHARS,':','/','\\',0 };
    int i, dot = -1;

    if (len > 12) return FALSE;

    /* a starting . is invalid, except for . and .. */
    if (len > 0 && name[0] == '.') return (len == 1 || (len == 2 && name[1] == '.'));

    for (i = 0; i < len; i++)
    {
        if (name[i] > 0x7f) return FALSE;
        if (wcschr( invalid_chars, name[i] )) return FALSE;
        if (name[i] == '.')
        {
            if (dot != -1) return FALSE;
            dot = i;
        }
    }

    if (dot == -1) return (len <= 8);
    if (dot > 8) return FALSE;
    return (len - dot > 1 && len - dot < 5);
}


/***********************************************************************
 *           append_entry
 *
 * Add a file to the directory data if it matches the mask.
 */
static BOOL append_entry( struct dir_data *data, const char *long_name,
                          const char *short_name, const UNICODE_STRING *mask )
{
    int long_len, short_len;
    WCHAR long_nameW[MAX_DIR_ENTRY_LEN + 1];
    WCHAR short_nameW[13];

    long_len = ntdll_umbstowcs( long_name, strlen(long_name), long_nameW, ARRAY_SIZE(long_nameW) );
    if (long_len == ARRAY_SIZE(long_nameW)) return TRUE;
    if (long_nameW[long_len - 1] == '?') --long_len;
    long_nameW[long_len] = 0;

    if (short_name)
    {
        short_len = ntdll_umbstowcs( short_name, strlen(short_name),
                                     short_nameW, ARRAY_SIZE( short_nameW ) - 1 );
    }
    else  /* generate a short name if necessary */
    {
        short_len = 0;
        if (!is_legal_8dot3_name( long_nameW, long_len ))
            short_len = hash_short_file_name( long_nameW, long_len, short_nameW );
    }
    short_nameW[short_len] = 0;
    wcsupr( short_nameW );

    TRACE( "long %s short %s mask %s\n",
           debugstr_w( long_nameW ), debugstr_w( short_nameW ), debugstr_us( mask ));

    if (mask && !match_filename( long_nameW, long_len, mask ))
    {
        if (!short_len) return TRUE;  /* no short name to match */
        if (!match_filename( short_nameW, short_len, mask )) return TRUE;
    }

    return add_dir_data_names( data, long_nameW, short_nameW, long_name );
}


/* fetch the attributes of a file */
static inline ULONG get_file_attributes( const struct stat *st )
{
    ULONG attr;

    if (S_ISDIR(st->st_mode))
        attr = FILE_ATTRIBUTE_DIRECTORY;
    else
        attr = FILE_ATTRIBUTE_ARCHIVE;
    if (!(st->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)))
        attr |= FILE_ATTRIBUTE_READONLY;
    return attr;
}


/* decode the xattr-stored DOS attributes */
static int parse_samba_dos_attrib_data( char *data, int len )
{
    char *end;
    int val;

    if (len > 2 && data[0] == '0' && data[1] == 'x')
    {
        data[len] = 0;
        val = strtol( data, &end, 16 );
        if (!*end) return val & XATTR_ATTRIBS_MASK;
    }
    else
    {
        static BOOL once;
        if (!once++) FIXME( "Unhandled " SAMBA_XATTR_DOS_ATTRIB " extended attribute value.\n" );
    }
    return 0;
}


static BOOL fd_is_mount_point( int fd, const struct stat *st )
{
    struct stat parent;
    return S_ISDIR( st->st_mode ) && !fstatat( fd, "..", &parent, 0 )
            && (parent.st_dev != st->st_dev || parent.st_ino == st->st_ino);
}


static unsigned int server_get_unix_name( HANDLE handle, char **unix_name );


/* get the stat info and file attributes for a file (by file descriptor) */
static int fd_get_file_info( HANDLE handle, int fd, unsigned int options,
                             struct stat *st, ULONG *attr, ULONG *reparse_tag )
{
    char buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    char attr_data[65];
    int attr_len, ret;

    *attr = 0;
    ret = fstat( fd, st );
    if (ret == -1) return ret;
    *attr |= get_file_attributes( st );
    if (reparse_tag) *reparse_tag = 0;
    /* consider mount points to be reparse points (IO_REPARSE_TAG_MOUNT_POINT) */
    if (options & FILE_OPEN_REPARSE_POINT)
    {
        if (fd_is_mount_point( fd, st ))
        {
            *attr |= FILE_ATTRIBUTE_REPARSE_POINT;
            if (reparse_tag) *reparse_tag = IO_REPARSE_TAG_MOUNT_POINT;
        }
    }

#ifdef WINE_IOS
    /* ml910: one listxattr for both names, memoised by (dev, ino, ctime). */
    {
        int xb = ios_xa_bits( NULL, fd, st );

        if (xb >= 0)
        {
            if (xb & IOS_XA_REPARSE)
            {
                attr_len = ios_xattr_fget_raw( fd, XATTR_REPARSE, buffer, sizeof(buffer) );
                if (attr_len >= 0 && attr_len >= sizeof(ULONG))
                {
                    *attr |= FILE_ATTRIBUTE_REPARSE_POINT;
                    if (reparse_tag) memcpy( reparse_tag, buffer, sizeof(ULONG) );
                }
            }
            if (xb & IOS_XA_DOSATTR)
            {
                attr_len = ios_xattr_fget_raw( fd, SAMBA_XATTR_DOS_ATTRIB, attr_data, sizeof(attr_data)-1 );
                if (attr_len != -1) *attr |= parse_samba_dos_attrib_data( attr_data, attr_len );
            }
            return ret;
        }
    }
#endif
    attr_len = xattr_fget( fd, XATTR_REPARSE, buffer, sizeof(buffer) );
    if (attr_len >= 0 && attr_len >= sizeof(ULONG))
    {
        *attr |= FILE_ATTRIBUTE_REPARSE_POINT;
        if (reparse_tag) memcpy( reparse_tag, buffer, sizeof(ULONG) );
    }

    attr_len = xattr_fget( fd, SAMBA_XATTR_DOS_ATTRIB, attr_data, sizeof(attr_data)-1 );
    if (attr_len != -1)
        *attr |= parse_samba_dos_attrib_data( attr_data, attr_len );
    else
    {
        if (errno == ENOTSUP) return ret;
#ifdef ENODATA
        if (errno == ENODATA) return ret;
#endif
#ifdef ENOATTR
        if (errno == ENOATTR) return ret;
#endif
        WARN( "Failed to get extended attribute " SAMBA_XATTR_DOS_ATTRIB ". errno %d (%s)\n",
              errno, strerror( errno ) );
    }
    return ret;
}


static int fd_set_dos_attrib( int fd, UINT attr, BOOL force_set )
{
#ifdef WINE_IOS
    /* ml910: the single place this tree writes a DOS-attribute xattr.  Note
     * it for the optional MADEIRA_FS_NOXATTR skip; the (dev,ino,ctime) memo
     * needs nothing here because the write itself bumps ctime. */
    __atomic_store_n( &ios_xa_written, 1, __ATOMIC_RELAXED );
    IOS_FSA( ios_fs_xa_write, 1 );
#endif
    /* we only store the HIDDEN and SYSTEM attributes */
    attr &= XATTR_ATTRIBS_MASK;
    if (force_set || attr != 0)
    {
        /* encode the attributes in Samba 3 ASCII format. Samba 4 has extended
         * this format with more features, but retains compatibility with the
         * earlier format. */
        char data[11];
        int len = snprintf( data, sizeof(data), "0x%x", attr );
        return xattr_fset( fd, SAMBA_XATTR_DOS_ATTRIB, data, len );
    }
    else return xattr_fremove( fd, SAMBA_XATTR_DOS_ATTRIB );
}


/* set the stat info and file attributes for a file (by file descriptor) */
static NTSTATUS fd_set_file_info( int fd, UINT attr, BOOL force_set_xattr )
{
    struct stat st;

    if (fstat( fd, &st ) == -1) return errno_to_status( errno );
    if (attr & FILE_ATTRIBUTE_READONLY)
    {
        if (S_ISDIR( st.st_mode))
            WARN("FILE_ATTRIBUTE_READONLY ignored for directory.\n");
        else
            st.st_mode &= ~0222; /* clear write permission bits */
    }
    else
    {
        /* add write permission only where we already have read permission */
        st.st_mode |= (0600 | ((st.st_mode & 044) >> 1)) & (~start_umask);
    }
    if (fchmod( fd, st.st_mode ) == -1) return errno_to_status( errno );

    /* if the file has multiple names, we can't be sure that it is safe to not
       set the extended attribute, since any of the names could start with a dot */
    force_set_xattr = force_set_xattr || st.st_nlink > 1;

    if (fd_set_dos_attrib( fd, attr, force_set_xattr ) == -1 && errno != ENOTSUP)
        WARN( "Failed to set extended attribute " SAMBA_XATTR_DOS_ATTRIB ". errno %d (%s)\n",
              errno, strerror( errno ) );

    return STATUS_SUCCESS;
}


/* get the stat info and file attributes for a file (by name) */
static int get_file_info( const char *path, struct stat *st, ULONG *attr, ULONG *reparse_tag )
{
    char buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    size_t len = strlen( path );
    char *parent_path;
    char attr_data[65];
    int attr_len, ret;

    *attr = 0;
    ret = lstat( path, st );
    if (ret == -1) return ret;
    if (reparse_tag) *reparse_tag = 0;
    if (S_ISLNK( st->st_mode ))
    {
        ret = stat( path, st );
        if (ret == -1) return ret;
        /* is a symbolic link and a directory, consider these "reparse points" */
        if (S_ISDIR( st->st_mode ))
        {
            *attr |= FILE_ATTRIBUTE_REPARSE_POINT;
            if (reparse_tag) *reparse_tag = IO_REPARSE_TAG_LX_SYMLINK;
        }
    }
    else if (S_ISDIR( st->st_mode ) && (parent_path = malloc( len + 4 )))
    {
        struct stat parent_st;

        /* consider mount points to be reparse points (IO_REPARSE_TAG_MOUNT_POINT) */
        strcpy( parent_path, path );
        strcat( parent_path, "/.." );
        if (!stat( parent_path, &parent_st )
                && (st->st_dev != parent_st.st_dev || st->st_ino == parent_st.st_ino))
        {
            *attr |= FILE_ATTRIBUTE_REPARSE_POINT;
            if (reparse_tag) *reparse_tag = IO_REPARSE_TAG_MOUNT_POINT;
        }

        free( parent_path );
    }
    *attr |= get_file_attributes( st );

#ifdef WINE_IOS
    /* ml910: one listxattr for both names, memoised by (dev, ino, ctime).
     * NOTE the is_hidden_file() fallback below is preserved exactly: it
     * applies whenever the DOS-attribute xattr is absent, which is what a
     * clear IOS_XA_DOSATTR bit means. */
    {
        int xb = ios_xa_bits( path, -1, st );

        if (xb >= 0)
        {
            if (xb & IOS_XA_REPARSE)
            {
                attr_len = ios_xattr_get_raw( path, XATTR_REPARSE, buffer, sizeof(buffer) );
                if (attr_len >= 0 && attr_len >= sizeof(ULONG))
                {
                    *attr |= FILE_ATTRIBUTE_REPARSE_POINT;
                    if (reparse_tag) memcpy( reparse_tag, buffer, sizeof(ULONG) );
                }
            }
            if (xb & IOS_XA_DOSATTR)
            {
                attr_len = ios_xattr_get_raw( path, SAMBA_XATTR_DOS_ATTRIB, attr_data, sizeof(attr_data)-1 );
                if (attr_len != -1)
                {
                    *attr |= parse_samba_dos_attrib_data( attr_data, attr_len );
                    return ret;
                }
            }
            if (is_hidden_file( path )) *attr |= FILE_ATTRIBUTE_HIDDEN;
            return ret;
        }
    }
#endif
    attr_len = xattr_get( path, XATTR_REPARSE, buffer, sizeof(buffer) );
    if (attr_len >= 0 && attr_len >= sizeof(ULONG))
    {
        *attr |= FILE_ATTRIBUTE_REPARSE_POINT;
        if (reparse_tag) memcpy( reparse_tag, buffer, sizeof(ULONG) );
    }

    attr_len = xattr_get( path, SAMBA_XATTR_DOS_ATTRIB, attr_data, sizeof(attr_data)-1 );
    if (attr_len != -1)
        *attr |= parse_samba_dos_attrib_data( attr_data, attr_len );
    else
    {
        if (is_hidden_file( path ))
            *attr |= FILE_ATTRIBUTE_HIDDEN;
        if (errno == ENOTSUP) return ret;
#ifdef ENODATA
        if (errno == ENODATA) return ret;
#endif
#ifdef ENOATTR
        if (errno == ENOATTR) return ret;
#endif
        WARN( "Failed to get extended attribute " SAMBA_XATTR_DOS_ATTRIB " from %s. errno %d (%s)\n",
              debugstr_a(path), errno, strerror( errno ) );
    }
    return ret;
}


#if defined(__ANDROID__) && !defined(HAVE_FUTIMENS)
static int futimens( int fd, const struct timespec spec[2] )
{
    return syscall( __NR_utimensat, fd, NULL, spec, 0 );
}
#define HAVE_FUTIMENS
#endif  /* __ANDROID__ */

#ifndef UTIME_OMIT
#define UTIME_OMIT ((1 << 30) - 2)
#endif

static BOOL set_file_times_precise( int fd, const LARGE_INTEGER *mtime,
                                    const LARGE_INTEGER *atime, NTSTATUS *status )
{
#ifdef HAVE_FUTIMENS
    struct timespec tv[2];

    tv[0].tv_sec = tv[1].tv_sec = 0;
    tv[0].tv_nsec = tv[1].tv_nsec = UTIME_OMIT;
    if (atime->QuadPart)
    {
        tv[0].tv_sec = atime->QuadPart / 10000000 - SECS_1601_TO_1970;
        tv[0].tv_nsec = (atime->QuadPart % 10000000) * 100;
    }
    if (mtime->QuadPart)
    {
        tv[1].tv_sec = mtime->QuadPart / 10000000 - SECS_1601_TO_1970;
        tv[1].tv_nsec = (mtime->QuadPart % 10000000) * 100;
    }
#ifdef __APPLE__
    if (!&futimens) return FALSE;
#endif
    if (futimens( fd, tv ) == -1) *status = errno_to_status( errno );
    else *status = STATUS_SUCCESS;
    return TRUE;
#else
    return FALSE;
#endif
}


static NTSTATUS set_file_times( int fd, const LARGE_INTEGER *mtime, const LARGE_INTEGER *atime )
{
    NTSTATUS status = STATUS_SUCCESS;
#if defined(HAVE_FUTIMES) || defined(HAVE_FUTIMESAT)
    struct timeval tv[2];
    struct stat st;
#endif

    if (set_file_times_precise( fd, mtime, atime, &status ))
        return status;

#if defined(HAVE_FUTIMES) || defined(HAVE_FUTIMESAT)
    if (!atime->QuadPart || !mtime->QuadPart)
    {

        tv[0].tv_sec = tv[0].tv_usec = 0;
        tv[1].tv_sec = tv[1].tv_usec = 0;
        if (!fstat( fd, &st ))
        {
            tv[0].tv_sec = st.st_atime;
            tv[1].tv_sec = st.st_mtime;
#ifdef HAVE_STRUCT_STAT_ST_ATIM
            tv[0].tv_usec = st.st_atim.tv_nsec / 1000;
#elif defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
            tv[0].tv_usec = st.st_atimespec.tv_nsec / 1000;
#endif
#ifdef HAVE_STRUCT_STAT_ST_MTIM
            tv[1].tv_usec = st.st_mtim.tv_nsec / 1000;
#elif defined(HAVE_STRUCT_STAT_ST_MTIMESPEC)
            tv[1].tv_usec = st.st_mtimespec.tv_nsec / 1000;
#endif
        }
    }
    if (atime->QuadPart)
    {
        tv[0].tv_sec = atime->QuadPart / 10000000 - SECS_1601_TO_1970;
        tv[0].tv_usec = (atime->QuadPart % 10000000) / 10;
    }
    if (mtime->QuadPart)
    {
        tv[1].tv_sec = mtime->QuadPart / 10000000 - SECS_1601_TO_1970;
        tv[1].tv_usec = (mtime->QuadPart % 10000000) / 10;
    }
#ifdef HAVE_FUTIMES
    if (futimes( fd, tv ) == -1) status = errno_to_status( errno );
#elif defined(HAVE_FUTIMESAT)
    if (futimesat( fd, NULL, tv ) == -1) status = errno_to_status( errno );
#endif

#else  /* HAVE_FUTIMES || HAVE_FUTIMESAT */
    FIXME( "setting file times not supported\n" );
    status = STATUS_NOT_IMPLEMENTED;
#endif
    return status;
}


static inline void get_file_times( const struct stat *st, LARGE_INTEGER *mtime, LARGE_INTEGER *ctime,
                                   LARGE_INTEGER *atime, LARGE_INTEGER *creation )
{
    mtime->QuadPart = ticks_from_time_t( st->st_mtime );
    ctime->QuadPart = ticks_from_time_t( st->st_ctime );
    atime->QuadPart = ticks_from_time_t( st->st_atime );
#ifdef HAVE_STRUCT_STAT_ST_MTIM
    mtime->QuadPart += st->st_mtim.tv_nsec / 100;
#elif defined(HAVE_STRUCT_STAT_ST_MTIMESPEC)
    mtime->QuadPart += st->st_mtimespec.tv_nsec / 100;
#endif
#ifdef HAVE_STRUCT_STAT_ST_CTIM
    ctime->QuadPart += st->st_ctim.tv_nsec / 100;
#elif defined(HAVE_STRUCT_STAT_ST_CTIMESPEC)
    ctime->QuadPart += st->st_ctimespec.tv_nsec / 100;
#endif
#ifdef HAVE_STRUCT_STAT_ST_ATIM
    atime->QuadPart += st->st_atim.tv_nsec / 100;
#elif defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
    atime->QuadPart += st->st_atimespec.tv_nsec / 100;
#endif
#ifdef HAVE_STRUCT_STAT_ST_BIRTHTIME
    creation->QuadPart = ticks_from_time_t( st->st_birthtime );
#ifdef HAVE_STRUCT_STAT_ST_BIRTHTIM
    creation->QuadPart += st->st_birthtim.tv_nsec / 100;
#elif defined(HAVE_STRUCT_STAT_ST_BIRTHTIMESPEC)
    creation->QuadPart += st->st_birthtimespec.tv_nsec / 100;
#endif
#elif defined(HAVE_STRUCT_STAT___ST_BIRTHTIME)
    creation->QuadPart = ticks_from_time_t( st->__st_birthtime );
#ifdef HAVE_STRUCT_STAT___ST_BIRTHTIM
    creation->QuadPart += st->__st_birthtim.tv_nsec / 100;
#endif
#else
    *creation = *mtime;
#endif
}


/* fill in the file information that depends on the stat and attribute info */
static NTSTATUS fill_file_info( const struct stat *st, ULONG attr, void *ptr,
                                FILE_INFORMATION_CLASS class )
{
    switch (class)
    {
    case FileBasicInformation:
        {
            FILE_BASIC_INFORMATION *info = ptr;

            get_file_times( st, &info->LastWriteTime, &info->ChangeTime,
                            &info->LastAccessTime, &info->CreationTime );
            info->FileAttributes = attr;
        }
        break;
    case FileStandardInformation:
        {
            FILE_STANDARD_INFORMATION *info = ptr;

            if ((info->Directory = S_ISDIR(st->st_mode)))
            {
                info->AllocationSize.QuadPart = 0;
                info->EndOfFile.QuadPart      = 0;
                info->NumberOfLinks           = 1;
            }
            else
            {
                info->AllocationSize.QuadPart = (ULONGLONG)st->st_blocks * 512;
                info->EndOfFile.QuadPart      = st->st_size;
                info->NumberOfLinks           = st->st_nlink;
            }
        }
        break;
    case FileInternalInformation:
        {
            FILE_INTERNAL_INFORMATION *info = ptr;
            info->IndexNumber.QuadPart = st->st_ino;
        }
        break;
    case FileEndOfFileInformation:
        {
            FILE_END_OF_FILE_INFORMATION *info = ptr;
            info->EndOfFile.QuadPart = S_ISDIR(st->st_mode) ? 0 : st->st_size;
        }
        break;
    case FileAllInformation:
        {
            FILE_ALL_INFORMATION *info = ptr;
            fill_file_info( st, attr, &info->BasicInformation, FileBasicInformation );
            fill_file_info( st, attr, &info->StandardInformation, FileStandardInformation );
            fill_file_info( st, attr, &info->InternalInformation, FileInternalInformation );
        }
        break;
    case FileNetworkOpenInformation:
        {
            FILE_NETWORK_OPEN_INFORMATION *info = ptr;
            get_file_times( st, &info->LastWriteTime, &info->ChangeTime,
                            &info->LastAccessTime, &info->CreationTime );
            info->FileAttributes = attr;
            if (S_ISDIR(st->st_mode))
            {
                info->AllocationSize.QuadPart = 0;
                info->EndOfFile.QuadPart      = 0;
            }
            else
            {
                info->AllocationSize.QuadPart = (ULONGLONG)st->st_blocks * 512;
                info->EndOfFile.QuadPart      = st->st_size;
            }
        }
        break;
    /* all directory structures start with the FileDirectoryInformation layout */
    case FileBothDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileDirectoryInformation:
        {
            FILE_DIRECTORY_INFORMATION *info = ptr;

            get_file_times( st, &info->LastWriteTime, &info->ChangeTime,
                            &info->LastAccessTime, &info->CreationTime );
            if (S_ISDIR(st->st_mode))
            {
                info->AllocationSize.QuadPart = 0;
                info->EndOfFile.QuadPart      = 0;
            }
            else
            {
                info->AllocationSize.QuadPart = (ULONGLONG)st->st_blocks * 512;
                info->EndOfFile.QuadPart      = st->st_size;
            }
            info->FileAttributes = attr;
        }
        break;
    case FileIdFullDirectoryInformation:
        {
            FILE_ID_FULL_DIRECTORY_INFORMATION *info = ptr;
            info->FileId.QuadPart = st->st_ino;
            fill_file_info( st, attr, info, FileDirectoryInformation );
        }
        break;
    case FileIdBothDirectoryInformation:
        {
            FILE_ID_BOTH_DIRECTORY_INFORMATION *info = ptr;
            info->FileId.QuadPart = st->st_ino;
            fill_file_info( st, attr, info, FileDirectoryInformation );
        }
        break;
    case FileIdExtdBothDirectoryInformation:
        {
            FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION *info = ptr;
            memset( &info->FileId, 0, sizeof(info->FileId) );
            *(ULONGLONG *)&info->FileId = st->st_ino;
            fill_file_info( st, attr, info, FileDirectoryInformation );
        }
        break;
    case FileIdGlobalTxDirectoryInformation:
        {
            FILE_ID_GLOBAL_TX_DIR_INFORMATION *info = ptr;
            info->FileId.QuadPart = st->st_ino;
            fill_file_info( st, attr, info, FileDirectoryInformation );
        }
        break;

    default:
        return STATUS_INVALID_INFO_CLASS;
    }
    return STATUS_SUCCESS;
}


static unsigned int server_get_unix_name( HANDLE handle, char **unix_name )
{
    data_size_t size = 1024;
    unsigned int ret;
    char *name;

    for (;;)
    {
        if (!(name = malloc( size + 1 ))) return STATUS_NO_MEMORY;

        SERVER_START_REQ( get_handle_unix_name )
        {
            req->handle = wine_server_obj_handle( handle );
            wine_server_set_reply( req, name, size );
            ret = wine_server_call( req );
            size = reply->name_len;
        }
        SERVER_END_REQ;

        if (!ret)
        {
            name[size] = 0;
            *unix_name = name;
            break;
        }
        free( name );
        if (ret != STATUS_BUFFER_OVERFLOW) break;
    }
    return ret;
}

static NTSTATUS server_get_name_info( HANDLE handle, FILE_NAME_INFORMATION *info, LONG *name_len )
{
    data_size_t size = 1024;
    NTSTATUS status;
    OBJECT_NAME_INFORMATION *name;

    for (;;)
    {
        if (!(name = malloc( size ))) return STATUS_NO_MEMORY;
        if (!(status = NtQueryObject( handle, ObjectNameInformation, name, size, &size )))
        {
            const WCHAR *ptr = name->Name.Buffer;
            const WCHAR *end = ptr + name->Name.Length / sizeof(WCHAR);

            /* Skip the volume mount point. */
            while (ptr != end && *ptr == '\\') ++ptr;
            while (ptr != end && *ptr != '\\') ++ptr;
            while (ptr != end && *ptr == '\\') ++ptr;
            while (ptr != end && *ptr != '\\') ++ptr;

            info->FileNameLength = (end - ptr) * sizeof(WCHAR);
            if (*name_len < info->FileNameLength) status = STATUS_BUFFER_OVERFLOW;
            else if (!info->FileNameLength) status = STATUS_INVALID_INFO_CLASS;
            else *name_len = info->FileNameLength;
            if (info->FileNameLength) memcpy( info->FileName, ptr, *name_len );
            free( name );
        }
        else
        {
            free( name );
            if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW) continue;
        }
        return status;
    }
}


#ifdef __APPLE__
static LONGLONG get_free_bytes_for_important_data(int fd)
{
    CFURLRef url = NULL;
    CFNumberRef num = NULL;
    char *path = NULL;
    LONGLONG space = -1;

    if (!(path = malloc( MAXPATHLEN ))) goto done;
    if (fcntl( fd, F_GETPATH, path ) == -1) goto done;
    if (!(url = CFURLCreateFromFileSystemRepresentation( NULL, (UInt8 *)path, strlen(path), false ))) goto done;
    if (!CFURLCopyResourcePropertyForKey( url, kCFURLVolumeAvailableCapacityForImportantUsageKey, &num, NULL )) goto done;
    CFNumberGetValue( num, kCFNumberLongLongType, &space );

done:
    free( path );
    if (url) CFRelease( url );
    if (num) CFRelease( num );
    return space;
}
#endif

static NTSTATUS get_full_size_info(int fd, FILE_FS_FULL_SIZE_INFORMATION *info) {
    struct stat st;
    ULONGLONG bsize;

#if !defined(linux) || !defined(HAVE_FSTATFS)
    struct statvfs stfs;
#else
    struct statfs stfs;
#endif

#ifdef __APPLE__
    LONGLONG important_free_bytes;
#endif

    if (fstat( fd, &st ) < 0) return errno_to_status( errno );
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) return STATUS_INVALID_DEVICE_REQUEST;

    /* Linux's fstatvfs is buggy */
#if !defined(linux) || !defined(HAVE_FSTATFS)
    if (fstatvfs( fd, &stfs ) < 0) return errno_to_status( errno );
    bsize = stfs.f_frsize;
#else
    if (fstatfs( fd, &stfs ) < 0) return errno_to_status( errno );
    bsize = stfs.f_bsize;
#endif

#ifdef __APPLE__
    important_free_bytes = get_free_bytes_for_important_data( fd );
    if (important_free_bytes != -1) stfs.f_bavail = stfs.f_bfree = important_free_bytes / bsize;
#endif

    if (bsize == 2048)  /* assume CD-ROM */
    {
        info->BytesPerSector = 2048;
        info->SectorsPerAllocationUnit = 1;
    }
    else
    {
        info->BytesPerSector = 512;
        info->SectorsPerAllocationUnit = 8;
    }
    info->TotalAllocationUnits.QuadPart = bsize * stfs.f_blocks / (info->BytesPerSector * info->SectorsPerAllocationUnit);
    info->CallerAvailableAllocationUnits.QuadPart = bsize * stfs.f_bavail / (info->BytesPerSector * info->SectorsPerAllocationUnit);
    info->ActualAvailableAllocationUnits.QuadPart = bsize * stfs.f_bfree / (info->BytesPerSector * info->SectorsPerAllocationUnit);
    return STATUS_SUCCESS;
}

static NTSTATUS get_full_size_info_ex(int fd, FILE_FS_FULL_SIZE_INFORMATION_EX *info)
{
    FILE_FS_FULL_SIZE_INFORMATION full_info;
    NTSTATUS status;

    if ((status = get_full_size_info(fd, &full_info)) != STATUS_SUCCESS)
        return status;

    info->ActualTotalAllocationUnits = full_info.TotalAllocationUnits.QuadPart;
    info->ActualAvailableAllocationUnits = full_info.ActualAvailableAllocationUnits.QuadPart;
    info->ActualPoolUnavailableAllocationUnits = 0;
    info->CallerAvailableAllocationUnits = full_info.CallerAvailableAllocationUnits.QuadPart;
    info->CallerPoolUnavailableAllocationUnits = 0;
    info->UsedAllocationUnits = info->ActualTotalAllocationUnits - info->ActualAvailableAllocationUnits;
    info->CallerTotalAllocationUnits = info->CallerAvailableAllocationUnits + info->UsedAllocationUnits;
    info->TotalReservedAllocationUnits = 0;
    info->VolumeStorageReserveAllocationUnits = 0;
    info->AvailableCommittedAllocationUnits = 0;
    info->PoolAvailableAllocationUnits = 0;
    info->SectorsPerAllocationUnit = full_info.SectorsPerAllocationUnit;
    info->BytesPerSector = full_info.BytesPerSector;

    return STATUS_SUCCESS;
}


static NTSTATUS server_get_file_info( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer,
                                      ULONG length, FILE_INFORMATION_CLASS info_class )
{
    SERVER_START_REQ( get_file_info )
    {
        req->handle = wine_server_obj_handle( handle );
        req->info_class = info_class;
        wine_server_set_reply( req, buffer, length );
        io->Status = wine_server_call( req );
        io->Information = wine_server_reply_size( reply );
    }
    SERVER_END_REQ;
    if (io->Status == STATUS_NOT_IMPLEMENTED)
        FIXME( "Unsupported info class %x\n", info_class );
    return io->Status;

}


static unsigned int server_open_file_object( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                             ULONG sharing, ULONG options )
{
    unsigned int status;

    SERVER_START_REQ( open_file_object )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        req->sharing    = sharing;
        req->options    = options;
        wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}


/* retrieve device/inode number for all the drives */
static unsigned int get_drives_info( struct file_identity info[MAX_DOS_DRIVES] )
{
    static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
    static struct file_identity cache[MAX_DOS_DRIVES];
    static time_t last_update;
    static unsigned int nb_drives;
    unsigned int ret;
    time_t now = time(NULL);

    mutex_lock( &cache_mutex );
    if (now != last_update)
    {
        char *buffer, *p;
        struct stat st;
        unsigned int i;

        if (asprintf( &buffer, "%s/dosdevices/a:", config_dir ) != -1)
        {
            p = buffer + strlen(buffer) - 2;

            for (i = nb_drives = 0; i < MAX_DOS_DRIVES; i++)
            {
                *p = 'a' + i;
                if (!stat( buffer, &st ))
                {
                    cache[i].dev = st.st_dev;
                    cache[i].ino = st.st_ino;
                    nb_drives++;
                }
                else
                {
                    cache[i].dev = 0;
                    cache[i].ino = 0;
                }
            }
            free( buffer );
        }
        last_update = now;
    }
    memcpy( info, cache, sizeof(cache) );
    ret = nb_drives;
    mutex_unlock( &cache_mutex );
    return ret;
}


/* Find a DOS device which can act as the root of "path".
 * Similar to find_drive_root(), but returns -1 instead of crossing volumes. */
static int find_dos_device( const char *path )
{
    int len = strlen(path);
    int drive;
    char *buffer;
    struct stat st;
    struct file_identity info[MAX_DOS_DRIVES];
    dev_t dev_id;

    if (!get_drives_info( info )) return -1;

    if (stat( path, &st ) < 0) return -1;
    dev_id = st.st_dev;

    /* strip off trailing slashes */
    while (len > 1 && path[len - 1] == '/') len--;

    /* make a copy of the path */
    if (!(buffer = malloc( len + 1 ))) return -1;
    memcpy( buffer, path, len );
    buffer[len] = 0;

    for (;;)
    {
        if (!stat( buffer, &st ) && S_ISDIR( st.st_mode ))
        {
            if (st.st_dev != dev_id) break;

            for (drive = 0; drive < MAX_DOS_DRIVES; drive++)
            {
                if ((info[drive].dev == st.st_dev) && (info[drive].ino == st.st_ino))
                {
                    TRACE( "%s -> drive %c:, root=%s, name=%s\n",
                           debugstr_a(path), 'A' + drive, debugstr_a(buffer), debugstr_a(path + len));
                    free( buffer );
                    return drive;
                }
            }
        }
        if (len <= 1) break;  /* reached root */
        while (len > 1 && path[len - 1] != '/') len--;
        while (len > 1 && path[len - 1] == '/') len--;
        buffer[len] = 0;
    }
    free( buffer );
    return -1;
}

static NTSTATUS get_mountmgr_fs_info( HANDLE handle, int fd, struct mountmgr_unix_drive *drive, ULONG size )
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING string;
    char *unix_name;
    HANDLE mountmgr;
    unsigned int status;
    int letter = -1;

    if (!server_get_unix_name( handle, &unix_name ))
    {
        letter = find_dos_device( unix_name );
        free( unix_name );
    }
    memset( drive, 0, sizeof(*drive) );
    if (letter == -1)
    {
        struct stat st;

        fstat( fd, &st );
        drive->unix_dev = st.st_rdev ? st.st_rdev : st.st_dev;
    }
    else
        drive->letter = 'a' + letter;

    init_unicode_string( &string, MOUNTMGR_DEVICE_NAME );
    InitializeObjectAttributes( &attr, &string, 0, NULL, NULL );
    status = server_open_file_object( &mountmgr, GENERIC_READ | SYNCHRONIZE, &attr,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT );
    if (status) return status;

    status = sync_ioctl( mountmgr, IOCTL_MOUNTMGR_QUERY_UNIX_DRIVE, drive, sizeof(*drive), drive, size );
    NtClose( mountmgr );
    if (status == STATUS_BUFFER_OVERFLOW) status = STATUS_SUCCESS;
    else if (status) WARN("failed to retrieve filesystem type from mountmgr, status %#x\n", status);
    return status;
}


/***********************************************************************
 *           get_volume_serial_fallback      (iOS-Madeira ml1030)
 *
 * A STABLE volume serial for a host that has no mount manager.
 *
 * Stability is the whole requirement: a program records a serial when it
 * installs and compares it when it launches, so the value has to survive a
 * reboot, a relaunch and a reinstall of the emulator.  It is therefore derived
 * from the FILESYSTEM's mount point — a property of the volume, not of this
 * process — and mixed with the DOS drive letter so that two drive letters
 * backed by the same filesystem still get different serials, which is the
 * distinction Windows draws.  st_dev is the fallback where there is no
 * f_mntonname; it is stable per boot, which is weaker but still far better than
 * failing the call.
 *
 * 0 is never returned: a great many callers treat a zero serial as "no volume".
 */
static DWORD get_volume_serial_fallback( int fd, WCHAR letter )
{
    UINT h = 2166136261u;     /* FNV-1a */
    BOOL hashed = FALSE;

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || \
    defined(__DragonFly__) || defined(__APPLE__)
    {
        struct statfs stfs;

        if (!fstatfs( fd, &stfs ))
        {
            const char *p;

            for (p = stfs.f_mntonname; *p; p++) { h ^= (unsigned char)*p; h *= 16777619u; }
            hashed = TRUE;
        }
    }
#endif
    if (!hashed)
    {
        struct stat st;

        if (!fstat( fd, &st ))
        {
            unsigned long long dev = st.st_dev;
            unsigned i;

            for (i = 0; i < sizeof(dev); i++) { h ^= (unsigned char)(dev >> (i * 8)); h *= 16777619u; }
        }
    }
    if (letter) { h ^= (unsigned char)letter; h *= 16777619u; }
    if (!h || h == 0xffffffff) h = 0x57494e45;   /* 'WINE' — never hand out 0 or -1 */
    return h;
}


/***********************************************************************
 *           get_dir_data_entry
 *
 * Return a directory entry from the cached data.
 */
static NTSTATUS get_dir_data_entry( struct dir_data *dir_data, void *info_ptr, IO_STATUS_BLOCK *io,
                                    ULONG max_length, FILE_INFORMATION_CLASS class,
                                    union file_directory_info **last_info )
{
    const struct dir_data_names *names = &dir_data->names[dir_data->pos];
    union file_directory_info *info;
    struct stat st;
    ULONG name_len, start, dir_size, attributes, reparse_tag;

    if (get_file_info( names->unix_name, &st, &attributes, &reparse_tag ) == -1)
    {
        TRACE( "file no longer exists %s\n", debugstr_a(names->unix_name) );
        return STATUS_SUCCESS;
    }
    if (is_ignored_file( &st ))
    {
        TRACE( "ignoring file %s\n", debugstr_a(names->unix_name) );
        return STATUS_SUCCESS;
    }
    start = dir_info_align( io->Information );
    dir_size = dir_info_size( class, 0 );
    if (start + dir_size > max_length) return STATUS_MORE_ENTRIES;

    max_length -= start + dir_size;
    name_len = wcslen( names->long_name ) * sizeof(WCHAR);
    /* if this is not the first entry, fail; the first entry is always returned (but truncated) */
    if (*last_info && name_len > max_length) return STATUS_MORE_ENTRIES;

    info = (union file_directory_info *)((char *)info_ptr + start);
    info->dir.NextEntryOffset = 0;
    info->dir.FileIndex = 0;  /* NTFS always has 0 here, so let's not bother with it */

    /* all the structures except FileNamesInformation start with a FileDirectoryInformation layout */
    if (class != FileNamesInformation)
    {
        if (st.st_dev != dir_data->id.dev) st.st_ino = 0;  /* ignore inode if on a different device */
        fill_file_info( &st, attributes, info, class );
    }

    switch (class)
    {
    case FileDirectoryInformation:
        info->dir.FileNameLength = name_len;
        break;

    case FileFullDirectoryInformation:
        /* non-Extd classes return the reparse tag in EaSize if there is one */
        info->full.EaSize = reparse_tag;
        info->full.FileNameLength = name_len;
        break;

    case FileIdFullDirectoryInformation:
        info->id_full.EaSize = reparse_tag;
        info->id_full.FileNameLength = name_len;
        break;

    case FileBothDirectoryInformation:
        info->both.EaSize = reparse_tag;
        info->both.ShortNameLength = wcslen( names->short_name ) * sizeof(WCHAR);
        memcpy( info->both.ShortName, names->short_name, info->both.ShortNameLength );
        info->both.FileNameLength = name_len;
        break;

    case FileIdBothDirectoryInformation:
        info->id_both.EaSize = reparse_tag;
        info->id_both.ShortNameLength = wcslen( names->short_name ) * sizeof(WCHAR);
        memcpy( info->id_both.ShortName, names->short_name, info->id_both.ShortNameLength );
        info->id_both.FileNameLength = name_len;
        break;

    case FileIdExtdBothDirectoryInformation:
        /* Extd classes do *not* return the reparse tag in EaSize */
        info->extd_both.EaSize = 0; /* FIXME */
        info->extd_both.ReparsePointTag = reparse_tag;
        info->extd_both.ShortNameLength = wcslen( names->short_name ) * sizeof(WCHAR);
        memcpy( info->extd_both.ShortName, names->short_name, info->extd_both.ShortNameLength );
        info->extd_both.FileNameLength = name_len;
        break;

    case FileIdGlobalTxDirectoryInformation:
        info->id_tx.TxInfoFlags = 0;
        memset( &info->id_tx.LockingTransactionId, 0, sizeof(GUID) );
        info->id_tx.FileNameLength = name_len;
        break;

    case FileNamesInformation:
        info->names.FileNameLength = name_len;
        break;

    default:
        assert(0);
        return 0;
    }

    memcpy( (char *)info + dir_size, names->long_name, min( name_len, max_length ) );
    io->Information = start + dir_size + min( name_len, max_length );
    if (*last_info) (*last_info)->next = (char *)info - (char *)*last_info;
    *last_info = info;
    return name_len > max_length ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

#ifdef VFAT_IOCTL_READDIR_BOTH

/***********************************************************************
 *           read_directory_vfat
 *
 * Read a directory using the VFAT ioctl; helper for NtQueryDirectoryFile.
 */
static NTSTATUS read_directory_data_vfat( struct dir_data *data, int fd, const UNICODE_STRING *mask )
{
    char *short_name, *long_name;
    KERNEL_DIRENT de[2];
    NTSTATUS status = STATUS_NO_MEMORY;
    off_t old_pos = lseek( fd, 0, SEEK_CUR );

    lseek( fd, 0, SEEK_SET );

    if (ioctl( fd, VFAT_IOCTL_READDIR_BOTH, (long)de ) == -1)
    {
        if (errno != ENOENT)
        {
            status = STATUS_NOT_SUPPORTED;
            goto done;
        }
        de[0].d_reclen = 0;
    }

    if (!append_entry( data, ".", NULL, mask )) goto done;
    if (!append_entry( data, "..", NULL, mask )) goto done;

    while (de[0].d_reclen)
    {
        if (strcmp( de[0].d_name, "." ) && strcmp( de[0].d_name, ".." ))
        {
            if (de[1].d_name[0])
            {
                short_name = de[0].d_name;
                long_name = de[1].d_name;
            }
            else
            {
                long_name = de[0].d_name;
                short_name = NULL;
            }
            if (!append_entry( data, long_name, short_name, mask )) goto done;
        }
        if (ioctl( fd, VFAT_IOCTL_READDIR_BOTH, (long)de ) == -1) break;
    }
    status = STATUS_SUCCESS;
done:
    lseek( fd, old_pos, SEEK_SET );
    return status;
}
#endif /* VFAT_IOCTL_READDIR_BOTH */


#ifdef HAVE_GETATTRLIST
/***********************************************************************
 *           read_directory_getattrlist
 *
 * Read a single file from a directory by determining whether the file
 * identified by mask exists using getattrlist.
 */
static NTSTATUS read_directory_data_getattrlist( struct dir_data *data, const char *unix_name )
{
    struct attrlist attrlist;
#pragma pack(push,4)
    struct
    {
        u_int32_t length;
        struct attrreference name_reference;
        fsobj_type_t type;
        char name[NAME_MAX * 3 + 1];
    } buffer;
#pragma pack(pop)

    memset( &attrlist, 0, sizeof(attrlist) );
    attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrlist.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
    if (getattrlist( unix_name, &attrlist, &buffer, sizeof(buffer), FSOPT_NOFOLLOW ) == -1)
        return STATUS_NO_SUCH_FILE;
    /* If unix_name named a symlink, the above may have succeeded even if the symlink is broken.
       Check that with another call without FSOPT_NOFOLLOW.  We don't ask for any attributes. */
    if (buffer.type == VLNK)
    {
        u_int32_t dummy;
        attrlist.commonattr = 0;
        if (getattrlist( unix_name, &attrlist, &dummy, sizeof(dummy), 0 ) == -1)
            return STATUS_NO_SUCH_FILE;
    }

    TRACE( "found %s\n", debugstr_a(buffer.name) );

    if (!append_entry( data, buffer.name, NULL, NULL )) return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;
}
#endif  /* HAVE_GETATTRLIST */


/***********************************************************************
 *           read_directory_stat
 *
 * Read a single file from a directory by determining whether the file
 * identified by mask exists using stat.
 */
static NTSTATUS read_directory_data_stat( struct dir_data *data, const char *unix_name )
{
    struct stat st;

    /* if the file system is not case sensitive we can't find the actual name through stat() */
    if (!get_dir_case_sensitivity( AT_FDCWD, "." )) return STATUS_NO_SUCH_FILE;
    if (stat( unix_name, &st ) == -1) return STATUS_NO_SUCH_FILE;

    TRACE( "found %s\n", debugstr_a(unix_name) );

    if (!append_entry( data, unix_name, NULL, NULL )) return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;
}


/***********************************************************************
 *           read_directory_readdir
 *
 * Read a directory using the POSIX readdir interface; helper for NtQueryDirectoryFile.
 */
static NTSTATUS read_directory_data_readdir( struct dir_data *data, const UNICODE_STRING *mask )
{
    struct dirent *de;
    NTSTATUS status = STATUS_NO_MEMORY;
    DIR *dir = opendir( "." );

    if (!dir) return STATUS_NO_SUCH_FILE;

    if (!append_entry( data, ".", NULL, mask )) goto done;
    if (!append_entry( data, "..", NULL, mask )) goto done;
    while ((de = readdir( dir )))
    {
        if (!strcmp( de->d_name, "." ) || !strcmp( de->d_name, ".." )) continue;
        if (!append_entry( data, de->d_name, NULL, mask )) goto done;
    }
    status = STATUS_SUCCESS;

done:
    closedir( dir );
    return status;
}


/***********************************************************************
 *           read_directory_data
 *
 * Read the full contents of a directory, using one of the above helper functions.
 */
static NTSTATUS read_directory_data( struct dir_data *data, int fd, const UNICODE_STRING *mask )
{
    NTSTATUS status;

#ifdef VFAT_IOCTL_READDIR_BOTH
    if (!(status = read_directory_data_vfat( data, fd, mask ))) return status;
#endif

    if (!has_wildcard( mask ))
    {
        /* convert the mask to a Unix name and check for it */
        char unix_name[MAX_DIR_ENTRY_LEN * 3 + 1];
        int ret = ntdll_wcstoumbs( mask->Buffer, mask->Length / sizeof(WCHAR),
                                   unix_name, sizeof(unix_name) - 1, TRUE );
        if (ret > 0)
        {
            unix_name[ret] = 0;
#ifdef HAVE_GETATTRLIST
            if (!(status = read_directory_data_getattrlist( data, unix_name ))) return status;
#endif
            if (!(status = read_directory_data_stat( data, unix_name ))) return status;
        }
    }

    return read_directory_data_readdir( data, mask );
}


/* compare file names for directory sorting */
static int name_compare( const void *a, const void *b )
{
    const struct dir_data_names *file_a = (const struct dir_data_names *)a;
    const struct dir_data_names *file_b = (const struct dir_data_names *)b;
    int ret = wcsicmp( file_a->long_name, file_b->long_name );
    if (!ret) ret = wcscmp( file_a->long_name, file_b->long_name );
    return ret;
}


/***********************************************************************
 *           init_cached_dir_data
 *
 * Initialize the cached directory contents.
 */
static NTSTATUS init_cached_dir_data( struct dir_data **data_ret, int fd, const UNICODE_STRING *mask )
{
    struct dir_data *data;
    struct stat st;
    NTSTATUS status;
    unsigned int i;

    if (!(data = calloc( 1, sizeof(*data) ))) return STATUS_NO_MEMORY;

    if ((status = read_directory_data( data, fd, mask )))
    {
        free_dir_data( data );
        return status;
    }

    if (mask)
    {
        data->mask.Length = data->mask.MaximumLength = mask->Length;
        if (!(data->mask.Buffer = malloc( mask->Length )))
        {
            free_dir_data( data );
            return STATUS_NO_MEMORY;
        }
        memcpy(data->mask.Buffer, mask->Buffer, mask->Length);
    }

    /* sort filenames, but not "." and ".." */
    i = 0;
    if (i < data->count && !strcmp( data->names[i].unix_name, "." )) i++;
    if (i < data->count && !strcmp( data->names[i].unix_name, ".." )) i++;
    if (i < data->count) qsort( data->names + i, data->count - i, sizeof(*data->names), name_compare );

    if (data->count)
    {
        fstat( fd, &st );
        data->id.dev = st.st_dev;
        data->id.ino = st.st_ino;
    }

    TRACE( "mask %s found %u files\n", debugstr_us( mask ), data->count );
    for (i = 0; i < data->count; i++)
        TRACE( "%s %s\n", debugstr_w(data->names[i].long_name), debugstr_w(data->names[i].short_name) );

    *data_ret = data;
    return data->count ? STATUS_SUCCESS : STATUS_NO_SUCH_FILE;
}


/***********************************************************************
 *           ustring_equal
 *
 * Simplified version of RtlEqualUnicodeString that performs only case-sensitive comparisons.
 */
static BOOLEAN ustring_equal( const UNICODE_STRING *a, const UNICODE_STRING *b )
{
    USHORT length_a = (a ? a->Length : 0);
    USHORT length_b = (b ? b->Length : 0);

    if (length_a != length_b) return FALSE;
    if (length_a == 0) return TRUE;
    return !memcmp(a->Buffer, b->Buffer, a->Length);
}


/***********************************************************************
 *           get_cached_dir_data
 *
 * Retrieve the cached directory data, or initialize it if necessary.
 */
static unsigned int get_cached_dir_data( HANDLE handle, struct dir_data **data_ret, int fd,
                                         const UNICODE_STRING *mask, BOOLEAN restart_scan )
{
    unsigned int i;
    int entry = -1, free_entries[16];
    unsigned int status;
    BOOLEAN fresh_handle;

    SERVER_START_REQ( get_directory_cache_entry )
    {
        req->handle = wine_server_obj_handle( handle );
        wine_server_set_reply( req, free_entries, sizeof(free_entries) );
        if (!(status = wine_server_call( req ))) entry = reply->entry;

        for (i = 0; i < wine_server_reply_size( reply ) / sizeof(*free_entries); i++)
        {
            int free_idx = free_entries[i];
            if (free_idx < dir_data_cache_size)
            {
                free_dir_data( dir_data_cache[free_idx] );
                dir_data_cache[free_idx] = NULL;
            }
        }
    }
    SERVER_END_REQ;

    if (status)
    {
        if (status == STATUS_SHARING_VIOLATION) FIXME( "shared directory handle not supported yet\n" );
        return status;
    }

    if (entry >= dir_data_cache_size)
    {
        unsigned int size = max( dir_data_cache_initial_size, max( dir_data_cache_size * 2, entry + 1 ) );
        struct dir_data **new_cache = realloc( dir_data_cache, size * sizeof(*new_cache) );

        if (!new_cache) return STATUS_NO_MEMORY;
        memset( new_cache + dir_data_cache_size, 0, (size - dir_data_cache_size) * sizeof(*new_cache) );
        dir_data_cache = new_cache;
        dir_data_cache_size = size;
    }

    fresh_handle = !dir_data_cache[entry];

    if (dir_data_cache[entry] && restart_scan && mask &&
        !ustring_equal(&dir_data_cache[entry]->mask, mask))
    {
        TRACE( "invalidating existing cache entry for handle %p, old mask: \"%s\", new mask: \"%s\"\n",
               handle, debugstr_us(&(dir_data_cache[entry]->mask)), debugstr_us(mask));
        free_dir_data( dir_data_cache[entry] );
        dir_data_cache[entry] = NULL;
    }

    if (!dir_data_cache[entry])
    {
        status = init_cached_dir_data( &dir_data_cache[entry], fd, mask );
        if (status == STATUS_NO_SUCH_FILE && !fresh_handle) status = STATUS_NO_MORE_FILES;
    }

    *data_ret = dir_data_cache[entry];
    if (restart_scan && *data_ret) (*data_ret)->pos = 0;
    return status;
}


/******************************************************************************
 *              NtQueryDirectoryFile   (NTDLL.@)
 */
#ifdef WINE_IOS
/* ml910: wrap-with-macro, so the upstream body below is untouched and the
 * exported symbol is the counting wrapper that follows it. */
#define NtQueryDirectoryFile ios_inner_NtQueryDirectoryFile
#endif
NTSTATUS WINAPI NtQueryDirectoryFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc_routine,
                                      void *apc_context, IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                                      FILE_INFORMATION_CLASS info_class, BOOLEAN single_entry,
                                      UNICODE_STRING *mask, BOOLEAN restart_scan )
{
    int cwd, fd, needs_close;
    enum server_fd_type type;
    struct dir_data *data;
    unsigned int status;

    TRACE("(%p %p %p %p %p %p 0x%08x 0x%08x 0x%08x %s 0x%08x\n",
          handle, event, apc_routine, apc_context, io, buffer,
          length, info_class, single_entry, debugstr_us(mask),
          restart_scan);

    if (event || apc_routine)
    {
        FIXME( "Unsupported yet option\n" );
        return STATUS_NOT_IMPLEMENTED;
    }
    switch (info_class)
    {
    case FileDirectoryInformation:
    case FileBothDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileIdBothDirectoryInformation:
    case FileIdExtdBothDirectoryInformation:
    case FileIdFullDirectoryInformation:
    case FileIdGlobalTxDirectoryInformation:
    case FileNamesInformation:
        if (length < dir_info_align( dir_info_size( info_class, 1 ))) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    case FileObjectIdInformation:
        if (length != sizeof(FILE_OBJECTID_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        return STATUS_INVALID_INFO_CLASS;
    case FileQuotaInformation:
        if (length != sizeof(FILE_QUOTA_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        return STATUS_INVALID_INFO_CLASS;
    case FileReparsePointInformation:
        if (length != sizeof(FILE_REPARSE_POINT_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        return STATUS_INVALID_INFO_CLASS;
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
    if (!buffer) return STATUS_ACCESS_VIOLATION;

    if ((status = server_get_unix_fd( handle, FILE_LIST_DIRECTORY, &fd, &needs_close, &type, NULL )))
        return status;

    if (type != FD_TYPE_DIR)
    {
        if (needs_close) close( fd );
        return STATUS_INVALID_PARAMETER;
    }

    io->Information = 0;
    if (mask && mask->Length == 0) mask = NULL;

    mutex_lock( &dir_mutex );

    cwd = open( ".", O_RDONLY );
    if (fchdir( fd ) != -1)
    {
        if (!(status = get_cached_dir_data( handle, &data, fd, mask, restart_scan )))
        {
            union file_directory_info *last_info = NULL;

            while (!status && data->pos < data->count)
            {
                status = get_dir_data_entry( data, buffer, io, length, info_class, &last_info );
                if (!status || status == STATUS_BUFFER_OVERFLOW) data->pos++;
                if (single_entry && last_info) break;
            }

            if (!last_info) status = STATUS_NO_MORE_FILES;
            else if (status == STATUS_MORE_ENTRIES) status = STATUS_SUCCESS;
        }
        if (cwd == -1 || fchdir( cwd ) == -1) chdir( "/" );
    }
    else status = errno_to_status( errno );

    if (status != STATUS_NO_SUCH_FILE) io->Status = status;

    mutex_unlock( &dir_mutex );

    if (needs_close) close( fd );
    if (cwd != -1) close( cwd );
    TRACE( "=> %x (%ld)\n", status, io->Information );
    return status;
}
#ifdef WINE_IOS
#undef NtQueryDirectoryFile
NTSTATUS WINAPI NtQueryDirectoryFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc_routine,
                                      void *apc_context, IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                                      FILE_INFORMATION_CLASS info_class, BOOLEAN single_entry,
                                      UNICODE_STRING *mask, BOOLEAN restart_scan )
{
    unsigned long long t0 = ios_fs_now_us();
    NTSTATUS status = ios_inner_NtQueryDirectoryFile( handle, event, apc_routine, apc_context, io,
                                                      buffer, length, info_class, single_entry,
                                                      mask, restart_scan );
    ios_fs_note( IOS_OP_QDIR, t0, ios_fs_now_us() );
    return status;
}
#endif


/***********************************************************************
 *           find_file_in_dir
 *
 * Find a file in a directory the hard way, by doing a case-insensitive search.
 * The file found is appended to unix_name at pos.
 * There must be at least MAX_DIR_ENTRY_LEN+2 chars available at pos.
 */
static NTSTATUS find_file_in_dir( int root_fd, char *unix_name, int pos, const WCHAR *name, int length,
                                  BOOLEAN check_case )
{
    WCHAR buffer[MAX_DIR_ENTRY_LEN];
    BOOLEAN is_name_8_dot_3;
    DIR *dir;
    struct dirent *de;
    struct stat st;
    int fd, ret;
#ifdef WINE_IOS
    char ios_key[IOS_PC_KEYMAX];
    int ios_cacheable = 0;
    struct ios_pc_neg ios_neg = { 0 };          /* stamp read back from a negative entry */
    struct ios_pc_neg ios_stamp = { 0 };        /* stamp taken before our own scan */
    int ios_have_neg = 0, ios_have_stamp = 0, ios_scan_errno = 0;
    unsigned long long ios_ph0 = 0, ios_sc0 = 0;
    /* ml915: the directory-contents cache.  ios_pst is the parent's stat,
     * shared by the per-component negative check and the dircache probe so
     * the two never stat the same directory twice. */
    struct stat ios_pst;
    struct ios_dc_stamp ios_dcst = { 0 };
    struct ios_dc_build ios_dcb = { 0 };
    int ios_pst_ok = 0, ios_dcb_on = 0, ios_matched = 0;

    ios_dir_stamp.mtime = 0;
    ios_dir_stamp_ok = 0;
#endif

    /* try a shortcut for this directory */

    unix_name[pos++] = '/';
#ifdef WINE_IOS
    ios_ph0 = ios_fs_now_us();
#endif
    ret = ntdll_wcstoumbs( name, length, unix_name + pos, MAX_DIR_ENTRY_LEN + 1, TRUE );
    if (ret >= 0 && ret <= MAX_DIR_ENTRY_LEN)
    {
        unix_name[pos + ret] = 0;
        if (!fstatat( root_fd, unix_name, &st, 0 ))
        {
#ifdef WINE_IOS
            IOS_FSA( ios_fs_exact, 1 );
            ios_ph_add( IOS_PH_EXACT, ios_ph0 );
#endif
            return STATUS_SUCCESS;
        }
    }
#ifdef WINE_IOS
    ios_ph_add( IOS_PH_EXACT, ios_ph0 );
#endif
    if (check_case) goto not_found;  /* we want an exact match */

#ifdef WINE_IOS
    /* ml910: this component's spelling differs from what the caller asked
     * for.  Upstream now pays getattrlistat + openat + fdopendir + a full
     * getdirentries scan for it, every single time, forever.  Ask the
     * resolved-name cache first; one fstatat re-validates the answer. */
    IOS_FSA( ios_fs_scan, 1 );
    if (root_fd != AT_FDCWD) IOS_FSA( ios_fs_pc_m_root, 1 );
    else if (ret <= 0 || ret > MAX_DIR_ENTRY_LEN) IOS_FSA( ios_fs_pc_m_key, 1 );
    else if (!ios_pc_key( ios_key, sizeof(ios_key), unix_name, pos + ret, pos ))
        IOS_FSA( ios_fs_pc_m_key, 1 );         /* parent path + name over IOS_PC_KEYMAX */
    else
    {
        int r;
        ios_cacheable = 1;
        ios_ph0 = ios_fs_now_us();
        r = ios_pc_lookup( ios_key, unix_name + pos, MAX_DIR_ENTRY_LEN + 1, &ios_neg );
        if (r == 1)
        {
            IOS_FSA( ios_fs_pc_hit, 1 );
            if (!fstatat( root_fd, unix_name, &st, 0 ))
            {
                ios_ph_add( IOS_PH_PCACHE, ios_ph0 );
                return STATUS_SUCCESS;
            }
            IOS_FSA( ios_fs_pc_stale, 1 );
            /* the cached spelling is gone: restore what was asked for and
             * let the upstream scan below produce a fresh answer */
            ntdll_wcstoumbs( name, length, unix_name + pos, MAX_DIR_ENTRY_LEN + 1, TRUE );
            unix_name[pos + ret] = 0;
        }
        else if (r == 2) ios_have_neg = 1;      /* validated below, once truncated */
        else IOS_FSA( ios_fs_pc_miss, 1 );
        ios_ph_add( IOS_PH_PCACHE, ios_ph0 );
    }
#endif

    if (pos > 1) unix_name[pos - 1] = 0;
    else unix_name[1] = 0;  /* keep the initial slash */

#ifdef WINE_IOS
    /* ml912: a remembered "not in this directory".  unix_name is now the
     * parent, so one fstatat() of it answers the whole question: same inode,
     * same nanosecond mtime => the directory has not gained or lost an entry
     * since we scanned it, so the name is still absent.  This is the case that
     * dominates the log — 2 full readdir scans per open, 300k readdir per 10 s
     * — and it is the case the positive cache could never hold. */
    if (ios_have_neg)
    {
        struct stat dst;
        int ok;

        ios_ph0 = ios_fs_now_us();
        ok = !fstatat( root_fd, unix_name, &dst, 0 );
        if (ok)
        {
            ios_pst = dst;                      /* ml915: the dircache probe reuses this */
            ios_pst_ok = 1;
            /* ml913: whatever the answer, we now know this directory's
             * identity — hand it to lookup_unix_name for the whole-path
             * negative entry rather than making it stat the same path again. */
            ios_dir_stamp.dev = dst.st_dev;
            ios_dir_stamp.ino = dst.st_ino;
            ios_dir_stamp.mtime = S_ISDIR( dst.st_mode ) ? ios_stat_mtime( &dst ) : 0;
        }
        if (ok && ios_neg.mtime && dst.st_dev == ios_neg.dev && dst.st_ino == ios_neg.ino &&
            ios_stat_mtime( &dst ) == ios_neg.mtime)
        {
            IOS_FSA( ios_fs_pc_nhit, 1 );
            /* ml914: proof and stamp are this one syscall, so the stamp is
             * usable for a whole-path entry.  Below it is NOT: a stamp read
             * after the exact-case probe but with no scan behind it (the
             * case-insensitive-directory shortcut) would hide a create that
             * landed between the two. */
            ios_dir_stamp_ok = 1;
            ios_ph_add( IOS_PH_NEG, ios_ph0 );
            goto not_found;
        }
        ios_dir_stamp.mtime = 0;
        IOS_FSA( ios_fs_pc_nstale, 1 );
        ios_ph_add( IOS_PH_NEG, ios_ph0 );
    }
    ios_sc0 = ios_fs_now_us();
#endif

    /* check if it fits in 8.3 so that we don't look for short names if we won't need them */

    is_name_8_dot_3 = is_legal_8dot3_name( name, length );
#ifndef VFAT_IOCTL_READDIR_BOTH
    is_name_8_dot_3 = is_name_8_dot_3 && length >= 8 && name[4] == '~';
#endif

    if (!is_name_8_dot_3 && !get_dir_case_sensitivity( root_fd, unix_name )) goto not_found;

#ifdef WINE_IOS
    /* ml915: upstream is about to read this whole directory to answer one
     * name.  If we have already read it and its (dev, ino, mtime, ctime) has
     * not moved, one fstatat plus a hash probe answers instead -- for a name
     * that is there AND for one that is not, which is the case that dominates
     * a level load.  Deliberately after both gates above, so what is answered
     * from the table is exactly what the scan below would have answered.
     * 8.3 lookups are not: they run a second match rule interleaved with this
     * one inside the same readdir pass (see the header note).  They still
     * BUILD the table. */
    if (!ios_dc_disabled())
    {
        if (!ios_pst_ok && !fstatat( root_fd, unix_name, &ios_pst, 0 )) ios_pst_ok = 1;
        if (ios_pst_ok && S_ISDIR( ios_pst.st_mode ))
        {
            int ios_r = -1;

            ios_dc_stamp_of( &ios_dcst, &ios_pst );
            if (!is_name_8_dot_3)
                ios_r = ios_dc_lookup( &ios_dcst, name, length, NULL,
                                       unix_name + pos, MAX_DIR_ENTRY_LEN + 1 );
            if (ios_r >= 0)
            {
                /* ml914's rule: the stamp was read BEFORE the work that
                 * proved the answer, and it still matches the one the table
                 * was built under -- proof and stamp are effectively this one
                 * syscall, so lookup_unix_name may record a whole-path
                 * negative entry against it. */
                ios_dir_stamp.dev = ios_dcst.dev;
                ios_dir_stamp.ino = ios_dcst.ino;
                ios_dir_stamp.mtime = ios_dcst.mtime;
                ios_dir_stamp_ok = 1;
                if (ios_r >= 1)
                {
                    unix_name[pos - 1] = '/';
                    if (ios_cacheable) ios_pc_put( ios_key, unix_name + pos );
                    ios_ph_add( IOS_PH_SCAN, ios_sc0 );
                    return STATUS_SUCCESS;
                }
                goto not_found;                 /* charges IOS_PH_SCAN itself */
            }
            ios_dcb_on = 1;                     /* build the table from the scan below */
        }
    }
#endif

    /* now look for it through the directory */

#ifdef VFAT_IOCTL_READDIR_BOTH
    if (is_name_8_dot_3)
    {
        int fd = openat( root_fd, unix_name, O_RDONLY | O_DIRECTORY );
        if (fd != -1)
        {
            KERNEL_DIRENT kde[2];

            if (ioctl( fd, VFAT_IOCTL_READDIR_BOTH, (long)kde ) != -1)
            {
                unix_name[pos - 1] = '/';
                while (kde[0].d_reclen)
                {
                    if (kde[1].d_name[0])
                    {
                        ret = ntdll_umbstowcs( kde[1].d_name, strlen(kde[1].d_name),
                                               buffer, MAX_DIR_ENTRY_LEN );
                        if (ret == length && !wcsnicmp( buffer, name, ret ))
                        {
                            strcpy( unix_name + pos, kde[1].d_name );
                            close( fd );
                            return STATUS_SUCCESS;
                        }
                    }
                    ret = ntdll_umbstowcs( kde[0].d_name, strlen(kde[0].d_name),
                                           buffer, MAX_DIR_ENTRY_LEN );
                    if (ret == length && !wcsnicmp( buffer, name, ret ))
                    {
                        strcpy( unix_name + pos,
                                kde[1].d_name[0] ? kde[1].d_name : kde[0].d_name );
                        close( fd );
                        return STATUS_SUCCESS;
                    }
                    if (ioctl( fd, VFAT_IOCTL_READDIR_BOTH, (long)kde ) == -1)
                    {
                        close( fd );
                        goto not_found;
                    }
                }
                /* if that did not work, restore previous state of unix_name */
                unix_name[pos - 1] = 0;
            }
            close( fd );
        }
        /* fall through to normal handling */
    }
#endif /* VFAT_IOCTL_READDIR_BOTH */

    if ((fd = openat( root_fd, unix_name, O_RDONLY )) == -1)
    {
#ifdef WINE_IOS
        ios_ph_add( IOS_PH_SCAN, ios_sc0 );
#endif
        return errno_to_status( errno );
    }
    if (!(dir = fdopendir( fd )))
    {
        close( fd );
#ifdef WINE_IOS
        ios_ph_add( IOS_PH_SCAN, ios_sc0 );
#endif
        return errno_to_status( errno );
    }

#ifdef WINE_IOS
    /* ml912: stamp the directory BEFORE reading it.  Taken afterwards, an
     * entry created during the scan could be stamped as "definitely absent";
     * taken before, such a change only makes the stamp look stale and the
     * next lookup rescans. */
    if (ios_cacheable || ios_dcb_on)
    {
        struct stat dst;
        if (!fstat( fd, &dst ))
        {
            ios_stamp.dev = dst.st_dev;
            ios_stamp.ino = dst.st_ino;
            ios_stamp.mtime = ios_stat_mtime( &dst );
            ios_have_stamp = 1;
            ios_dir_stamp = ios_stamp;          /* ml913: free stamp for a whole-path entry */
            ios_dir_stamp_ok = 1;               /* ml914: read before the scan */
            /* ml915: and the same read, on the fd we are about to walk, is
             * the stamp the directory table is built under. */
            ios_dc_stamp_of( &ios_dcst, &dst );
            if (!ios_dcst.mtime) ios_dcb_on = 0;
        }
        else
        {
            if (ios_cacheable) IOS_FSA( ios_fs_pc_m_nostamp, 1 );
            ios_dcb_on = 0;                     /* no stamp, no table */
        }
    }
    if (ios_dcb_on) IOS_FSA( ios_fs_dc_scan, 1 );
    /* ml914: readdir() returns NULL both at end-of-directory and on error,
     * and an error means the scan is TRUNCATED, not that the name is absent.
     * Upstream pays for that once; a cached negative would pay forever. */
    errno = 0;
#endif

    unix_name[pos - 1] = '/';
    while ((de = readdir( dir )))
    {
        ret = ntdll_umbstowcs( de->d_name, strlen(de->d_name), buffer, MAX_DIR_ENTRY_LEN );
#ifdef WINE_IOS
        /* ml915: record the entry with the very conversion the match below
         * uses, then -- once the answer is known -- keep reading, because a
         * table that stops at the match is no use to the next name.  That
         * costs the rest of one walk, once per directory, and removes every
         * later walk of it. */
        if (ios_dcb_on) ios_dc_build_add( &ios_dcb, de->d_name, buffer, ret );
        if (ios_matched) continue;
#endif
        if (ret == length && !wcsnicmp( buffer, name, ret ))
        {
            strcpy( unix_name + pos, de->d_name );
#ifdef WINE_IOS
            if (ios_dcb_on) { ios_matched = 1; continue; }
#endif
            closedir( dir );
#ifdef WINE_IOS
            if (ios_cacheable) ios_pc_put( ios_key, unix_name + pos );
            ios_ph_add( IOS_PH_SCAN, ios_sc0 );
#endif
            return STATUS_SUCCESS;
        }

        if (!is_name_8_dot_3) continue;

        if (!is_legal_8dot3_name( buffer, ret ))
        {
            WCHAR short_nameW[12];
            ret = hash_short_file_name( buffer, ret, short_nameW );
            if (ret == length && !wcsnicmp( short_nameW, name, length ))
            {
                strcpy( unix_name + pos, de->d_name );
#ifdef WINE_IOS
                if (ios_dcb_on) { ios_matched = 1; continue; }
#endif
                closedir( dir );
#ifdef WINE_IOS
                if (ios_cacheable) ios_pc_put( ios_key, unix_name + pos );
                ios_ph_add( IOS_PH_SCAN, ios_sc0 );
#endif
                return STATUS_SUCCESS;
            }
        }
    }
#ifdef WINE_IOS
    ios_scan_errno = errno;
#endif
    closedir( dir );
#ifdef WINE_IOS
    /* ml915: hand the completed table over.  unix_name currently reads
     * "<parent>/<found name>", so the parent is restored for the moment it
     * takes to record the path the table is keyed on.  A truncated scan
     * (readdir error) cannot be cached in either direction. */
    if (ios_dcb_on)
    {
        unsigned int ios_cut = pos > 1 ? (unsigned int)pos - 1 : 1;
        char ios_save = unix_name[ios_cut];

        unix_name[ios_cut] = 0;
        if (ios_scan_errno) ios_dc_build_abort( &ios_dcb );
        else ios_dc_build_finish( &ios_dcb, &ios_dcst, root_fd == AT_FDCWD ? unix_name : NULL );
        unix_name[ios_cut] = ios_save;
    }
    if (ios_matched)                            /* the scan DID match; it just kept reading */
    {
        if (ios_cacheable) ios_pc_put( ios_key, unix_name + pos );
        ios_ph_add( IOS_PH_SCAN, ios_sc0 );
        return STATUS_SUCCESS;
    }
    /* ml912: the scan read the whole directory and found nothing.  Remember
     * that, stamped with what the directory looked like when we started, so
     * the next lookup of this name costs one fstatat instead of another
     * openat + fdopendir + full getdirentries walk. */
    if (ios_scan_errno)
    {
        ios_dir_stamp.mtime = 0;
        ios_dir_stamp_ok = 0;
    }
    else if (ios_cacheable && ios_have_stamp) ios_pc_store( ios_key, NULL, &ios_stamp );
#endif

not_found:
#ifdef WINE_IOS
    if (ios_sc0) ios_ph_add( IOS_PH_SCAN, ios_sc0 );
#endif
    unix_name[pos - 1] = 0;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}


#ifndef _WIN64

static const WCHAR catrootW[] = {'s','y','s','t','e','m','3','2','\\','c','a','t','r','o','o','t',0};
static const WCHAR catroot2W[] = {'s','y','s','t','e','m','3','2','\\','c','a','t','r','o','o','t','2',0};
static const WCHAR driversstoreW[] = {'s','y','s','t','e','m','3','2','\\','d','r','i','v','e','r','s','s','t','o','r','e',0};
static const WCHAR driversetcW[] = {'s','y','s','t','e','m','3','2','\\','d','r','i','v','e','r','s','\\','e','t','c',0};
static const WCHAR logfilesW[] = {'s','y','s','t','e','m','3','2','\\','l','o','g','f','i','l','e','s',0};
static const WCHAR spoolW[] = {'s','y','s','t','e','m','3','2','\\','s','p','o','o','l',0};
static const WCHAR system32W[] = {'s','y','s','t','e','m','3','2',0};
static const WCHAR syswow64W[] = {'s','y','s','w','o','w','6','4',0};
static const WCHAR sysnativeW[] = {'s','y','s','n','a','t','i','v','e',0};
static const WCHAR regeditW[] = {'r','e','g','e','d','i','t','.','e','x','e',0};
static const WCHAR syswow64_regeditW[] = {'s','y','s','w','o','w','6','4','\\','r','e','g','e','d','i','t','.','e','x','e',0};
static const WCHAR windirW[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\',0};
static const WCHAR syswow64dirW[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','w','o','w','6','4','\\'};

static const WCHAR * const no_redirect[] =
{
    catrootW,
    catroot2W,
    driversstoreW,
    driversetcW,
    logfilesW,
    spoolW
};

static struct file_identity windir, sysdir;

static inline ULONG starts_with_path( const WCHAR *name, ULONG name_len, const WCHAR *prefix )
{
    ULONG len = wcslen( prefix );

    if (name_len < len) return 0;
    if (wcsnicmp( name, prefix, len )) return 0;
    if (name_len > len && name[len] != '\\') return 0;
    return len;
}

static BOOL replace_path( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *str, ULONG prefix_len,
                          const WCHAR *match, const WCHAR *replace )
{
    const WCHAR *name = attr->ObjectName->Buffer;
    ULONG match_len, replace_len, len = attr->ObjectName->Length / sizeof(WCHAR);
    WCHAR *p;

    if (!starts_with_path( name + prefix_len, len - prefix_len, match )) return FALSE;

    match_len = wcslen( match );
    replace_len = wcslen( replace );
    str->Length = (len + replace_len - match_len) * sizeof(WCHAR);
    str->MaximumLength = str->Length + sizeof(WCHAR);
    if (!(p = str->Buffer = malloc( str->MaximumLength ))) return FALSE;

    memcpy( p, name, prefix_len * sizeof(WCHAR) );
    p += prefix_len;
    memcpy( p, replace, replace_len * sizeof(WCHAR) );
    p += replace_len;
    name += prefix_len + match_len;
    len -= prefix_len + match_len;
    memcpy( p, name, len * sizeof(WCHAR) );
    p[len] = 0;
    attr->ObjectName = str;
    return TRUE;
}

/***********************************************************************
 *           init_redirects
 */
static void init_redirects(void)
{
    static const char system_dir[] = "/dosdevices/c:/windows/system32";
    char *dir;
    struct stat st;

    if (asprintf( &dir, "%s%s", config_dir, system_dir ) == -1) return;
    if (!stat( dir, &st ))
    {
        sysdir.dev = st.st_dev;
        sysdir.ino = st.st_ino;
    }
    *strrchr( dir, '/' ) = 0;
    if (!stat( dir, &st ))
    {
        windir.dev = st.st_dev;
        windir.ino = st.st_ino;
    }
    else ERR( "%s: %s\n", dir, strerror(errno) );
    free( dir );

}

/***********************************************************************
 *           get_redirect
 */
static void get_redirect( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *redir )
{
    const WCHAR *name = attr->ObjectName->Buffer;
    unsigned int i, prefix_len = 0, len = attr->ObjectName->Length / sizeof(WCHAR);

    if (!NtCurrentTeb64()) return;

    if (!attr->RootDirectory)
    {
        prefix_len = wcslen( windirW );
        if (len < prefix_len || wcsnicmp( name, windirW, prefix_len )) return;
    }
    else
    {
        int fd, needs_close;
        struct stat st;

        if (!len) return;
        if (server_get_unix_fd( attr->RootDirectory, 0, &fd, &needs_close, NULL, NULL )) return;
        fstat( fd, &st );
        if (needs_close) close( fd );
        if (!is_same_file( &windir, &st ))
        {
            if (!is_same_file( &sysdir, &st )) return;
            if (NtCurrentTeb64()->TlsSlots[WOW64_TLS_FILESYSREDIR]) return;
            if (name[0] == '\\') return;

            /* only check for paths that should NOT be redirected */
            for (i = 0; i < ARRAY_SIZE( no_redirect ); i++)
                if (starts_with_path( name, len, no_redirect[i] + 9 /* "system32\\" */)) return;

            /* redirect everything else */
            redir->Length = sizeof(syswow64dirW) + len * sizeof(WCHAR);
            redir->MaximumLength = redir->Length + sizeof(WCHAR);
            if (!(redir->Buffer = malloc( redir->MaximumLength ))) return;
            memcpy( redir->Buffer, syswow64dirW, sizeof(syswow64dirW) );
            memcpy( redir->Buffer + ARRAY_SIZE(syswow64dirW), name, len * sizeof(WCHAR) );
            redir->Buffer[redir->Length / sizeof(WCHAR)] = 0;
            attr->RootDirectory = 0;
            attr->ObjectName = redir;
            return;
        }
    }

    /* sysnative is redirected even when redirection is disabled */

    if (replace_path( attr, redir, prefix_len, sysnativeW, system32W )) return;

    if (NtCurrentTeb64()->TlsSlots[WOW64_TLS_FILESYSREDIR]) return;

    for (i = 0; i < ARRAY_SIZE( no_redirect ); i++)
        if (starts_with_path( name + prefix_len, len - prefix_len, no_redirect[i] )) return;

    if (replace_path( attr, redir, prefix_len, system32W, syswow64W )) return;
    if (replace_path( attr, redir, prefix_len, regeditW, syswow64_regeditW )) return;
}

#endif


#define IS_OPTION_TRUE(ch) ((ch) == 'y' || (ch) == 'Y' || (ch) == 't' || (ch) == 'T' || (ch) == '1')

/***********************************************************************
 *           init_files
 */
void init_files(void)
{
    HANDLE key;

#ifndef _WIN64
    if (is_old_wow64()) init_redirects();
#endif
    /* a couple of directories that we don't want to return in directory searches */
    ignore_file( config_dir );
    ignore_file( "/dev" );
    ignore_file( "/proc" );
#ifdef linux
    ignore_file( "/sys" );
#endif
    /* retrieve initial umask */
    start_umask = umask( 0777 );
    umask( start_umask );

    if (!open_hkcu_key( "Software\\Wine", &key ))
    {
        static WCHAR showdotfilesW[] = {'S','h','o','w','D','o','t','F','i','l','e','s',0};
        char tmp[80];
        DWORD dummy;
        UNICODE_STRING nameW;

        init_unicode_string( &nameW, showdotfilesW );
        if (!NtQueryValueKey( key, &nameW, KeyValuePartialInformation, tmp, sizeof(tmp), &dummy ))
        {
            WCHAR *str = (WCHAR *)((KEY_VALUE_PARTIAL_INFORMATION *)tmp)->Data;
            show_dot_files = IS_OPTION_TRUE( str[0] );
        }
        NtClose( key );
    }
}


/******************************************************************************
 *           get_dos_device
 *
 * Get the Unix path of a DOS device.
 */
static NTSTATUS get_dos_device( char **unix_name, int start_pos )
{
    struct stat st;
    char *new_name, *dev = *unix_name + start_pos;

    /* special case for drive devices */
    if (dev[0] && dev[1] == ':' && !dev[2]) strcpy( dev + 1, "::" );

    if (strchr( dev, '/' )) goto failed;

    for (;;)
    {
        if (!stat( *unix_name, &st ))
        {
            TRACE( "-> %s\n", debugstr_a(*unix_name));
            return STATUS_SUCCESS;
        }
        if (!dev) break;

        /* now try some defaults for it */
        if (!strcmp( dev, "aux" ))
        {
            strcpy( dev, "com1" );
            continue;
        }
        if (!strcmp( dev, "prn" ))
        {
            strcpy( dev, "lpt1" );
            continue;
        }

        new_name = NULL;
        if (dev[1] == ':' && dev[2] == ':')  /* drive device */
        {
            dev[2] = 0;  /* remove last ':' to get the drive mount point symlink */
            new_name = get_default_drive_device( *unix_name );
        }
        free( *unix_name );
        *unix_name = new_name;
        if (!new_name) return STATUS_BAD_DEVICE_TYPE;
        dev = NULL; /* last try */
    }
failed:
    free( *unix_name );
    *unix_name = NULL;
    return STATUS_BAD_DEVICE_TYPE;
}


/* return the length of the DOS namespace prefix if any */
static inline int get_dos_prefix_len( const UNICODE_STRING *name )
{
    static const WCHAR dosdev_prefixW[] = {'\\','D','o','s','D','e','v','i','c','e','s','\\'};

    if (name->Length >= sizeof(nt_prefixW) &&
        !memcmp( name->Buffer, nt_prefixW, sizeof(nt_prefixW) ))
        return ARRAY_SIZE( nt_prefixW );

    if (name->Length >= sizeof(dosdev_prefixW) &&
        !wcsnicmp( name->Buffer, dosdev_prefixW, ARRAY_SIZE( dosdev_prefixW )))
        return ARRAY_SIZE( dosdev_prefixW );

    return 0;
}


/***********************************************************************
 *           remove_last_component
 *
 * Remove the last component of the path. Helper for find_drive_rootA.
 */
static unsigned int remove_last_component( const char *path, unsigned int len )
{
    int level = 0;

    while (level < 1)
    {
        /* find start of the last path component */
        unsigned int prev = len;
        if (prev <= 1) break;  /* reached root */
        while (prev > 1 && path[prev - 1] != '/') prev--;
        /* does removing it take us up a level? */
        if (len - prev != 1 || path[prev] != '.')  /* not '.' */
        {
            if (len - prev == 2 && path[prev] == '.' && path[prev+1] == '.')  /* is it '..'? */
                level--;
            else
                level++;
        }
        /* strip off trailing slashes */
        while (prev > 1 && path[prev - 1] == '/') prev--;
        len = prev;
    }
    return len;
}


/******************************************************************************
 *           find_file_id
 *
 * Recursively search directories from the dir queue for a given inode.
 */
static NTSTATUS find_file_id( int root_fd, char **unix_name, ULONG *len, ULONGLONG file_id, dev_t dev, struct list *dir_queue )
{
    unsigned int pos;
    int dir_fd;
    DIR *dir;
    struct dirent *de;
    NTSTATUS status;
    struct stat st;
    char *name = *unix_name;

    while (!(status = next_dir_in_queue( dir_queue, name )))
    {
        if ((dir_fd = openat( root_fd, name, O_RDONLY )) == -1) continue;
        if (!(dir = fdopendir( dir_fd )))
        {
            close( dir_fd );
            continue;
        }
        TRACE( "searching %s for %s\n", debugstr_a(name), wine_dbgstr_longlong(file_id) );
        pos = strlen( name );
        if (pos + MAX_DIR_ENTRY_LEN >= *len / sizeof(WCHAR))
        {
            if (!(name = realloc( name, *len * 2 )))
            {
                closedir( dir );
                return STATUS_NO_MEMORY;
            }
            *len *= 2;
            *unix_name = name;
        }
        name[pos++] = '/';
        while ((de = readdir( dir )))
        {
            if (!strcmp( de->d_name, "." ) || !strcmp( de->d_name, ".." )) continue;
            strcpy( name + pos, de->d_name );
            if (fstatat( root_fd, name, &st, AT_SYMLINK_NOFOLLOW ) == -1) continue;
            if (st.st_dev != dev) continue;
            if (st.st_ino == file_id)
            {
                closedir( dir );
                return STATUS_SUCCESS;
            }
            if (!S_ISDIR( st.st_mode )) continue;
            if ((status = add_dir_to_queue( dir_queue, name )) != STATUS_SUCCESS)
            {
                closedir( dir );
                return status;
            }
        }
        closedir( dir );
    }
    return status;
}


/******************************************************************************
 *           file_id_to_unix_file_name
 *
 * Lookup a file from its file id instead of its name.
 */
static NTSTATUS file_id_to_unix_file_name( const OBJECT_ATTRIBUTES *attr, char **unix_name_ret,
                                           UNICODE_STRING *nt_name )
{
    enum server_fd_type type;
    int root_fd, needs_close;
    char *unix_name;
    ULONG len;
    NTSTATUS status;
    ULONGLONG file_id;
    struct stat st, root_st;
    struct list dir_queue = LIST_INIT( dir_queue );

    nt_name->Buffer = NULL;
    if (attr->ObjectName->Length != sizeof(ULONGLONG)) return STATUS_OBJECT_PATH_SYNTAX_BAD;
    if (!attr->RootDirectory) return STATUS_INVALID_PARAMETER;
    memcpy( &file_id, attr->ObjectName->Buffer, sizeof(file_id) );

    len = 2 * MAX_DIR_ENTRY_LEN + 4;
    if (!(unix_name = malloc( len ))) return STATUS_NO_MEMORY;
    strcpy( unix_name, "." );

    if ((status = server_get_unix_fd( attr->RootDirectory, 0, &root_fd, &needs_close, &type, NULL )))
        goto done;

    if (type != FD_TYPE_DIR)
    {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto done;
    }

    fstat( root_fd, &root_st );
    if (root_st.st_ino == file_id)  /* shortcut for "." */
    {
        status = STATUS_SUCCESS;
        goto done;
    }

    /* shortcut for ".." */
    if (!fstatat( root_fd, "..", &st, 0 ) && st.st_dev == root_st.st_dev && st.st_ino == file_id)
    {
        strcpy( unix_name, ".." );
        status = STATUS_SUCCESS;
    }
    else
    {
        status = add_dir_to_queue( &dir_queue, "." );
        if (!status)
            status = find_file_id( root_fd, &unix_name, &len, file_id, root_st.st_dev, &dir_queue );
        if (!status)  /* get rid of "./" prefix */
            memmove( unix_name, unix_name + 2, strlen(unix_name) - 1 );
        flush_dir_queue( &dir_queue );
    }

done:
    if (status == STATUS_SUCCESS)
    {
        TRACE( "%s -> %s\n", wine_dbgstr_longlong(file_id), debugstr_a(unix_name) );
        *unix_name_ret = unix_name;

        nt_name->MaximumLength = (strlen(unix_name) + 1) * sizeof(WCHAR);
        if ((nt_name->Buffer = malloc( nt_name->MaximumLength )))
        {
            DWORD i, len = ntdll_umbstowcs( unix_name, strlen(unix_name), nt_name->Buffer, strlen(unix_name) );
            nt_name->Buffer[len] = 0;
            nt_name->Length = len * sizeof(WCHAR);
            for (i = 0; i < len; i++) if (nt_name->Buffer[i] == '/') nt_name->Buffer[i] = '\\';
        }
    }
    else
    {
        TRACE( "%s not found in dir %p\n", wine_dbgstr_longlong(file_id), attr->RootDirectory );
        free( unix_name );
    }
    if (needs_close) close( root_fd );
    return status;
}


static NTSTATUS resolve_reparse_point( int fd, int root_fd, OBJECT_ATTRIBUTES *attr,
        UNICODE_STRING *nt_name, unsigned int nt_pos, unsigned int reparse_len, char **unix_name,
        int unix_len, int pos, UINT disposition, BOOL open_reparse, BOOL is_unix, unsigned int reparse_count );


/******************************************************************************
 *           lookup_unix_name
 *
 * Helper for nt_to_unix_file_name
 */
static NTSTATUS lookup_unix_name( int root_fd, OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name,
                                  unsigned int nt_pos, char **buffer, int unix_len, int pos,
                                  UINT disposition, BOOL open_reparse, BOOL is_unix, unsigned int reparse_count )
{
    static const WCHAR invalid_charsW[] = { INVALID_NT_CHARS, '/', 0 };
    const WCHAR *name = attr->ObjectName->Buffer + nt_pos;
    unsigned int name_len = (attr->ObjectName->Length / sizeof(WCHAR)) - nt_pos;
    NTSTATUS status;
    int ret;
    struct stat st;
    char *unix_name = *buffer;
    const WCHAR *ptr, *end;
#ifdef WINE_IOS
    const int ios_pos0 = pos;
    unsigned int ios_depth = 0;
    /* ml914: two different keys for the two whole-path caches -- see the
     * note at the key construction below. */
    char ios_kbuf[IOS_PC_KEYMAX];       /* '\1' + case-folded path -> ios_pc */
    char ios_nbuf[IOS_PC_KEYMAX];       /* exact-case path         -> ios_np */
    /* ml915: '\2' + the exact-case path of this path's PARENT -> ios_pc, whose
     * value is the resolved on-disk directory.  See the probe below. */
    char ios_pdbuf[IOS_PC_KEYMAX];
    unsigned int ios_pdlen = 0;         /* bytes of the parent, inside unix_name */
    int ios_have_key = 0, ios_have_pd = 0;
    struct ios_pc_neg ios_cstamp = { 0 };   /* deepest-existing-dir stamp */
    int ios_cstamp_ok = 0;
    unsigned long long ios_ph0 = 0;
#endif

    /* check syntax of individual components */

    for (ptr = name, end = name + name_len; ptr < end; ptr++)
    {
        if (*ptr == '\\') return STATUS_OBJECT_NAME_INVALID;  /* duplicate backslash */
        if (*ptr == '.')
        {
            if (ptr + 1 == end) return STATUS_OBJECT_NAME_INVALID;  /* "." element */
            if (ptr[1] == '\\') return STATUS_OBJECT_NAME_INVALID;  /* "." element */
            if (ptr[1] == '.')
            {
                if (ptr + 2 == end) return STATUS_OBJECT_NAME_INVALID;  /* ".." element */
                if (ptr[2] == '\\') return STATUS_OBJECT_NAME_INVALID;  /* ".." element */
            }
        }
        /* check for invalid characters (all chars except 0 are valid for unix) */
        for ( ; ptr < end && *ptr != '\\'; ptr++)
        {
            if (!*ptr) return STATUS_OBJECT_NAME_INVALID;
            if (is_unix) continue;
            if (*ptr < 32 || wcschr( invalid_charsW, *ptr )) return STATUS_OBJECT_NAME_INVALID;
        }
    }

    /* try a shortcut first */

    unix_name[pos] = '/';
    ret = ntdll_wcstoumbs( name, name_len, unix_name + pos + 1, unix_len - pos - 1, TRUE );
    if (ret >= 0 && ret < unix_len - pos - 1)
    {
        char *p;
        unix_name[pos + 1 + ret] = 0;
        for (p = unix_name + pos ; *p; p++) if (*p == '\\') *p = '/';
#ifdef WINE_IOS
        /* ml913: build the key BEFORE the shortcut stat and ask the
         * whole-path negative cache first, so a repeat probe of a path that
         * does not exist costs exactly one fstatat — of the deepest directory
         * that does — instead of the shortcut stat plus a component walk.
         * Safe to run first: anything appearing at this path has to be
         * created in that directory, which bumps its mtime and makes the
         * entry stale, at which point the shortcut below runs as usual.
         *
         * ml914: two keys, because the two whole-path caches do not have the
         * same soundness requirement.
         *
         * ios_np (negative) is keyed on the EXACT requested spelling.  A
         * case-folded key is unsound for a whole path: this resolver is NOT
         * case-insensitive across a path, it prefers the exact case at every
         * component (the shortcut stat, then find_file_in_dir's own exact
         * stat), so on a case-sensitive volume "Foo/bar" and "foo/bar" may be
         * two different files, and a folded key hands one's absence to the
         * other -- a hard NOT_FOUND for a file that exists.  Reaching that
         * needs two entries in one directory differing only in case, which
         * nothing can create THROUGH this resolver (the case-insensitive scan
         * turns the second CreateFile/CreateDirectory into a collision), but
         * the app bundle and anything else writing the container from the
         * host side are under no such constraint.  The exact key costs
         * nothing: a program repeats its own spelling.
         *
         * ios_pc (positive) keeps its fold: a hit there is re-validated with
         * an fstatat of the cached spelling, so the worst a conflated key can
         * do is a failed stat and a rescan.  It gains a '\1' namespace byte,
         * which keeps whole-path entries out of find_file_in_dir's
         * per-component key space in the same table: the two used to collide
         * outright -- <resolved parent>/<folded leaf> is the same string as
         * the whole-path key of that lookup whenever the parent is already
         * lower-case -- so a one-component value could be read back as a whole
         * path (and each put evicted the other's entry).  '\1' cannot occur
         * in a converted NT name; the syntax check above rejects every char
         * below 32. */
        if (root_fd == AT_FDCWD && !is_unix &&
            ios_pc_key( ios_kbuf + 1, sizeof(ios_kbuf) - 1, unix_name, pos + 1 + ret, pos + 1 ))
        {
            const char *ios_ls;

            ios_kbuf[0] = '\1';
            memcpy( ios_nbuf, unix_name, pos + 1 + ret + 1 );
            ios_have_key = 1;

            /* ml915: and the key for this path's PARENT.  Exact spelling, for
             * the same reason ios_np's key is exact: a folded key would hand
             * one directory's resolution to a case sibling.  '\2' keeps it out
             * of the '\1' whole-path and the unprefixed per-component key
             * spaces in the same table. */
            /* ios_ls[1] rejects a trailing separator: there is then no leaf,
             * `pos` below stops at the GRANDparent, and the entry would map a
             * directory that does not exist onto one that does. */
            if ((ios_ls = strrchr( unix_name + pos + 1, '/' )) && ios_ls[1])
            {
                ios_pdlen = (unsigned int)(ios_ls - unix_name);
                if (ios_pdlen + 2 < sizeof(ios_pdbuf))
                {
                    ios_pdbuf[0] = '\2';
                    memcpy( ios_pdbuf + 1, unix_name, ios_pdlen );
                    ios_pdbuf[1 + ios_pdlen] = 0;
                    ios_have_pd = 1;
                }
            }
        }

        if (ios_have_key && !open_reparse && !ios_np_disabled())
        {
            char ios_dbuf[IOS_PC_KEYMAX];
            struct ios_pc_neg ios_nst;
            unsigned int ios_nstatus = 0;

            ios_ph0 = ios_fs_now_us();
            if (ios_np_get( ios_nbuf, ios_dbuf, sizeof(ios_dbuf), &ios_nst, &ios_nstatus ) &&
                (ios_nstatus == STATUS_OBJECT_PATH_NOT_FOUND ||
                 disposition == FILE_OPEN || disposition == FILE_OVERWRITE))
            {
                struct stat dst;

                if (!fstatat( root_fd, ios_dbuf, &dst, 0 ) &&
                    dst.st_dev == ios_nst.dev && dst.st_ino == ios_nst.ino &&
                    ios_stat_mtime( &dst ) == ios_nst.mtime)
                {
                    IOS_FSA( ios_fs_np_hit, 1 );
                    if (!ios_fs_disabled()) ios_np_log_hit( ios_nbuf, ios_dbuf );
                    ios_ph_add( IOS_PH_WNEG, ios_ph0 );
                    return ios_nstatus;
                }
                IOS_FSA( ios_fs_np_stale, 1 );
            }
            ios_ph_add( IOS_PH_WNEG, ios_ph0 );
        }

        /* ml915: the case the whole-path negative cache above cannot serve --
         * a leaf this process has NEVER asked for before.  That is what the
         * q66 log is made of: ~4800 failing opens per 10 s of mostly DISTINCT
         * names (localised and variant package spellings), so a per-path entry
         * is written once and read never, and each miss walked the path
         * component by component and then scanned a directory of thousands.
         *
         * Split the question in two and cache each half where it repeats:
         *   - the PARENT resolution, keyed on the exact requested spelling of
         *     everything up to the last separator (one entry per directory,
         *     hit by every name in it);
         *   - the leaf, answered by that directory's contents table.
         * One fstatat of the resolved parent validates BOTH: it proves the
         * directory is still there and it is the stamp the table is checked
         * against.  A failing open is then one syscall and two hash probes,
         * instead of ~11 fstatat plus two getdirentries walks.
         *
         * What is returned here is exactly what the code below would return:
         *   absent -- the walk would resolve every component but the last
         *     (the parent exists: we just stat'd it), find_file_in_dir would
         *     fail the exact-case stat and then the case-insensitive scan,
         *     upstream's `<leaf>?` reparse probe would fail the same way, and
         *     with FILE_OPEN/FILE_OVERWRITE the leaf miss stays
         *     STATUS_OBJECT_NAME_NOT_FOUND.  Both probes must say absent.
         *   present in the caller's own spelling, in a directory whose
         *     resolved spelling IS the requested one -- then the path in the
         *     buffer is already the resolved path and the shortcut stat below
         *     would have returned STATUS_SUCCESS with it unchanged.  Any other
         *     kind of match falls through and is resolved the long way, so the
         *     "exact case wins over readdir order" rule is untouched.
         *
         * Guards, all of them the ones ios_np already carries: never for
         * open_reparse (it changes what a `<leaf>?` match means), never for a
         * create disposition (those want the constructed name back with
         * STATUS_NO_SUCH_FILE), never for a leaf that is a legal 8.3 name (a
         * scan matches those a second way, by short-name hash, which the table
         * does not model), and never with a relative root_fd. */
        if (ios_have_pd && !open_reparse && !ios_dc_disabled() &&
            (disposition == FILE_OPEN || disposition == FILE_OVERWRITE))
        {
            const WCHAR *ios_leaf = name + name_len;
            unsigned int ios_leaflen;
            BOOLEAN ios_l83;

            while (ios_leaf > name && ios_leaf[-1] != '\\') ios_leaf--;
            ios_leaflen = (unsigned int)(name + name_len - ios_leaf);
            ios_l83 = ios_leaflen ? is_legal_8dot3_name( ios_leaf, ios_leaflen ) : TRUE;
#ifndef VFAT_IOCTL_READDIR_BOTH
            ios_l83 = ios_l83 && ios_leaflen >= 8 && ios_leaf[4] == '~';
#endif
            if (ios_leaflen && ios_leaflen <= MAX_DIR_ENTRY_LEN && !ios_l83)
            {
                char ios_dbuf[IOS_PC_KEYMAX];

                ios_ph0 = ios_fs_now_us();
                if (ios_pc_get( ios_pdbuf, ios_dbuf, sizeof(ios_dbuf) ))
                {
                    struct stat ios_dst;

                    if (!fstatat( root_fd, ios_dbuf, &ios_dst, 0 ) && S_ISDIR( ios_dst.st_mode ))
                    {
                        struct ios_dc_stamp ios_ds;
                        WCHAR ios_lw[MAX_DIR_ENTRY_LEN + 1];
                        char ios_tmp[MAX_DIR_ENTRY_LEN + 2];
                        size_t ios_dl = strlen( ios_dbuf );
                        int ios_fr;

                        ios_dc_stamp_of( &ios_ds, &ios_dst );
                        memcpy( ios_lw, ios_leaf, ios_leaflen * sizeof(WCHAR) );
                        ios_fr = ios_dc_lookup( &ios_ds, ios_lw, ios_leaflen,
                                                unix_name + ios_pdlen + 1, ios_tmp, sizeof(ios_tmp) );
                        if (!ios_fr)
                        {
                            ios_lw[ios_leaflen] = '?';
                            if (!ios_dc_lookup( &ios_ds, ios_lw, ios_leaflen + 1, NULL,
                                                ios_tmp, sizeof(ios_tmp) ))
                            {
                                IOS_FSA( ios_fs_dc_fast, 1 );
                                ios_ph_add( IOS_PH_WDIR, ios_ph0 );
                                return STATUS_OBJECT_NAME_NOT_FOUND;
                            }
                        }
                        else if (ios_fr == 2 && ios_dl == ios_pdlen &&
                                 !memcmp( ios_dbuf, unix_name, ios_pdlen ))
                        {
                            IOS_FSA( ios_fs_dc_fexact, 1 );
                            ios_ph_add( IOS_PH_WDIR, ios_ph0 );
                            return STATUS_SUCCESS;
                        }
                    }
                }
                else IOS_FSA( ios_fs_dc_fmiss, 1 );
                ios_ph_add( IOS_PH_WDIR, ios_ph0 );
            }
        }
        ios_ph0 = ios_fs_now_us();
#endif
        if (!fstatat( root_fd, unix_name, &st, 0 ))
        {
#ifdef WINE_IOS
            ios_ph_add( IOS_PH_WPATH, ios_ph0 );
#endif
            if (disposition == FILE_CREATE) return STATUS_OBJECT_NAME_COLLISION;
            return STATUS_SUCCESS;
        }
#ifdef WINE_IOS
        /* ml910: the whole path in the requested spelling does not exist, so
         * upstream now walks it component by component and scans a directory
         * for every component whose on-disk case differs.  Ask the
         * resolved-name cache for the whole remaining path first: a repeat
         * open of a deep path then costs this one extra fstatat instead of
         * ~5 syscalls per component.  Keyed on the case-folded request, so a
         * later exact-case file still wins — the shortcut above runs first
         * and we are never reached for it. */
        if (root_fd != AT_FDCWD) IOS_FSA( ios_fs_pc_m_root, 1 );
        else if (!is_unix)
        {
            if (!ios_have_key) IOS_FSA( ios_fs_pc_m_key, 1 );   /* whole path over IOS_PC_KEYMAX */
            else
            {
                /* ml914: ios_kbuf is a local array that nothing below writes
                 * to, so the put at the end of this function can use it
                 * directly -- the old heap copy was pure overhead. */
                if (ios_pc_get( ios_kbuf, unix_name + pos + 1, unix_len - pos - 1 ))
                {
                    IOS_FSA( ios_fs_pc_hit, 1 );
                    if (!fstatat( root_fd, unix_name, &st, 0 ))
                    {
                        ios_ph_add( IOS_PH_WPATH, ios_ph0 );
                        if (disposition == FILE_CREATE) return STATUS_OBJECT_NAME_COLLISION;
                        return STATUS_SUCCESS;
                    }
                    IOS_FSA( ios_fs_pc_stale, 1 );
                }
                else IOS_FSA( ios_fs_pc_miss, 1 );
                /* the buffer is rewritten from `pos` by find_file_in_dir(),
                 * so nothing has to be restored here */
            }
        }
        ios_ph_add( IOS_PH_WPATH, ios_ph0 );
#endif
    }

    if (!name_len)  /* empty name -> drive root doesn't exist */
        return STATUS_OBJECT_PATH_NOT_FOUND;
    if (is_unix && (disposition == FILE_OPEN || disposition == FILE_OVERWRITE))
        return STATUS_OBJECT_NAME_NOT_FOUND;

    /* now do it component by component */

    while (name_len)
    {
        const WCHAR *end, *next;
        WCHAR *reparse_name;

        end = name;
        while (end < name + name_len && *end != '\\') end++;
        next = end;
        if (next < name + name_len) next++;
        name_len -= next - name;

        /* grow the buffer if needed */

        if (unix_len - pos < MAX_DIR_ENTRY_LEN + 3)
        {
            char *new_name;
            unix_len += 2 * MAX_DIR_ENTRY_LEN;
            if (!(new_name = realloc( unix_name, unix_len ))) return STATUS_NO_MEMORY;
            unix_name = *buffer = new_name;
        }

        status = find_file_in_dir( root_fd, unix_name, pos, name, end - name, is_unix );
#ifdef WINE_IOS
        /* ml914: THIS component's directory stamp, captured before the
         * `<name>?` probe below runs a second find_file_in_dir over the same
         * directory.  That probe used to overwrite ios_dir_stamp with a stamp
         * read AFTER this component's scan had already concluded, so a file
         * created in the window between the two scans (one whole getdirentries
         * walk wide -- ~1.6 ms on this device) was invisible to the scan yet
         * already reflected in the stored mtime, and the whole-path negative
         * entry then never went stale: a permanent NOT_FOUND for a file that
         * does exist. */
        ios_cstamp = ios_dir_stamp;
        ios_cstamp_ok = ios_dir_stamp_ok;
#endif

        /* try to resolve it as a reparse point */
        if (status == STATUS_OBJECT_NAME_NOT_FOUND && (reparse_name = malloc( (end - name + 1) * sizeof(WCHAR) )))
        {
            int reparse_fd;
#ifdef WINE_IOS
            /* ml913: for every leaf that does not exist this runs a SECOND
             * full find_file_in_dir, on `<leaf>?`.  Its syscalls land in the
             * per-component phases; IOS_PH_REPARSE gets only what the probe
             * itself adds around them (the WCHAR copy, the openat, and
             * resolve_reparse_point), so the phases stay disjoint. */
            unsigned long long ios_rp0 = ios_fs_now_us();
            NTSTATUS ios_rpst;
#endif

            memcpy( reparse_name, name, (end - name) * sizeof(WCHAR) );
            reparse_name[end - name] = '?';

            if (!name_len && open_reparse)
            {
#ifdef WINE_IOS
                ios_ph_add( IOS_PH_REPARSE, ios_rp0 );
#endif
                status = find_file_in_dir( root_fd, unix_name, pos, reparse_name, end - name + 1, is_unix );
#ifdef WINE_IOS
                ios_rp0 = ios_fs_now_us();
#endif
            }
            else
            {
#ifdef WINE_IOS
                ios_ph_add( IOS_PH_REPARSE, ios_rp0 );
                ios_rpst = find_file_in_dir( root_fd, unix_name, pos, reparse_name, end - name + 1, is_unix );
                ios_rp0 = ios_fs_now_us();
                if (!ios_rpst && (reparse_fd = openat( root_fd, unix_name, O_RDONLY )) >= 0)
#else
                if (!find_file_in_dir( root_fd, unix_name, pos, reparse_name, end - name + 1, is_unix )
                    && (reparse_fd = openat( root_fd, unix_name, O_RDONLY )) >= 0)
#endif
                {
                    status = resolve_reparse_point( reparse_fd, root_fd, attr, nt_name, nt_pos, next - name, buffer,
                                                    unix_len, pos, disposition, open_reparse, is_unix, reparse_count );
                    close( reparse_fd );
                    free( reparse_name );
#ifdef WINE_IOS
                    /* reparse walks a different path; never cached */
                    ios_ph_add( IOS_PH_REPARSE, ios_rp0 );
#endif
                    return status;
                }
            }
            free( reparse_name );
#ifdef WINE_IOS
            ios_ph_add( IOS_PH_REPARSE, ios_rp0 );
#endif
        }

        /* if this is the last element, not finding it is not necessarily fatal */
        if (!name_len)
        {
            if (status == STATUS_OBJECT_NAME_NOT_FOUND)
            {
                if (disposition != FILE_OPEN && disposition != FILE_OVERWRITE)
                {
                    ret = ntdll_wcstoumbs( name, end - name, unix_name + pos + 1, MAX_DIR_ENTRY_LEN + 1, TRUE );
                    if (ret > 0 && ret <= MAX_DIR_ENTRY_LEN)
                    {
                        unix_name[pos] = '/';
                        pos += ret + 1;
                        if (end < next) unix_name[pos++] = '/';
                        unix_name[pos] = 0;
                        status = STATUS_NO_SUCH_FILE;
                        break;
                    }
                }
            }
            else if (status == STATUS_SUCCESS && disposition == FILE_CREATE)
            {
                status = STATUS_OBJECT_NAME_COLLISION;
            }
            if (end < next) strcat( unix_name, "/" );
        }
        else if (status == STATUS_OBJECT_NAME_NOT_FOUND) status = STATUS_OBJECT_PATH_NOT_FOUND;

        if (status != STATUS_SUCCESS) break;

        pos += strlen( unix_name + pos );
        nt_pos += next - name;
        name = next;
#ifdef WINE_IOS
        ios_depth++;
#endif
    }

#ifdef WINE_IOS
    IOS_FSA( ios_fs_depth[ios_depth > IOS_FS_DEPTH_MAX ? IOS_FS_DEPTH_MAX : ios_depth], 1 );
    if (ios_have_key)
    {
        /* A fully resolved path goes into the positive cache as the on-disk
         * spelling.  STATUS_NO_SUCH_FILE deliberately does not: it means the
         * caller asked to CREATE the leaf and wants the constructed name
         * back, and the walk that produced it is the cheap one anyway. */
        if (status == STATUS_SUCCESS) ios_pc_put( ios_kbuf, *buffer + ios_pos0 + 1 );
        else if (!open_reparse && !ios_np_disabled() && ios_cstamp_ok && ios_cstamp.mtime &&
                 (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND))
        {
            /* ml913: the walk stopped at the first component that does not
             * exist, and every path in this function leaves `pos` at the end
             * of the last one that DOES — so (*buffer)[0..pos) is exactly the
             * deepest existing directory, in its real on-disk spelling.
             * Record the whole absence against that directory's stamp.
             * find_file_in_dir normally already stat'd it for us (either to
             * validate a per-component negative entry or to stamp its own
             * scan), so this usually costs no syscall at all.
             *
             * ml914: only a stamp find_file_in_dir read BEFORE it proved the
             * name absent will do (ios_cstamp_ok).  The old code fell back to
             * stat'ing the directory HERE, after the whole walk had finished,
             * whenever no stamp had been handed over -- which is exactly the
             * ordering that bakes a just-created file into a permanent
             * absence, so that fallback is gone.  Not caching costs one walk;
             * caching the wrong answer costs the title. */
            char *nb = *buffer;
            char save = nb[pos];

            nb[pos] = 0;
            ios_np_put( ios_nbuf, nb, &ios_cstamp, status );
            nb[pos] = save;
        }
    }
    /* ml915: and the half of that answer the NEXT name in this directory can
     * reuse.  STATUS_OBJECT_NAME_NOT_FOUND is precisely "every component but
     * the last resolved", and every path through this function leaves `pos` at
     * the end of the last component that exists -- so (*buffer)[0..pos) is the
     * requested parent's resolved on-disk spelling.  PATH_NOT_FOUND stops
     * higher up and NO_SUCH_FILE has already moved `pos` past a constructed
     * leaf, so neither is recorded. */
    if (ios_have_pd && status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        char *nb = *buffer;
        char save = nb[pos];

        nb[pos] = 0;
        ios_pc_put( ios_pdbuf, nb );
        nb[pos] = save;
    }
#endif
    return status;
}


/******************************************************************************
 *           nt_to_unix_file_name_no_root
 */
static NTSTATUS nt_to_unix_file_name_no_root( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name,
                                              char **unix_name_ret, UINT disposition,
                                              BOOL open_reparse, unsigned int reparse_count )
{
    static const WCHAR unixW[] = {'u','n','i','x'};
    static const WCHAR invalid_charsW[] = { INVALID_NT_CHARS, 0 };

    NTSTATUS status = STATUS_SUCCESS;
    unsigned int nt_pos;
    const WCHAR *name;
    struct stat st;
    char *unix_name;
    int pos, ret, name_len, unix_len, prefix_len;
    WCHAR prefix[MAX_DIR_ENTRY_LEN + 1];
    BOOLEAN is_unix = FALSE;
#ifdef WINE_IOS
    /* ml913: everything this function does before handing off to
     * lookup_unix_name — the DOS prefix parse, the config_dir/dosdevices
     * assembly, the malloc, and the non-drive prefix lstat. */
    unsigned long long ios_ph0 = ios_fs_now_us();
#endif

    name     = attr->ObjectName->Buffer;
    name_len = attr->ObjectName->Length / sizeof(WCHAR);

    if (!name_len || name[0] != '\\') return STATUS_OBJECT_PATH_SYNTAX_BAD;

    if (!(nt_pos = get_dos_prefix_len( attr->ObjectName )))
        return STATUS_BAD_DEVICE_TYPE;  /* no DOS prefix, assume NT native name */

    name += nt_pos;
    name_len -= nt_pos;

    if (!name_len) return STATUS_OBJECT_NAME_INVALID;

    /* check for sub-directory */
    for (pos = 0; pos < name_len && pos <= MAX_DIR_ENTRY_LEN; pos++)
    {
        if (name[pos] == '\\') break;
        if (name[pos] < 32 || wcschr( invalid_charsW, name[pos] ))
            return STATUS_OBJECT_NAME_INVALID;
        prefix[pos] = (name[pos] >= 'A' && name[pos] <= 'Z') ? name[pos] + 'a' - 'A' : name[pos];
    }
    if (pos > MAX_DIR_ENTRY_LEN) return STATUS_OBJECT_NAME_INVALID;

    if (pos >= 4 && !memcmp( prefix, unixW, sizeof(unixW) ))
    {
        /* allow slash for unix namespace */
        if (pos > 4 && prefix[4] == '/') pos = 4;
        is_unix = pos == 4;
    }
    prefix_len = pos;
    prefix[prefix_len] = 0;

    unix_len = name_len * 3 + MAX_DIR_ENTRY_LEN + 3;
    unix_len += strlen(config_dir) + sizeof("/dosdevices/");
    if (!(unix_name = malloc( unix_len ))) return STATUS_NO_MEMORY;
    strcpy( unix_name, config_dir );
    strcat( unix_name, "/dosdevices/" );
    pos = strlen(unix_name);

    ret = ntdll_wcstoumbs( prefix, prefix_len, unix_name + pos, unix_len - pos - 1, TRUE );
    if (ret <= 0)
    {
        free( unix_name );
        return STATUS_OBJECT_NAME_INVALID;
    }

    if (prefix_len == name_len)  /* no subdir, plain DOS device */
    {
        unix_name[pos + ret] = 0;
        *unix_name_ret = unix_name;
        return get_dos_device( unix_name_ret, pos );
    }
    pos += ret;

    /* check if prefix exists (except for DOS drives to avoid extra stat calls) */

    if (wcschr( prefix, '/' ))
    {
        free( unix_name );
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    if (prefix_len != 2 || prefix[1] != ':')
    {
        unix_name[pos] = 0;
        if (lstat( unix_name, &st ) == -1 && errno == ENOENT)
        {
            if (!is_unix)
            {
                free( unix_name );
                return STATUS_BAD_DEVICE_TYPE;
            }
            pos = 0;  /* fall back to unix root */
        }
    }

    prefix_len++;  /* skip initial backslash */
    if (name_len > prefix_len && name[prefix_len] == '\\') prefix_len++;  /* allow a second backslash */
    nt_pos += prefix_len;

#ifdef WINE_IOS
    ios_ph_add( IOS_PH_PREFIX, ios_ph0 );
#endif
    status = lookup_unix_name( AT_FDCWD, attr, nt_name, nt_pos, &unix_name, unix_len,
                               pos, disposition, open_reparse, is_unix, reparse_count );
    if (status == STATUS_SUCCESS || status == STATUS_NO_SUCH_FILE)
    {
        *unix_name_ret = unix_name;
    }
    else
    {
        free( unix_name );
    }
    return status;
}


/******************************************************************************
 *           nt_to_unix_file_name
 *
 * Convert a file name from NT namespace to Unix namespace.
 *
 * If disposition is not FILE_OPEN or FILE_OVERWRITE, the last path
 * element doesn't have to exist; in that case STATUS_NO_SUCH_FILE is
 * returned, but the unix name is still filled in properly.
 */
static NTSTATUS nt_to_unix_file_name( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name,
                                      char **name_ret, UINT disposition, BOOL open_reparse )
{
    enum server_fd_type type;
    int root_fd, needs_close;
    const WCHAR *name;
    char *unix_name;
    int name_len, unix_len;
    NTSTATUS status;

    if (!attr->RootDirectory)  /* without root dir fall back to normal lookup */
        return nt_to_unix_file_name_no_root( attr, nt_name, name_ret, disposition, open_reparse, 0 );

    name     = attr->ObjectName->Buffer;
    name_len = attr->ObjectName->Length / sizeof(WCHAR);

    if (name_len && name[0] == '\\') return STATUS_INVALID_PARAMETER;

    unix_len = name_len * 3 + MAX_DIR_ENTRY_LEN + 3;
    if (!(unix_name = malloc( unix_len ))) return STATUS_NO_MEMORY;
    unix_name[0] = '.';

    if (!(status = server_get_unix_fd( attr->RootDirectory, 0, &root_fd, &needs_close, &type, NULL )))
    {
        if (type != FD_TYPE_DIR)
        {
            if (needs_close) close( root_fd );
            status = STATUS_BAD_DEVICE_TYPE;
        }
        else
        {
            status = lookup_unix_name( root_fd, attr, nt_name, 0, &unix_name, unix_len,
                                       1, disposition, open_reparse, FALSE, 0 );
            if (needs_close) close( root_fd );
        }
    }
    else if (status == STATUS_OBJECT_TYPE_MISMATCH) status = STATUS_BAD_DEVICE_TYPE;

    if (status == STATUS_SUCCESS || status == STATUS_NO_SUCH_FILE)
    {
        TRACE( "%s -> %s\n", debugstr_us(attr->ObjectName), debugstr_a(unix_name) );
        *name_ret = unix_name;
    }
    else
    {
        TRACE( "%s not found in %s\n", debugstr_w(name), unix_name );
        free( unix_name );
    }
    return status;
}


/******************************************************************
 *		collapse_path
 *
 * Get rid of . and .. components in the path.
 */
static WCHAR *collapse_path( WCHAR *path )
{
    WCHAR *p, *start, *next;

    /* convert every / into a \ */
    for (p = path; *p; p++) if (*p == '/') *p = '\\';

    p = path + 4;
    while (*p && *p != '\\') p++;
    start = p + 1;

    /* collapse duplicate backslashes */
    next = start;
    for (p = next; *p; p++) if (*p != '\\' || next[-1] != '\\') *next++ = *p;
    *next = 0;

    p = start;
    while (*p)
    {
        if (*p == '.')
        {
            switch(p[1])
            {
            case '\\': /* .\ component */
                next = p + 2;
                memmove( p, next, (wcslen(next) + 1) * sizeof(WCHAR) );
                continue;
            case 0:  /* final . */
                if (p > start) p--;
                *p = 0;
                continue;
            case '.':
                if (p[2] == '\\')  /* ..\ component */
                {
                    next = p + 3;
                    if (p > start)
                    {
                        p--;
                        while (p > start && p[-1] != '\\') p--;
                    }
                    memmove( p, next, (wcslen(next) + 1) * sizeof(WCHAR) );
                    continue;
                }
                else if (!p[2])  /* final .. */
                {
                    if (p > start)
                    {
                        p--;
                        while (p > start && p[-1] != '\\') p--;
                        if (p > start) p--;
                    }
                    *p = 0;
                    continue;
                }
                break;
            }
        }
        /* skip to the next component */
        while (*p && *p != '\\') p++;
        if (*p == '\\')
        {
            /* remove last dot in previous dir name */
            if (p > start && p[-1] == '.') memmove( p-1, p, (wcslen(p) + 1) * sizeof(WCHAR) );
            else p++;
        }
    }

    /* remove trailing spaces and dots (yes, Windows really does that, don't ask) */
    while (p > start && (p[-1] == ' ' || p[-1] == '.')) p--;
    *p = 0;
    return path;
}


/* from MSDN */
#define MAXIMUM_REPARSE_COUNT 63


static NTSTATUS resolve_absolute_reparse_point( const WCHAR *target, unsigned int target_len,
        OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name, const WCHAR *remainder, unsigned int remainder_len,
        char **unix_name, UINT disposition, BOOL open_reparse, unsigned int reparse_count )
{
    WCHAR *new_nt_name;
    char *new_unix_name;
    NTSTATUS status;

    TRACE( "target %s\n", debugstr_wn(target, target_len) );

    /* glue together the target with the remainder of the path */

    if (!(new_nt_name = malloc( (target_len + 1 + remainder_len + 1) * sizeof(WCHAR) ))) return STATUS_NO_MEMORY;
    memcpy( new_nt_name, target, target_len * sizeof(WCHAR) );
    if (remainder_len)
    {
        if (new_nt_name[target_len - 1] != '\\')
            new_nt_name[target_len++] = '\\';
        memcpy( new_nt_name + target_len, remainder, remainder_len * sizeof(WCHAR) );
    }
    new_nt_name[target_len + remainder_len] = 0;

    free( nt_name->Buffer );
    nt_name->Buffer = new_nt_name;
    nt_name->Length = (target_len + remainder_len) * sizeof(WCHAR);
    nt_name->MaximumLength = nt_name->Length + sizeof(WCHAR);
    attr->RootDirectory = 0;
    attr->ObjectName = nt_name;

    status = nt_to_unix_file_name_no_root( attr, nt_name, &new_unix_name, disposition, open_reparse, reparse_count );
    if (!status || status == STATUS_NO_SUCH_FILE)
    {
        free( *unix_name );
        *unix_name = new_unix_name;
    }
    return status;
}


/* limited version of collapse_path() that only deals with . and .. elements
 * in relative symlinks */
static NTSTATUS collapse_relative_symlink( WCHAR *path, unsigned int len, unsigned int *ret_len )
{
    const WCHAR *end = path + len;
    WCHAR *p, *start, *next;

    if (path[0] == '\\')
    {
        p = path + 4;
        while (*p && *p != '\\') p++;
        p++;
    }
    else
    {
        p = path;
    }
    start = p;

    while (p < end)
    {
        if (*p == '.')
        {
            if (p + 1 == end) /* final . */
            {
                if (p > start) p--;
                end = p;
                continue;
            }
            else if (p[1] == '\\') /* .\ component */
            {
                next = p + 2;
                memmove( p, next, (end - next) * sizeof(WCHAR) );
                end -= 2;
                continue;
            }
            else if (p[1] == '.')
            {
                if (p + 2 == end) /* final .. */
                {
                    if (p == start) return STATUS_IO_REPARSE_DATA_INVALID;
                    p--;
                    while (p > start && p[-1] != '\\') p--;
                    if (p > start) p--;
                    end = p;
                    continue;
                }
                else if (p[2] == '\\') /* ..\ component */
                {
                    if (p == start) return STATUS_IO_REPARSE_DATA_INVALID;
                    next = p + 3;
                    p--;
                    while (p > start && p[-1] != '\\') p--;
                    memmove( p, next, (end - next) * sizeof(WCHAR) );
                    end -= (next - p);
                    continue;
                }
            }
        }

        /* skip to the next component */
        while (p < end && *p != '\\') p++;
        if (p < end) p++;
    }

    *ret_len = end - path;
    return STATUS_SUCCESS;
}


static NTSTATUS resolve_reparse_point( int fd, int root_fd, OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name,
        unsigned int nt_pos, unsigned int reparse_len, char **unix_name, int unix_len, int pos,
        UINT disposition, BOOL open_reparse, BOOL is_unix, unsigned int reparse_count )
{
    const WCHAR *name = attr->ObjectName->Buffer;
    unsigned int name_len = attr->ObjectName->Length / sizeof(WCHAR);
    const WCHAR *remainder = name + nt_pos + reparse_len;
    unsigned int remainder_len = name_len - (nt_pos + reparse_len);
    REPARSE_DATA_BUFFER *data;
    NTSTATUS status;
    int size;

    if (reparse_count++ >= MAXIMUM_REPARSE_COUNT)
    {
        WARN( "too many reparse points\n" );
        return STATUS_REPARSE_POINT_NOT_RESOLVED;
    }

    if (!(data = malloc( MAXIMUM_REPARSE_DATA_BUFFER_SIZE ))) return STATUS_NO_MEMORY;

    if ((size = xattr_fget( fd, XATTR_REPARSE, data, MAXIMUM_REPARSE_DATA_BUFFER_SIZE )) < 0)
    {
        ERR( "failed to read: %s\n", strerror(errno) );
        free( data );
        return errno_to_status( errno );
    }

    TRACE( "size %d tag %#x\n", size, data->ReparseTag );

    if (size < sizeof(*data))
    {
        free( data );
        return STATUS_IO_REPARSE_DATA_INVALID;
    }

    switch (data->ReparseTag)
    {
    case IO_REPARSE_TAG_SYMLINK:
    {
        const WCHAR *target = data->SymbolicLinkReparseBuffer.PathBuffer
                        + data->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR);
        USHORT target_len = data->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR);

        if (data->SymbolicLinkReparseBuffer.Flags & SYMLINK_FLAG_RELATIVE)
        {
            unsigned int collapsed_len;
            WCHAR *new_nt_name;

            TRACE( "target %s\n", debugstr_wn(target, target_len) );

            if (!target_len)
            {
                free( data );
                return STATUS_IO_REPARSE_DATA_INVALID;
            }

            if (!(new_nt_name = malloc( (nt_pos + target_len + 1 + remainder_len + 1) * sizeof(WCHAR) )))
            {
                free( data );
                return STATUS_NO_MEMORY;
            }

            memcpy( new_nt_name, name, nt_pos * sizeof(WCHAR) );
            memcpy( new_nt_name + nt_pos, target, target_len * sizeof(WCHAR) );

            if ((status = collapse_relative_symlink( new_nt_name, nt_pos + target_len, &collapsed_len )))
            {
                if (attr->RootDirectory)
                {
                    /* FIXME: it's legal to unwind past the root directory (but
                     * not past the volume root), which we can't detect here.
                     * We need to retrieve the whole NT name */
                    FIXME( "attempt to unwind past root directory %s\n", debugstr_wn(target, target_len) );
                }
                free( new_nt_name );
                free( data );
                return status;
            }

            if (remainder_len)
            {
                if (new_nt_name[collapsed_len - 1] != '\\')
                    new_nt_name[collapsed_len++] = '\\';
                memcpy( new_nt_name + collapsed_len, remainder, remainder_len * sizeof(WCHAR) );
            }
            new_nt_name[collapsed_len + remainder_len] = 0;

            free( nt_name->Buffer );
            nt_name->Buffer = new_nt_name;
            nt_name->Length = (collapsed_len + remainder_len) * sizeof(WCHAR);
            nt_name->MaximumLength = nt_name->Length + sizeof(WCHAR);
            attr->ObjectName = nt_name;

            status = lookup_unix_name( root_fd, attr, nt_name, nt_pos, unix_name, unix_len, pos,
                                       disposition, open_reparse, is_unix, reparse_count );
        }
        else
        {
            status = resolve_absolute_reparse_point( target, target_len, attr, nt_name,
                                                     remainder, remainder_len, unix_name,
                                                     disposition, open_reparse, reparse_count );
        }
        break;
    }

    case IO_REPARSE_TAG_MOUNT_POINT:
    {
        const WCHAR *target = data->MountPointReparseBuffer.PathBuffer
                        + data->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR);
        USHORT target_len = data->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR);

        status = resolve_absolute_reparse_point( target, target_len, attr, nt_name, remainder, remainder_len,
                                                 unix_name, disposition, open_reparse, reparse_count );
        break;
    }

    default:
        if (!IsReparseTagDirectory(data->ReparseTag))
        {
            status = STATUS_IO_REPARSE_TAG_NOT_HANDLED;
            break;
        }

        /* Directory reparse tags can be opened as normal directories.
         * This is doable, but tricky, and unlikely to be needed. */
        FIXME( "directory reparse tag %#x\n", data->ReparseTag );
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    free( data );
    return status;
}


/***********************************************************************
 *           find_drive_nt_root
 */
static NTSTATUS find_drive_nt_root( char *unix_name, unsigned int len,
                                    WCHAR **nt_name, UINT disposition )
{
    unsigned int i, pos, lenW;
    WCHAR *buffer;
    NTSTATUS status = STATUS_SUCCESS;
    struct stat st;
    struct file_identity info[MAX_DOS_DRIVES];

    *nt_name = NULL;

    /* get device and inode of all drives */
    if (!get_drives_info( info )) return STATUS_OBJECT_PATH_NOT_FOUND;

    /* strip off trailing slashes */
    while (len > 1 && unix_name[len - 1] == '/') len--;
    unix_name[len] = 0;

    for (pos = len; pos; pos = remove_last_component( unix_name, pos ))
    {
        char prev = unix_name[pos];
        unix_name[pos] = 0;
        if (stat( unix_name, &st ))
        {
            if (pos < len) return STATUS_OBJECT_PATH_NOT_FOUND;
            if (disposition == FILE_OPEN || disposition == FILE_OVERWRITE)
                return STATUS_OBJECT_NAME_NOT_FOUND;
            status = STATUS_NO_SUCH_FILE;
            continue;
        }
        unix_name[pos] = prev;
        if (!S_ISDIR( st.st_mode )) continue;

        /* find the drive */
        for (i = 0; i < MAX_DOS_DRIVES; i++)
        {
            if (info[i].dev != st.st_dev || info[i].ino != st.st_ino) continue;
            while (pos < len && unix_name[pos] == '/') pos++;
            len -= pos;
            buffer = malloc( (len + ARRAY_SIZE(dos_prefixW) + 1) * sizeof(WCHAR) );
            if (!buffer) return STATUS_NO_MEMORY;
            memcpy( buffer, dos_prefixW, sizeof(dos_prefixW) );
            buffer[4] += i;
            lenW = ARRAY_SIZE(dos_prefixW);
            lenW += ntdll_umbstowcs( unix_name + pos, len, buffer + lenW, len );
            buffer[lenW] = 0;
            *nt_name = collapse_path( buffer );
            return status;
        }
        if (pos <= 1) break;
    }
    return status;
}


/******************************************************************
 *           unix_to_nt_file_name
 */
NTSTATUS unix_to_nt_file_name( const char *unix_name, WCHAR **nt, UINT disposition )
{
    NTSTATUS status;
    WCHAR *buffer;
    ULONG len = strlen(unix_name) + 1;
    char *name = strdup( unix_name );

    *nt = NULL;
    if (!name) return STATUS_NO_MEMORY;
    status = find_drive_nt_root( name, len - 1, &buffer, disposition );
    free( name );
    if (status && status != STATUS_NO_SUCH_FILE) return status;

    if (!buffer)  /* conversion failed, return \\?\unix path */
    {
        if (!(buffer = malloc( sizeof(unix_prefixW) + len * sizeof(WCHAR) ))) return STATUS_NO_MEMORY;
        memcpy( buffer, unix_prefixW, sizeof(unix_prefixW) );
        ntdll_umbstowcs( unix_name, len, buffer + ARRAY_SIZE(unix_prefixW), len );
        collapse_path( buffer );
    }

    *nt = buffer;
    return status;
}


/******************************************************************
 *           ntdll_get_dos_file_name
 */
NTSTATUS ntdll_get_dos_file_name( const char *unix_name, WCHAR **dos, UINT disposition )
{
    WCHAR *buffer;
    NTSTATUS status = unix_to_nt_file_name( unix_name, &buffer, disposition );

    if (buffer)
    {
        if (buffer[5] == ':') memmove( buffer, buffer + 4, (wcslen(buffer + 4) + 1) * sizeof(WCHAR) );
        else buffer[1] = '\\';
    }
    *dos = buffer;
    return status;
}


/* remove trailing backslash from NT name; helper for get_nt_and_unix_names */
static void remove_trailing_backslash( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name )
{
    UNICODE_STRING *obj_name = attr->ObjectName;
    ULONG len = obj_name->Length / sizeof(WCHAR);

    if (!len || obj_name->Buffer[len - 1] != '\\') return;
    if (!attr->RootDirectory)
    {
        ULONG i, count = 0;
        for (i = 0; i < len; i++) if (obj_name->Buffer[i] == '\\') count++;
        if (count <= 3) return;
    }
    if (obj_name != nt_name)  /* not already redirected, make a copy */
    {
        nt_name->Length = nt_name->MaximumLength = obj_name->Length;
        if (!(nt_name->Buffer = malloc( nt_name->MaximumLength ))) return;
        memcpy( nt_name->Buffer, obj_name->Buffer, nt_name->Length );
        attr->ObjectName = nt_name;
    }

    nt_name->Length -= sizeof(WCHAR);
    nt_name->Buffer[len - 1] = 0;
}

/***********************************************************************
 *           get_nt_and_unix_names
 *
 * Get the true NT name (potentially after wow64 redirection) and the
 * Unix name to open a file.
 *
 * If disposition is not FILE_OPEN or FILE_OVERWRITE, the last path
 * element doesn't have to exist; in that case STATUS_NO_SUCH_FILE is
 * returned, but the names are still filled in properly.
 *
 * nt_name.Buffer and unix_name must be freed by caller in all cases.
 */
NTSTATUS get_nt_and_unix_names( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name,
                                char **unix_name_ret, UINT disposition, BOOL open_reparse )
{
    ULONG lenA, lenW = attr->ObjectName->Length / sizeof(WCHAR);
    UNICODE_STRING *orig = attr->ObjectName;
    NTSTATUS status;

    nt_name->Buffer = NULL;
    *unix_name_ret = NULL;

    if (!attr->RootDirectory && lenW > ARRAY_SIZE(unix_prefixW) &&
        !wcsncmp( attr->ObjectName->Buffer, unix_prefixW, ARRAY_SIZE(unix_prefixW) ))
    {
        const WCHAR *name = attr->ObjectName->Buffer + ARRAY_SIZE(unix_prefixW);
        char *unix_name;
        WCHAR *buffer;

        lenW -= ARRAY_SIZE(unix_prefixW);
        *unix_name_ret = unix_name = malloc( lenW * 3 + 1 );
        if (!unix_name) return STATUS_NO_MEMORY;
        lenA = ntdll_wcstoumbs( name, lenW, unix_name, lenW * 3, FALSE );
        for (ULONG i = 0; i < lenA; i++) if (unix_name[i] == '\\') unix_name[i] = '/';

        status = find_drive_nt_root( unix_name, lenA, &buffer, disposition );
        if (buffer)
        {
            init_unicode_string( nt_name, buffer );
            attr->ObjectName = nt_name;
        }
    }
    else
    {
#ifndef _WIN64
        get_redirect( attr, nt_name );
#endif
        status = nt_to_unix_file_name( attr, nt_name, unix_name_ret, disposition, open_reparse );
    }

    if (!status || status == STATUS_NO_SUCH_FILE)
    {
        remove_trailing_backslash( attr, nt_name );
        TRACE( "%s -> ret %x nt %s unix %s\n", debugstr_us(orig),
               status, debugstr_us(attr->ObjectName), debugstr_a(*unix_name_ret) );
    }
    else TRACE( "%s -> ret %x\n", debugstr_us(orig), status );
    return status;
}


/***********************************************************************
 *           get_full_path
 *
 * Simplified version of RtlGetFullPathName_U.
 */
NTSTATUS get_full_path( char *name, const WCHAR *curdir, UNICODE_STRING *nt_name )
{
    WCHAR *ret;
    ULONG prefix_len, len = max( ARRAY_SIZE(unix_prefixW), wcslen(curdir) ) + strlen(name) + 1;

    /* special case for Unix file name */
    if (name[0] == '/' && !find_drive_nt_root( name, strlen(name), &ret, FILE_OPEN )) goto done;

    if (!(ret = malloc( len * sizeof(WCHAR) ))) return STATUS_NO_MEMORY;

    if (IS_SEPARATOR(name[0]) && name[1] == '?' && name[2] == '?' && IS_SEPARATOR(name[3]))  /* \??\ */
    {
        prefix_len = 0;
    }
    else if (IS_SEPARATOR(name[0]) && IS_SEPARATOR(name[1]))  /* \\ prefix */
    {
        if ((name[2] == '.' || name[2] == '?') && IS_SEPARATOR(name[3])) /* \\?\ device */
        {
            name += 4;
            memcpy( ret, nt_prefixW, sizeof(nt_prefixW) );
            prefix_len = ARRAY_SIZE(nt_prefixW);
        }
        else  /* UNC path */
        {
            name += 2;
            memcpy( ret, unc_prefixW, sizeof(unc_prefixW) );
            prefix_len = ARRAY_SIZE(unc_prefixW);
        }
    }
    else if (IS_SEPARATOR(name[0]))  /* absolute path */
    {
        memcpy( ret, dos_prefixW, sizeof(dos_prefixW) );
        prefix_len = ARRAY_SIZE(dos_prefixW);
        ret[4] = curdir[4];
    }
    else if (name[0] && name[1] == ':')  /* drive letter */
    {
        memcpy( ret, dos_prefixW, sizeof(dos_prefixW) );
        prefix_len = ARRAY_SIZE(dos_prefixW);
        ret[4] = towupper(name[0]);
        name += 2;
    }
    else  /* relative path */
    {
        prefix_len = wcslen( curdir );
        memcpy( ret, curdir, prefix_len * sizeof(WCHAR) );
    }

    ntdll_umbstowcs( name, strlen(name) + 1, ret + prefix_len, len - prefix_len );
    collapse_path( ret );
 done:
    init_unicode_string( nt_name, ret );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_nt_path
 *
 * Simplified version of RtlDosPathNameToNtPathName_U.
 */
NTSTATUS get_nt_path( const WCHAR *name, UNICODE_STRING *nt_name )
{
    ULONG len = wcslen( name );
    WCHAR *ret, *p;

    nt_name->Buffer = NULL;
    if (!(ret = p = malloc( (len + 8) * sizeof(WCHAR) ))) return STATUS_NO_MEMORY;

    if (name[0] == '\\' && name[1] == '\\')
    {
        if ((name[2] == '.' || name[2] == '?') && name[3] == '\\')
        {
            memcpy( p, nt_prefixW, sizeof(nt_prefixW) );
            p += ARRAY_SIZE( nt_prefixW );
            name += 4;
        }
        else
        {
            memcpy( p, unc_prefixW, sizeof(unc_prefixW) );
            p += ARRAY_SIZE( unc_prefixW );
            name += 2;
        }
    }
    else if (wcsncmp( name, nt_prefixW, ARRAY_SIZE(nt_prefixW) ))
    {
        memcpy( p, nt_prefixW, sizeof(nt_prefixW) );
        p += ARRAY_SIZE( nt_prefixW );
    }
    wcscpy( p, name );
    collapse_path( ret );
    init_unicode_string( nt_name, ret );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           ntdll_get_unix_file_name
 */
NTSTATUS ntdll_get_unix_file_name( const WCHAR *dos, char **unix_name, UINT disposition )
{
    UNICODE_STRING nt_name, true_nt_name;
    OBJECT_ATTRIBUTES attr;
    char *buffer = NULL;
    NTSTATUS status = get_nt_path( dos, &nt_name );

    if (status) return status;
    InitializeObjectAttributes( &attr, &nt_name, 0, 0, NULL );
    status = get_nt_and_unix_names( &attr, &true_nt_name, &buffer, disposition, FALSE );
    free( nt_name.Buffer );
    free( true_nt_name.Buffer );

    if (!status || status == STATUS_NO_SUCH_FILE)
    {
        /* remove dosdevices prefix for z: drive if it points to the Unix root */
        if (!strncmp( buffer, config_dir, strlen(config_dir) ) &&
            !strncmp( buffer + strlen(config_dir), "/dosdevices/z:/", 15 ))
        {
            struct stat st1, st2;
            BOOL is_root;
            char *p = buffer + strlen(config_dir) + 14;
            *p = 0;
            is_root = !stat( buffer, &st1 ) && !stat( "/", &st2 ) &&
                      st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
            *p = '/';
            if (is_root) memmove( buffer, p, strlen(p) + 1 );
        }
        *unix_name = buffer;
    }
    else free( buffer );

    return status;
}


/***********************************************************************
 *           unmount_device
 *
 * Unmount the specified device.
 */
static NTSTATUS unmount_device( HANDLE handle )
{
    NTSTATUS status;
    int unix_fd, needs_close;

    if (!(status = server_get_unix_fd( handle, 0, &unix_fd, &needs_close, NULL, NULL )))
    {
        struct stat st;
        char *mount_point = NULL;

        if (fstat( unix_fd, &st ) == -1 || !is_valid_mounted_device( &st ))
            status = STATUS_INVALID_PARAMETER;
        else
        {
            if ((mount_point = get_device_mount_point( st.st_rdev )))
            {
#ifdef __APPLE__
                static char diskutil[] = "diskutil";
                static char unmount[] = "unmount";
                char *argv[4] = {diskutil, unmount, mount_point, NULL};
#else
                static char umount[] = "umount";
                char *argv[3] = {umount, mount_point, NULL};
#endif
                __wine_unix_spawnvp( argv, TRUE );
#ifdef linux
                /* umount will fail to release the loop device since we still have
                    a handle to it, so we release it here */
                if (major(st.st_rdev) == LOOP_MAJOR) ioctl( unix_fd, 0x4c01 /*LOOP_CLR_FD*/, 0 );
#endif
                /* Add in a small delay. Without this subsequent tasks
                    like IOCTL_STORAGE_EJECT_MEDIA might fail. */
                usleep( 100000 );
            }
        }
        if (needs_close) close( unix_fd );
    }
    return status;
}


/******************************************************************************
 *              open_unix_file
 *
 * Helper for NtCreateFile that takes a Unix path.
 */
NTSTATUS open_unix_file( HANDLE *handle, const char *unix_name, ACCESS_MASK access,
                         OBJECT_ATTRIBUTES *attr, ULONG attributes, ULONG sharing, ULONG disposition,
                         ULONG options, void *ea_buffer, ULONG ea_length )
{
    struct object_attributes *objattr;
    unsigned int status;
    data_size_t len;

    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_file )
    {
        req->access     = access;
        req->sharing    = sharing;
        req->create     = disposition;
        req->options    = options;
        req->attrs      = attributes;
        wine_server_add_data( req, objattr, len );
        wine_server_add_data( req, unix_name, strlen(unix_name) );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return status;
}


/******************************************************************************
 *              NtCreateFile   (NTDLL.@)
 */
#ifdef WINE_IOS
/* ml487 (#78): defined next to NtReadFile, used here — forward-declare so the
 * call below doesn't become an implicit (non-static) declaration. */
static void ios_js_track_add( HANDLE handle, const char *unix_name );
#endif

#ifdef WINE_IOS
/* ml665: bounded counter for the [file-fail] probe below. */
static int ios_file_fail_logged;
static int ios_file_wfail_logged;   /* ml669: separate budget for write/create opens */
#endif

#ifdef WINE_IOS
/* ml733: video-stream read tracking. See the call site in NtCreateFile. */
static HANDLE ios_video_handles[4];
static unsigned int ios_video_reads[4], ios_video_bytes[4];

static void ios_video_track_open( HANDLE h, const WCHAR *name, int len )
{
    int i;
    char nm[160];
    for (i = 0; i < 4; i++) if (!ios_video_handles[i]) break;
    if (i == 4) return;                       /* only ever a few streams */
    ios_video_handles[i] = h;
    ios_video_reads[i] = ios_video_bytes[i] = 0;
    {
        int k, o = 0;
        for (k = (len > 60 ? len - 60 : 0); k < len && o < (int)sizeof(nm) - 1; k++)
            nm[o++] = (name[k] >= 0x20 && name[k] < 0x7f) ? (char)name[k] : '?';
        nm[o] = 0;
    }
    ERR( "[video-io] ml733 OPEN slot=%d handle=%p ...%s\n", i, h, nm );
}

/* Called from the single read choke point for EVERY status, because end of
 * stream and a stalled decoder are exactly the cases we need to tell apart. */
static void ios_video_read_note( HANDLE h, unsigned int status, UINT got, LARGE_INTEGER *offset )
{
    int i;
    for (i = 0; i < 4; i++) if (ios_video_handles[i] == h) break;
    if (i == 4) return;
    ios_video_reads[i]++;
    ios_video_bytes[i] += got;
    /* Log the first few, then only every 512th, but ALWAYS log a short read,
     * a zero-byte read or a non-success status -- those are the end-of-stream
     * signals, and sampling them away would defeat the whole probe. */
    if (ios_video_reads[i] <= 8 || !(ios_video_reads[i] % 512) || !got || status)
        ERR( "[video-io] ml733 slot=%d read#%u got=%u total=%uKB off=%lld status=%08x%s\n",
             i, ios_video_reads[i], got, ios_video_bytes[i] / 1024,
             offset ? (long long)offset->QuadPart : -1LL, status,
             (!got || status) ? "  <-- END/ERROR" : "" );
}
#endif

NTSTATUS WINAPI NtCreateFile( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                              IO_STATUS_BLOCK *io, LARGE_INTEGER *alloc_size,
                              ULONG attributes, ULONG sharing, ULONG disposition,
                              ULONG options, void *ea_buffer, ULONG ea_length )
{
    OBJECT_ATTRIBUTES new_attr;
    UNICODE_STRING nt_name;
    char *unix_name = NULL;
    BOOL name_hidden = FALSE;
    BOOL created = FALSE;
    unsigned int status;
#ifdef WINE_IOS
    unsigned long long ios_t0 = ios_fs_now_us();
#endif

    TRACE( "handle=%p access=%08x name=%s objattr=%08x root=%p sec=%p io=%p alloc_size=%p "
           "attr=%08x sharing=%08x disp=%d options=%08x ea=%p.0x%08x\n",
           handle, access, debugstr_us(attr->ObjectName), attr->Attributes,
           attr->RootDirectory, attr->SecurityDescriptor, io, alloc_size,
           attributes, sharing, disposition, options, ea_buffer, ea_length );

    *handle = 0;
    if (!attr || !attr->ObjectName) return STATUS_INVALID_PARAMETER;

    if (alloc_size) FIXME( "alloc_size not supported\n" );

    new_attr = *attr;
    if (options & FILE_OPEN_BY_FILE_ID)
    {
        status = file_id_to_unix_file_name( &new_attr, &unix_name, &nt_name );
        if (!status) new_attr.ObjectName = &nt_name;
    }
    else
    {
#ifdef WINE_IOS
        /* ml912: time the path walk on its own.  open=911/547ms says nothing
         * about which half is ours; this does. */
        unsigned long long ios_lk0 = ios_fs_now_us(), ios_lk1;
#endif
        status = get_nt_and_unix_names( &new_attr, &nt_name, &unix_name, disposition,
                                        options & FILE_OPEN_REPARSE_POINT );
#ifdef WINE_IOS
        ios_lk1 = ios_fs_now_us();
        IOS_FSA( ios_fs_open_lk_us, ios_lk1 > ios_lk0 ? ios_lk1 - ios_lk0 : 0 );
        IOS_FSA( ios_fs_open_lk_n, 1 );
        if (status && status != STATUS_NO_SUCH_FILE)
        {
            IOS_FSA( ios_fs_open_lk_fail, 1 );
            /* ml915: and how long that failure took, so [fs-stats] can print
             * fail_avg_us -- the one number the dircache has to move. */
            IOS_FSA( ios_fs_open_lk_fail_us, ios_lk1 > ios_lk0 ? ios_lk1 - ios_lk0 : 0 );
        }
#endif
    }

    if (status == STATUS_BAD_DEVICE_TYPE)
    {
        status = server_open_file_object( handle, access, &new_attr, sharing, options );
        if (status == STATUS_SUCCESS) io->Information = FILE_OPENED;
        goto done;
    }

    if (status == STATUS_NO_SUCH_FILE && disposition != FILE_OPEN && disposition != FILE_OVERWRITE)
    {
        created = TRUE;
        status = STATUS_SUCCESS;
    }

    if (status == STATUS_SUCCESS)
    {
        name_hidden = is_hidden_file( unix_name );
#ifdef WINE_IOS
        {
            /* ml912: open_unix_file() is pure wineserver — the create_file
             * request does the real open() in the server process, so this
             * timer is the server round trip and nothing else. */
            unsigned long long ios_sv0 = ios_fs_now_us(), ios_sv1;
            status = open_unix_file( handle, unix_name, access, &new_attr, attributes,
                                     sharing, disposition, options, ea_buffer, ea_length );
            ios_sv1 = ios_fs_now_us();
            IOS_FSA( ios_fs_open_srv_us, ios_sv1 > ios_sv0 ? ios_sv1 - ios_sv0 : 0 );
            IOS_FSA( ios_fs_open_srv_n, 1 );
            /* ml915: `created` means the walk proved the leaf absent and the
             * server has now made it exist, so the parent directory just
             * gained a name.  Its mtime moved too, but a mtime cannot be
             * relied on to advance within one clock tick and a create
             * followed immediately by an open of the same name is a normal
             * thing for an installer or a save system to do. */
            if (!status && created) ios_dc_invalidate_path( unix_name );
        }
#else
        status = open_unix_file( handle, unix_name, access, &new_attr, attributes,
                                 sharing, disposition, options, ea_buffer, ea_length );
#endif
#ifdef WINE_IOS
        /* ml487 (#78): remember which handles are steamui *.js so NtReadFile can
         * checksum exactly those reads — see ios_js_track_add(). */
        if (!status) ios_js_track_add( *handle, unix_name );
#endif
    }
    else WARN( "%s not found (%x)\n", debugstr_us(attr->ObjectName), status );

    if (status == STATUS_SUCCESS)
    {
        if (created) io->Information = FILE_CREATED;
        else switch(disposition)
        {
        case FILE_SUPERSEDE:
            io->Information = FILE_SUPERSEDED;
            break;
        case FILE_CREATE:
            io->Information = FILE_CREATED;
            break;
        case FILE_OPEN:
        case FILE_OPEN_IF:
            io->Information = FILE_OPENED;
            break;
        case FILE_OVERWRITE:
        case FILE_OVERWRITE_IF:
            io->Information = FILE_OVERWRITTEN;
            break;
        }

        if (io->Information == FILE_CREATED &&
            ((attributes & XATTR_ATTRIBS_MASK) || name_hidden))
        {
            int fd, needs_close;

            /* set any DOS extended attributes */
            if (!server_get_unix_fd( *handle, 0, &fd, &needs_close, NULL, NULL ))
            {
                if (fd_set_dos_attrib( fd, attributes, TRUE ) == -1 && errno != ENOTSUP)
                    WARN( "Failed to set extended attribute " SAMBA_XATTR_DOS_ATTRIB ". errno %d (%s)",
                          errno, strerror( errno ) );
                if (needs_close) close( fd );
            }
        }
    }
    else if (status == STATUS_TOO_MANY_OPENED_FILES)
    {
        static int once;
        if (!once++) ERR_(winediag)( "Too many open files, ulimit -n probably needs to be increased\n" );
    }

 done:
#ifdef WINE_IOS
    /* ml733: track the video stream the cutscene decoder reads.
     *
     * The game plays its intro and then sits on a black screen at 60 FPS
     * without ever loading the next context. The decoder is a native x86-64
     * library reached by P/Invoke, so we cannot see its return values without
     * building call-level tracing -- but every byte it consumes comes through
     * this file layer, which we already own. Whether reads continue forever,
     * stop at end of stream, or stop early separates "the decoder never
     * finishes" from "it finished and the transition never ran", and that is
     * the split worth one run.
     *
     * Name match only, so nothing else pays for it. */
    if (!status && handle && *handle && attr && attr->ObjectName && attr->ObjectName->Buffer)
    {
        const WCHAR *b = attr->ObjectName->Buffer;
        int n = attr->ObjectName->Length / (int)sizeof(WCHAR);
        if (n >= 4)
        {
            WCHAR e3 = b[n-3] | 0x20, e2 = b[n-2] | 0x20, e1 = b[n-1] | 0x20;
            if (b[n-4] == '.' && e3 == 'o' && e2 == 'g' && (e1 == 'v' || e1 == 'g'))
            {
                ios_video_track_open( *handle, b, n );
            }
        }
    }
    /* iOS-Madeira ml665: [file-fail] — we have NEVER logged a failing guest file
     * open, and that blind spot cost several runs on Book of the Dead.
     *
     * Book of the Dead's stdout stream is left at _flags=0,_file=-1 -- the exact
     * state freopen() leaves when it closes a stream and the REOPEN then fails.
     * stderr next to it is a healthy -2 from UCRT's own no-handle path, which
     * proves CRT init and our standard-handle setup are both correct. So the
     * failure is a file that would not open. This names it.
     *
     * Bounded and failure-only: successful opens are the overwhelming majority
     * and logging them would drown the run (and change its timing). */
    /* ml669: SPLIT THE BUDGET. ml665's single 64-entry cap was consumed entirely
     * by ordinary loader search-path misses (winemac.drv, winex11.drv, uxtheme,
     * Common-Controls manifests) 1,600 lines before the game even started, so it
     * never observed a single game file operation. Those read-only probes are
     * expected behaviour, not failures.
     *
     * Writes and creates are what we actually need: Unity's _wfreopen of its log
     * is a write-open, and its failure is what leaves stdout closed at _file=-1.
     * Give them their own generous budget that read-only misses cannot touch. */
    {
        int is_write = (access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) != 0
                       || disposition != FILE_OPEN;
        if (status && is_write && ios_file_wfail_logged < 192)
        {
            const WCHAR *w = nt_name.Buffer ? nt_name.Buffer : (attr && attr->ObjectName ? attr->ObjectName->Buffer : NULL);
            unsigned int wl = nt_name.Buffer ? nt_name.Length / 2
                                             : (attr && attr->ObjectName ? attr->ObjectName->Length / 2 : 0);
            char nb[300];
            unsigned int k = 0;
            if (w) while (k < wl && k < sizeof(nb) - 1) { nb[k] = (w[k] < 32 || w[k] > 126) ? '?' : (char)w[k]; k++; }
            nb[k] = 0;
            ios_file_wfail_logged++;
            /* ml959: log the SHARE MODE too. rdr23's real blocker is a
             * STATUS_SHARING_VIOLATION (0xc0000043) on EMP.dll's own state file
             * %APPDATA%\\EMPRESS\\15a3.bin, opened FILE_OVERWRITE_IF for write --
             * which is why that file sits at 0 bytes on disk. A sharing
             * violation means a conflicting open handle exists, and without the
             * requested share mode there is no way to tell whether wineserver's
             * verdict is correct (a genuinely exclusive holder) or whether we
             * are rejecting an open Windows would allow. */
            dprintf( 2, "[file-wfail] ml669 #%d status=0x%08x disp=%u access=0x%08x sharing=0x%08x "
                     "options=0x%08x unix=%s name=%s\n",
                     ios_file_wfail_logged, status, disposition, access, sharing, options,
                     unix_name ? unix_name : "(none)", nb );
        }
    }
    if (status && ios_file_fail_logged < 64)
    {
        const WCHAR *w = nt_name.Buffer ? nt_name.Buffer : (attr && attr->ObjectName ? attr->ObjectName->Buffer : NULL);
        unsigned int wl = nt_name.Buffer ? nt_name.Length / 2
                                         : (attr && attr->ObjectName ? attr->ObjectName->Length / 2 : 0);
        char nb[300];
        unsigned int k = 0;
        if (w) while (k < wl && k < sizeof(nb) - 1) { nb[k] = (w[k] < 32 || w[k] > 126) ? '?' : (char)w[k]; k++; }
        nb[k] = 0;
        ios_file_fail_logged++;
        dprintf( 2, "[file-fail] ml665 #%d NtCreateFile status=0x%08x disp=%u access=0x%08x "
                 "options=0x%08x unix=%s name=%s\n",
                 ios_file_fail_logged, status, disposition, access, options,
                 unix_name ? unix_name : "(none)", nb );
    }
    ios_fs_note( created ? IOS_OP_CREATE : IOS_OP_OPEN, ios_t0, ios_fs_now_us() );
#endif
    free( unix_name );
    free( nt_name.Buffer );
    return io->Status = status;
}


/******************************************************************************
 *              NtOpenFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenFile( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                            IO_STATUS_BLOCK *io, ULONG sharing, ULONG options )
{
    return NtCreateFile( handle, access, attr, io, NULL, 0, sharing, FILE_OPEN, options, NULL, 0 );
}


/******************************************************************************
 *		NtCreateMailslotFile    (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateMailslotFile( HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr,
                                      IO_STATUS_BLOCK *io, ULONG options, ULONG quota, ULONG msg_size,
                                      LARGE_INTEGER *timeout )
{
    unsigned int status;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "%p %08x %p %p %08x %08x %08x %p\n",
           handle, access, attr, io, options, quota, msg_size, timeout );

    *handle = 0;
    if (!attr) return STATUS_INVALID_PARAMETER;
    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_mailslot )
    {
        req->access       = access;
        req->options      = options;
        req->max_msgsize  = msg_size;
        req->read_timeout = timeout ? timeout->QuadPart : -1;
        wine_server_add_data( req, objattr, len );
        if (!(status = wine_server_call( req ))) *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return status;
}


/******************************************************************
 *		NtCreateNamedPipeFile    (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateNamedPipeFile( HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr,
                                       IO_STATUS_BLOCK *io, ULONG sharing, ULONG dispo, ULONG options,
                                       ULONG pipe_type, ULONG read_mode, ULONG completion_mode,
                                       ULONG max_inst, ULONG inbound_quota, ULONG outbound_quota,
                                       LARGE_INTEGER *timeout )
{
    unsigned int status;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if (!attr) return STATUS_INVALID_PARAMETER;

    TRACE( "(%p %x %s %p %x %d %x %d %d %d %d %d %d %p)\n",
           handle, access, debugstr_us(attr->ObjectName), io, sharing, dispo,
           options, pipe_type, read_mode, completion_mode, max_inst,
           inbound_quota, outbound_quota, timeout );

    /* assume we only get relative timeout */
    if (timeout && timeout->QuadPart > 0) FIXME( "Wrong time %s\n", wine_dbgstr_longlong(timeout->QuadPart) );

    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_named_pipe )
    {
        req->access  = access;
        req->options = options;
        req->sharing = sharing;
        req->flags =
            (pipe_type ? NAMED_PIPE_MESSAGE_STREAM_WRITE   : 0) |
            (read_mode ? NAMED_PIPE_MESSAGE_STREAM_READ    : 0) |
            (completion_mode ? NAMED_PIPE_NONBLOCKING_MODE : 0);
        req->disposition  = dispo;
        req->maxinstances = max_inst;
        req->outsize = outbound_quota;
        req->insize  = inbound_quota;
        req->timeout = timeout ? timeout->QuadPart : 0ULL;
        wine_server_add_data( req, objattr, len );
        if (!(status = wine_server_call( req )))
        {
            *handle = wine_server_ptr_handle( reply->handle );
            io->Information = reply->created ? FILE_CREATED : FILE_OPENED;
        }
    }
    SERVER_END_REQ;

    free( objattr );
    return io->Status = status;
}


/******************************************************************
 *              NtDeleteFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtDeleteFile( OBJECT_ATTRIBUTES *attr )
{
    HANDLE handle;
    NTSTATUS status;
    char *unix_name;
    UNICODE_STRING nt_name;
    OBJECT_ATTRIBUTES new_attr = *attr;

    if (!(status = get_nt_and_unix_names( &new_attr, &nt_name, &unix_name, FILE_OPEN, FALSE )))
    {
        if (!(status = open_unix_file( &handle, unix_name, GENERIC_READ | GENERIC_WRITE | DELETE, &new_attr,
                                       0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                                       FILE_DELETE_ON_CLOSE, NULL, 0 )))
        {
            NtClose( handle );
#ifdef WINE_IOS
            ios_dc_invalidate_path( unix_name );   /* ml915: a name left that directory */
#endif
        }
    }
    free( unix_name );
    free( nt_name.Buffer );
    return status;
}


/******************************************************************************
 *              NtQueryFullAttributesFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryFullAttributesFile( const OBJECT_ATTRIBUTES *attr,
                                           FILE_NETWORK_OPEN_INFORMATION *info )
{
    char *unix_name;
    unsigned int status;
    UNICODE_STRING nt_name;
    OBJECT_ATTRIBUTES new_attr = *attr;
#ifdef WINE_IOS
    unsigned long long ios_t0 = ios_fs_now_us();
#endif

    if (!(status = get_nt_and_unix_names( &new_attr, &nt_name, &unix_name, FILE_OPEN, TRUE )))
    {
        ULONG attributes;
        struct stat st;

        if (get_file_info( unix_name, &st, &attributes, NULL ) == -1)
            status = errno_to_status( errno );
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
            status = STATUS_INVALID_INFO_CLASS;
        else
            fill_file_info( &st, attributes, info, FileNetworkOpenInformation );
    }
    else WARN( "%s not found (%x)\n", debugstr_us(attr->ObjectName), status );
    free( unix_name );
    free( nt_name.Buffer );
#ifdef WINE_IOS
    ios_fs_note( IOS_OP_QFULL, ios_t0, ios_fs_now_us() );
#endif
    return status;
}


/******************************************************************************
 *              NtQueryAttributesFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryAttributesFile( const OBJECT_ATTRIBUTES *attr, FILE_BASIC_INFORMATION *info )
{
    char *unix_name;
    unsigned int status;
    UNICODE_STRING nt_name;
    OBJECT_ATTRIBUTES new_attr = *attr;
#ifdef WINE_IOS
    unsigned long long ios_t0 = ios_fs_now_us();
#endif

    if (!(status = get_nt_and_unix_names( &new_attr, &nt_name, &unix_name, FILE_OPEN, TRUE )))
    {
        ULONG attributes;
        struct stat st;

        if (get_file_info( unix_name, &st, &attributes, NULL ) == -1)
            status = errno_to_status( errno );
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
            status = STATUS_INVALID_INFO_CLASS;
        else
            status = fill_file_info( &st, attributes, info, FileBasicInformation );
    }
    else WARN( "%s not found (%x)\n", debugstr_us(attr->ObjectName), status );
    free( unix_name );
    free( nt_name.Buffer );
#ifdef WINE_IOS
    ios_fs_note( IOS_OP_QATTR, ios_t0, ios_fs_now_us() );
#endif
    return status;
}


/******************************************************************************
 *              NtQueryInformationFile   (NTDLL.@)
 */
#ifdef WINE_IOS
#define NtQueryInformationFile ios_inner_NtQueryInformationFile
#endif
NTSTATUS WINAPI NtQueryInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                        void *ptr, ULONG len, FILE_INFORMATION_CLASS class )
{
    static const size_t info_sizes[FileMaximumInformation] =
    {
        0,
        sizeof(FILE_DIRECTORY_INFORMATION),            /* FileDirectoryInformation */
        sizeof(FILE_FULL_DIRECTORY_INFORMATION),       /* FileFullDirectoryInformation */
        sizeof(FILE_BOTH_DIRECTORY_INFORMATION),       /* FileBothDirectoryInformation */
        sizeof(FILE_BASIC_INFORMATION),                /* FileBasicInformation */
        sizeof(FILE_STANDARD_INFORMATION),             /* FileStandardInformation */
        sizeof(FILE_INTERNAL_INFORMATION),             /* FileInternalInformation */
        sizeof(FILE_EA_INFORMATION),                   /* FileEaInformation */
        0,                                             /* FileAccessInformation */
        sizeof(FILE_NAME_INFORMATION),                 /* FileNameInformation */
        sizeof(FILE_RENAME_INFORMATION)-sizeof(WCHAR), /* FileRenameInformation */
        0,                                             /* FileLinkInformation */
        sizeof(FILE_NAMES_INFORMATION)-sizeof(WCHAR),  /* FileNamesInformation */
        sizeof(FILE_DISPOSITION_INFORMATION),          /* FileDispositionInformation */
        sizeof(FILE_POSITION_INFORMATION),             /* FilePositionInformation */
        sizeof(FILE_FULL_EA_INFORMATION),              /* FileFullEaInformation */
        0,                                             /* FileModeInformation */
        sizeof(FILE_ALIGNMENT_INFORMATION),            /* FileAlignmentInformation */
        sizeof(FILE_ALL_INFORMATION),                  /* FileAllInformation */
        sizeof(FILE_ALLOCATION_INFORMATION),           /* FileAllocationInformation */
        sizeof(FILE_END_OF_FILE_INFORMATION),          /* FileEndOfFileInformation */
        0,                                             /* FileAlternateNameInformation */
        sizeof(FILE_STREAM_INFORMATION)-sizeof(WCHAR), /* FileStreamInformation */
        sizeof(FILE_PIPE_INFORMATION),                 /* FilePipeInformation */
        sizeof(FILE_PIPE_LOCAL_INFORMATION),           /* FilePipeLocalInformation */
        0,                                             /* FilePipeRemoteInformation */
        sizeof(FILE_MAILSLOT_QUERY_INFORMATION),       /* FileMailslotQueryInformation */
        0,                                             /* FileMailslotSetInformation */
        0,                                             /* FileCompressionInformation */
        0,                                             /* FileObjectIdInformation */
        0,                                             /* FileCompletionInformation */
        0,                                             /* FileMoveClusterInformation */
        0,                                             /* FileQuotaInformation */
        0,                                             /* FileReparsePointInformation */
        sizeof(FILE_NETWORK_OPEN_INFORMATION),         /* FileNetworkOpenInformation */
        sizeof(FILE_ATTRIBUTE_TAG_INFORMATION),        /* FileAttributeTagInformation */
        0,                                             /* FileTrackingInformation */
        0,                                             /* FileIdBothDirectoryInformation */
        0,                                             /* FileIdFullDirectoryInformation */
        0,                                             /* FileValidDataLengthInformation */
        0,                                             /* FileShortNameInformation */
        0,                                             /* FileIoCompletionNotificationInformation, */
        0,                                             /* FileIoStatusBlockRangeInformation */
        0,                                             /* FileIoPriorityHintInformation */
        0,                                             /* FileSfioReserveInformation */
        0,                                             /* FileSfioVolumeInformation */
        0,                                             /* FileHardLinkInformation */
        0,                                             /* FileProcessIdsUsingFileInformation */
        0,                                             /* FileNormalizedNameInformation */
        0,                                             /* FileNetworkPhysicalNameInformation */
        0,                                             /* FileIdGlobalTxDirectoryInformation */
        0,                                             /* FileIsRemoteDeviceInformation */
        0,                                             /* FileAttributeCacheInformation */
        0,                                             /* FileNumaNodeInformation */
        0,                                             /* FileStandardLinkInformation */
        0,                                             /* FileRemoteProtocolInformation */
        0,                                             /* FileRenameInformationBypassAccessCheck */
        0,                                             /* FileLinkInformationBypassAccessCheck */
        0,                                             /* FileVolumeNameInformation */
        sizeof(FILE_ID_INFORMATION),                   /* FileIdInformation */
        0,                                             /* FileIdExtdDirectoryInformation */
        0,                                             /* FileReplaceCompletionInformation */
        0,                                             /* FileHardLinkFullIdInformation */
        0,                                             /* FileIdExtdBothDirectoryInformation */
        0,                                             /* FileDispositionInformationEx */
        0,                                             /* FileRenameInformationEx */
        0,                                             /* FileRenameInformationExBypassAccessCheck */
        0,                                             /* FileDesiredStorageClassInformation */
        sizeof(FILE_STAT_INFORMATION),                 /* FileStatInformation */
        0,                                             /* FileMemoryPartitionInformation */
        0,                                             /* FileStatLxInformation */
        0,                                             /* FileCaseSensitiveInformation */
        0,                                             /* FileLinkInformationEx */
        0,                                             /* FileLinkInformationExBypassAccessCheck */
        0,                                             /* FileStorageReserveIdInformation */
        0,                                             /* FileCaseSensitiveInformationForceAccessCheck */
        0,                                             /* FileKnownFolderInformation */
    };

    struct stat st;
    int fd, needs_close = FALSE;
    ULONG attr;
    unsigned int reparse_tag;
    unsigned int options;
    unsigned int status;

    TRACE( "(%p,%p,%p,0x%08x,0x%08x)\n", handle, io, ptr, len, class);

    io->Information = 0;

    if (class == WineFileUnixNameInformation)
        return server_get_file_info( handle, io, ptr, len, class );
    if (class <= 0 || class >= FileMaximumInformation)
        return io->Status = STATUS_INVALID_INFO_CLASS;
    if (!info_sizes[class])
        return server_get_file_info( handle, io, ptr, len, class );
    if (len < info_sizes[class])
        return io->Status = STATUS_INFO_LENGTH_MISMATCH;

    if ((status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, &options )))
    {
        if (status != STATUS_BAD_DEVICE_TYPE) return io->Status = status;
        return server_get_file_info( handle, io, ptr, len, class );
    }

    switch (class)
    {
    case FileBasicInformation:
        if (fd_get_file_info( handle, fd, options, &st, &attr, NULL ) == -1)
            status = errno_to_status( errno );
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
            status = STATUS_INVALID_INFO_CLASS;
        else
            fill_file_info( &st, attr, ptr, class );
        break;
    case FileStandardInformation:
        {
            FILE_STANDARD_INFORMATION *info = ptr;

            if (fd_get_file_info( handle, fd, options, &st, &attr, NULL ) == -1)
                status = errno_to_status( errno );
            else
            {
                fill_file_info( &st, attr, info, class );
                info->DeletePending = FALSE; /* FIXME */
            }
        }
        break;
    case FilePositionInformation:
        {
            FILE_POSITION_INFORMATION *info = ptr;
            off_t res = lseek( fd, 0, SEEK_CUR );
            if (res == (off_t)-1) status = errno_to_status( errno );
            else info->CurrentByteOffset.QuadPart = res;
        }
        break;
    case FileInternalInformation:
        if (fd_get_file_info( handle, fd, options, &st, &attr, NULL ) == -1)
            status = errno_to_status( errno );
        else
            fill_file_info( &st, attr, ptr, class );
        break;
    case FileEaInformation:
        {
            FILE_EA_INFORMATION *info = ptr;
            info->EaSize = 0;
        }
        break;
    case FileEndOfFileInformation:
        if (fd_get_file_info( handle, fd, options, &st, &attr, NULL ) == -1)
            status = errno_to_status( errno );
        else
            fill_file_info( &st, attr, ptr, class );
        break;
    case FileAllInformation:
        {
            FILE_ALL_INFORMATION *info = ptr;

            if (fd_get_file_info( handle, fd, options, &st, &attr, NULL ) == -1)
                status = errno_to_status( errno );
            else
            {
                LONG name_len = len - FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation.FileName);

                fill_file_info( &st, attr, info, FileAllInformation );
                info->StandardInformation.DeletePending = FALSE; /* FIXME */
                info->EaInformation.EaSize = 0;
                info->AccessInformation.AccessFlags = 0;  /* FIXME */
                info->PositionInformation.CurrentByteOffset.QuadPart = lseek( fd, 0, SEEK_CUR );
                info->ModeInformation.Mode = 0;  /* FIXME */
                info->AlignmentInformation.AlignmentRequirement = 1;  /* FIXME */
                status = server_get_name_info( handle, &info->NameInformation, &name_len );
                io->Information = FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation.FileName) + name_len;
            }
        }
        break;
    case FileNameInformation:
        {
            LONG name_len = len - FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
            status = server_get_name_info( handle, ptr, &name_len );
            io->Information = offsetof( FILE_NAME_INFORMATION, FileName ) + name_len;
        }
        break;
    case FileNetworkOpenInformation:
        if (fd_get_file_info( handle, fd, options, &st, &attr, NULL ) == -1)
            status = errno_to_status( errno );
        else
            fill_file_info( &st, attr, ptr, FileNetworkOpenInformation );
        break;
    case FileIdInformation:
        if (fd_get_file_info( handle, fd, options, &st, &attr, NULL ) == -1)
            status = errno_to_status( errno );
        else
        {
            struct mountmgr_unix_drive drive;
            FILE_ID_INFORMATION *info = ptr;

            /* iOS-Madeira ml1030: same fallback as FileFsVolumeInformation — with
             * no mount manager this used to report serial 0 for every file, and
             * 0 is the value callers read as "no volume". */
            if (!get_mountmgr_fs_info( handle, fd, &drive, sizeof(drive) ))
                info->VolumeSerialNumber = drive.serial;
            else
                info->VolumeSerialNumber = get_volume_serial_fallback( fd, drive.letter );
            memset( &info->FileId, 0, sizeof(info->FileId) );
            *(ULONGLONG *)&info->FileId = st.st_ino;
        }
        break;
    case FileAttributeTagInformation:
        if (fd_get_file_info( handle, fd, options, &st, &attr, &reparse_tag ) == -1)
            status = errno_to_status( errno );
        else
        {
            FILE_ATTRIBUTE_TAG_INFORMATION *info = ptr;
            info->FileAttributes = attr;
            info->ReparseTag = reparse_tag;
        }
        break;
    case FileStatInformation:
        if (fd_get_file_info( handle, fd, options, &st, &attr, &reparse_tag ) == -1)
            status = errno_to_status( errno );
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
            status = STATUS_INVALID_INFO_CLASS;
        else
        {
            FILE_STAT_INFORMATION *info = ptr;
            FILE_BASIC_INFORMATION basic;
            FILE_STANDARD_INFORMATION std;

            fill_file_info( &st, attr, &basic, FileBasicInformation );
            fill_file_info( &st, attr, &std, FileStandardInformation );

            info->FileId.QuadPart = st.st_ino;
            info->CreationTime   = basic.CreationTime;
            info->LastAccessTime = basic.LastAccessTime;
            info->LastWriteTime  = basic.LastWriteTime;
            info->ChangeTime     = basic.ChangeTime;
            info->AllocationSize = std.AllocationSize;
            info->EndOfFile      = std.EndOfFile;
            info->FileAttributes = attr;
            info->ReparseTag     = reparse_tag;
            info->NumberOfLinks  = std.NumberOfLinks;
            info->EffectiveAccess = FILE_ALL_ACCESS; /* FIXME */
        }
        break;
    default:
        FIXME("Unsupported class (%d)\n", class);
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }
    if (needs_close) close( fd );
    if (status == STATUS_SUCCESS && !io->Information) io->Information = info_sizes[class];
    return io->Status = status;
}
#ifdef WINE_IOS
#undef NtQueryInformationFile
NTSTATUS WINAPI NtQueryInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                        void *ptr, ULONG len, FILE_INFORMATION_CLASS class )
{
    unsigned long long t0 = ios_fs_now_us();
    NTSTATUS status = ios_inner_NtQueryInformationFile( handle, io, ptr, len, class );
    ios_fs_note( IOS_OP_QINFO, t0, ios_fs_now_us() );
    return status;
}
#endif


/******************************************************************************
 *              NtSetInformationFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                      void *ptr, ULONG len, FILE_INFORMATION_CLASS class )
{
    int fd, needs_close;
    unsigned int status = STATUS_SUCCESS;

    TRACE( "(%p,%p,%p,0x%08x,0x%08x)\n", handle, io, ptr, len, class );

    switch (class)
    {
    case FileBasicInformation:
        if (len >= sizeof(FILE_BASIC_INFORMATION))
        {
            const FILE_BASIC_INFORMATION *info = ptr;
            LARGE_INTEGER mtime, atime;
            char *unix_name;

            if ((status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, NULL )))
                return io->Status = status;

            if (server_get_unix_name( handle, &unix_name )) unix_name = NULL;

            mtime.QuadPart = info->LastWriteTime.QuadPart == -1 ? 0 : info->LastWriteTime.QuadPart;
            atime.QuadPart = info->LastAccessTime.QuadPart == -1 ? 0 : info->LastAccessTime.QuadPart;

            if (atime.QuadPart || mtime.QuadPart)
                status = set_file_times( fd, &mtime, &atime );

            if (status == STATUS_SUCCESS)
                status = fd_set_file_info( fd, info->FileAttributes,
                                           unix_name && is_hidden_file( unix_name ));

            if (needs_close) close( fd );
            free( unix_name );
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FilePositionInformation:
        if (len >= sizeof(FILE_POSITION_INFORMATION))
        {
            const FILE_POSITION_INFORMATION *info = ptr;

            if ((status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, NULL )))
                return io->Status = status;

            if (lseek( fd, info->CurrentByteOffset.QuadPart, SEEK_SET ) == (off_t)-1)
                status = errno_to_status( errno );

            if (needs_close) close( fd );
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FileEndOfFileInformation:
        if (len >= sizeof(FILE_END_OF_FILE_INFORMATION))
        {
            const FILE_END_OF_FILE_INFORMATION *info = ptr;

            SERVER_START_REQ( set_fd_eof_info )
            {
                req->handle   = wine_server_obj_handle( handle );
                req->eof      = info->EndOfFile.QuadPart;
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FilePipeInformation:
        if (len >= sizeof(FILE_PIPE_INFORMATION))
        {
            FILE_PIPE_INFORMATION *info = ptr;

            if ((info->CompletionMode | info->ReadMode) & ~1)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            SERVER_START_REQ( set_named_pipe_info )
            {
                req->handle = wine_server_obj_handle( handle );
                req->flags  = (info->CompletionMode ? NAMED_PIPE_NONBLOCKING_MODE    : 0) |
                              (info->ReadMode       ? NAMED_PIPE_MESSAGE_STREAM_READ : 0);
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FileMailslotSetInformation:
        {
            FILE_MAILSLOT_SET_INFORMATION *info = ptr;

            SERVER_START_REQ( set_mailslot_info )
            {
                req->handle = wine_server_obj_handle( handle );
                req->flags = MAILSLOT_SET_READ_TIMEOUT;
                req->read_timeout = info->ReadTimeout.QuadPart;
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        break;

    case FileCompletionInformation:
        if (len >= sizeof(FILE_COMPLETION_INFORMATION))
        {
            FILE_COMPLETION_INFORMATION *info = ptr;

            SERVER_START_REQ( set_completion_info )
            {
                req->handle   = wine_server_obj_handle( handle );
                req->chandle  = wine_server_obj_handle( info->CompletionPort );
                req->ckey     = info->CompletionKey;
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FileIoCompletionNotificationInformation:
        if (len >= sizeof(FILE_IO_COMPLETION_NOTIFICATION_INFORMATION))
        {
            FILE_IO_COMPLETION_NOTIFICATION_INFORMATION *info = ptr;

            if (info->Flags & FILE_SKIP_SET_USER_EVENT_ON_FAST_IO)
                FIXME( "FILE_SKIP_SET_USER_EVENT_ON_FAST_IO not supported\n" );

            SERVER_START_REQ( set_fd_completion_mode )
            {
                req->handle   = wine_server_obj_handle( handle );
                req->flags    = info->Flags;
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INFO_LENGTH_MISMATCH;
        break;

    case FileIoPriorityHintInformation:
        if (len >= sizeof(FILE_IO_PRIORITY_HINT_INFO))
        {
            FILE_IO_PRIORITY_HINT_INFO *info = ptr;
            if (info->PriorityHint < MaximumIoPriorityHintType)
                TRACE( "ignoring FileIoPriorityHintInformation %u\n", info->PriorityHint );
            else
                status = STATUS_INVALID_PARAMETER;
        }
        else status = STATUS_INFO_LENGTH_MISMATCH;
        break;

    case FileAllInformation:
        status = STATUS_INVALID_INFO_CLASS;
        break;

    case FileValidDataLengthInformation:
        if (len >= sizeof(FILE_VALID_DATA_LENGTH_INFORMATION))
        {
            struct stat st;
            const FILE_VALID_DATA_LENGTH_INFORMATION *info = ptr;

            if ((status = server_get_unix_fd( handle, FILE_WRITE_DATA, &fd, &needs_close, NULL, NULL )))
                return io->Status = status;

            if (fstat( fd, &st ) == -1) status = errno_to_status( errno );
            else if (info->ValidDataLength.QuadPart <= 0 || (off_t)info->ValidDataLength.QuadPart > st.st_size)
                status = STATUS_INVALID_PARAMETER;
            else
            {
#ifdef HAVE_POSIX_FALLOCATE
                int err;
                if ((err = posix_fallocate( fd, 0, (off_t)info->ValidDataLength.QuadPart )) != 0)
                {
                    if (err == EOPNOTSUPP) WARN( "posix_fallocate not supported on this filesystem\n" );
                    else status = errno_to_status( err );
                }
#else
                WARN( "setting valid data length not supported\n" );
#endif
            }
            if (needs_close) close( fd );
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FileDispositionInformation:
        if (len >= sizeof(FILE_DISPOSITION_INFORMATION))
        {
            FILE_DISPOSITION_INFORMATION *info = ptr;

            SERVER_START_REQ( set_fd_disp_info )
            {
                req->handle   = wine_server_obj_handle( handle );
                req->flags    = info->DoDeleteFile ? FILE_DISPOSITION_DELETE : FILE_DISPOSITION_DO_NOT_DELETE;
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FileDispositionInformationEx:
        if (len >= sizeof(FILE_DISPOSITION_INFORMATION_EX))
        {
            FILE_DISPOSITION_INFORMATION_EX *info = ptr;

            if (info->Flags & FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK)
                FIXME( "FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK not supported\n" );

            SERVER_START_REQ( set_fd_disp_info )
            {
                req->handle   = wine_server_obj_handle( handle );
                req->flags    = info->Flags;
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FileRenameInformation:
    case FileRenameInformationEx:
        if (len >= sizeof(FILE_RENAME_INFORMATION))
        {
            FILE_RENAME_INFORMATION *info = ptr;
            unsigned int flags;
            UNICODE_STRING name_str, nt_name;
            OBJECT_ATTRIBUTES attr;
            char *unix_name;

            if (class == FileRenameInformation)
                flags = info->ReplaceIfExists ? FILE_RENAME_REPLACE_IF_EXISTS : 0;
            else
                flags = info->Flags;

            if (flags & ~(FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_IGNORE_READONLY_ATTRIBUTE))
                FIXME( "unsupported flags: %#x\n", flags );

            name_str.Buffer = info->FileName;
            name_str.Length = info->FileNameLength;
            name_str.MaximumLength = info->FileNameLength + sizeof(WCHAR);
            InitializeObjectAttributes( &attr, &name_str, OBJ_CASE_INSENSITIVE, info->RootDirectory, NULL );
            status = get_nt_and_unix_names( &attr, &nt_name, &unix_name, FILE_OPEN_IF, TRUE );
            if (status == STATUS_SUCCESS || status == STATUS_NO_SUCH_FILE)
            {
                SERVER_START_REQ( set_fd_name_info )
                {
                    req->handle   = wine_server_obj_handle( handle );
                    req->rootdir  = wine_server_obj_handle( attr.RootDirectory );
                    req->namelen  = attr.ObjectName->Length;
                    req->link     = FALSE;
                    req->flags    = flags;
                    wine_server_add_data( req, attr.ObjectName->Buffer, attr.ObjectName->Length );
                    wine_server_add_data( req, unix_name, strlen(unix_name) );
                    status = wine_server_call( req );
                }
                SERVER_END_REQ;

#ifdef WINE_IOS
                /* ml915: the destination directory gained a name.  The source
                 * one lost one, but only the server knows which path that
                 * was; its mtime covers it. */
                if (!status) ios_dc_invalidate_path( unix_name );
#endif
            }
            free( unix_name );
            free( nt_name.Buffer );
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    case FileLinkInformation:
    case FileLinkInformationEx:
        if (len >= sizeof(FILE_LINK_INFORMATION))
        {
            FILE_LINK_INFORMATION *info = ptr;
            unsigned int flags;
            UNICODE_STRING name_str, nt_name;
            OBJECT_ATTRIBUTES attr;
            char *unix_name;

            if (class == FileLinkInformation)
                flags = info->ReplaceIfExists ? FILE_LINK_REPLACE_IF_EXISTS : 0;
            else
                flags = info->Flags;

            if (flags & ~(FILE_LINK_REPLACE_IF_EXISTS | FILE_LINK_IGNORE_READONLY_ATTRIBUTE))
                FIXME( "unsupported flags: %#x\n", flags );

            name_str.Buffer = info->FileName;
            name_str.Length = info->FileNameLength;
            name_str.MaximumLength = info->FileNameLength + sizeof(WCHAR);
            InitializeObjectAttributes( &attr, &name_str, OBJ_CASE_INSENSITIVE, info->RootDirectory, NULL );
            status = get_nt_and_unix_names( &attr, &nt_name, &unix_name, FILE_OPEN_IF, TRUE );
            if (status == STATUS_SUCCESS || status == STATUS_NO_SUCH_FILE)
            {
                SERVER_START_REQ( set_fd_name_info )
                {
                    req->handle   = wine_server_obj_handle( handle );
                    req->rootdir  = wine_server_obj_handle( attr.RootDirectory );
                    req->namelen  = attr.ObjectName->Length;
                    req->link     = TRUE;
                    req->flags    = flags;
                    wine_server_add_data( req, attr.ObjectName->Buffer, attr.ObjectName->Length );
                    wine_server_add_data( req, unix_name, strlen(unix_name) );
                    status  = wine_server_call( req );
                }
                SERVER_END_REQ;

#ifdef WINE_IOS
                if (!status) ios_dc_invalidate_path( unix_name );   /* ml915 */
#endif
            }
            free( unix_name );
            free( nt_name.Buffer );
        }
        else status = STATUS_INVALID_PARAMETER_3;
        break;

    default:
        FIXME("Unsupported class (%d)\n", class);
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }
    io->Information = 0;
    return io->Status = status;
}


/***********************************************************************
 *                  Asynchronous file I/O                              *
 */

struct async_fileio_read
{
    struct async_fileio io;
    char               *buffer;
    unsigned int        already;
    unsigned int        count;
    BOOL                avail_mode;
};

struct async_fileio_write
{
    struct async_fileio io;
    const char         *buffer;
    unsigned int        already;
    unsigned int        count;
};

struct async_fileio_read_changes
{
    struct async_fileio io;
    void               *buffer;
    ULONG               buffer_size;
    ULONG               data_size;
    char                data[1];
};

struct async_irp
{
    struct async_fileio io;
    void               *buffer;   /* buffer for output */
    ULONG               size;     /* size of buffer */
};

static struct async_fileio *fileio_freelist;

void release_fileio( struct async_fileio *io )
{
    for (;;)
    {
        struct async_fileio *next = fileio_freelist;
        io->next = next;
        if (InterlockedCompareExchangePointer( (void **)&fileio_freelist, io, next ) == next) return;
    }
}

struct async_fileio *alloc_fileio( DWORD size, async_callback_t callback, HANDLE handle )
{
    /* first free remaining previous fileinfos */
    struct async_fileio *io = InterlockedExchangePointer( (void **)&fileio_freelist, NULL );

    while (io)
    {
        struct async_fileio *next = io->next;
        free( io );
        io = next;
    }

    if ((io = malloc( size )))
    {
        io->callback = callback;
        io->handle   = handle;
    }
    return io;
}

/* callback for irp async I/O completion */
static BOOL irp_completion( void *user, ULONG_PTR *info, unsigned int *status )
{
    struct async_irp *async = user;

    if (*status == STATUS_ALERTED)
    {
        SERVER_START_REQ( get_async_result )
        {
            req->user_arg = wine_server_client_ptr( async );
            wine_server_set_reply( req, async->buffer, async->size );
            *status = virtual_locked_server_call( req );
        }
        SERVER_END_REQ;
    }
    release_fileio( &async->io );
    return TRUE;
}

static BOOL async_read_proc( void *user, ULONG_PTR *info, unsigned int *status )
{
    struct async_fileio_read *fileio = user;
    int fd, needs_close, result;

    switch (*status)
    {
    case STATUS_ALERTED: /* got some new data */
        /* check to see if the data is ready (non-blocking) */
        if ((*status = server_get_unix_fd( fileio->io.handle, FILE_READ_DATA, &fd,
                                          &needs_close, NULL, NULL )))
            break;

        result = virtual_locked_read(fd, &fileio->buffer[fileio->already], fileio->count-fileio->already);
        if (needs_close) close( fd );

        if (result < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
                return FALSE;

            /* check to see if the transfer is complete */
            *status = errno_to_status( errno );
        }
        else if (result == 0)
        {
            *status = fileio->already ? STATUS_SUCCESS : STATUS_PIPE_BROKEN;
        }
        else
        {
            fileio->already += result;

            if (fileio->already < fileio->count && !fileio->avail_mode)
                return FALSE;

            *status = STATUS_SUCCESS;
        }
        break;

    case STATUS_TIMEOUT:
    case STATUS_IO_TIMEOUT:
        if (fileio->already) *status = STATUS_SUCCESS;
        break;
    }

    *info = fileio->already;
    release_fileio( &fileio->io );
    return TRUE;
}

static BOOL async_write_proc( void *user, ULONG_PTR *info, unsigned int *status )
{
    struct async_fileio_write *fileio = user;
    int result, fd, needs_close;
    enum server_fd_type type;

    switch (*status)
    {
    case STATUS_ALERTED:
        /* write some data (non-blocking) */
        if ((*status = server_get_unix_fd( fileio->io.handle, FILE_WRITE_DATA, &fd,
                                          &needs_close, &type, NULL )))
            break;

        result = write( fd, &fileio->buffer[fileio->already], fileio->count - fileio->already );

        if (needs_close) close( fd );

        if (result < 0)
        {
            if (errno == EAGAIN || errno == EINTR) return FALSE;
            *status = errno_to_status( errno );
        }
        else
        {
            fileio->already += result;
            if (fileio->already < fileio->count) return FALSE;
            *status = STATUS_SUCCESS;
        }
        break;

    case STATUS_TIMEOUT:
    case STATUS_IO_TIMEOUT:
        if (fileio->already) *status = STATUS_SUCCESS;
        break;
    }

    *info = fileio->already;
    release_fileio( &fileio->io );
    return TRUE;
}

#ifdef WINE_IOS
/* A session contains native and WoW pseudo-processes at the same time.
 * The loader temporarily clears wow_peb while booting a child, and otherwise
 * leaves it pointing at the last WoW child. Neither value identifies this
 * caller's I/O ABI. The window registry is keyed by the calling TEB/PEB. */
extern ULONG_PTR ios_wow_base(void);
BOOL ios_in_wow64_call(void)
{
    static int enabled = -1;
    static unsigned int reported;
    int mode = __atomic_load_n( &enabled, __ATOMIC_RELAXED );
    BOOL legacy = is_win64 && is_wow64();
    BOOL owner = is_win64 && ios_wow_base() != 0;
    if (mode < 0)
    {
        const char *env = getenv( "MADEIRA_IO_STATUS_OWNER" );
        mode = !env || strcmp( env, "0" );
        __atomic_store_n( &enabled, mode, __ATOMIC_RELAXED );
    }
    if (owner != legacy && __atomic_load_n( &reported, __ATOMIC_RELAXED ) < 8 &&
        __atomic_fetch_add( &reported, 1, __ATOMIC_RELAXED ) < 8)
        dprintf( 2, "[io-status-owner] ml1300 owner32=%u session32=%u enabled=%u\n",
                 owner, legacy, !!mode );
    return mode ? owner : legacy;
}
#endif

static void set_sync_iosb( IO_STATUS_BLOCK *io, NTSTATUS status, ULONG_PTR info, unsigned int options )
{
    if (in_wow64_call() && !(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)))
    {
        IO_STATUS_BLOCK32 *io32 = io->Pointer;

        io32->Status = status;
        io32->Information = info;
    }
    else
    {
        io->Status = status;
        io->Information = info;
    }
}

/* do a read call through the server */
static unsigned int server_read_file( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                      IO_STATUS_BLOCK *io, void *buffer, ULONG size,
                                      LARGE_INTEGER *offset, ULONG *key )
{
    struct async_irp *async;
    unsigned int status;
    HANDLE wait_handle;
    ULONG options;

    if (!(async = (struct async_irp *)alloc_fileio( sizeof(*async), irp_completion, handle )))
        return STATUS_NO_MEMORY;

    async->buffer  = buffer;
    async->size    = size;

    SERVER_START_REQ( read )
    {
        req->async = server_async( handle, &async->io, event, apc, apc_context, iosb_client_ptr(io) );
        req->pos   = offset ? offset->QuadPart : 0;
        wine_server_set_reply( req, buffer, size );
        status = virtual_locked_server_call( req );
        wait_handle = wine_server_ptr_handle( reply->wait );
        options     = reply->options;
        if (wait_handle && status != STATUS_PENDING)
            set_sync_iosb( io, status, wine_server_reply_size( reply ), options );
    }
    SERVER_END_REQ;

    if (status != STATUS_PENDING) free( async );

    if (wait_handle) status = wait_async( wait_handle, (options & FILE_SYNCHRONOUS_IO_ALERT) );
    return status;
}

/* do a write call through the server */
static unsigned int server_write_file( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                       IO_STATUS_BLOCK *io, const void *buffer, ULONG size,
                                       LARGE_INTEGER *offset, ULONG *key )
{
    struct async_irp *async;
    unsigned int status;
    HANDLE wait_handle;
    ULONG options;

    if (!(async = (struct async_irp *)alloc_fileio( sizeof(*async), irp_completion, handle )))
        return STATUS_NO_MEMORY;

    async->buffer  = NULL;
    async->size    = 0;

    SERVER_START_REQ( write )
    {
        req->async = server_async( handle, &async->io, event, apc, apc_context, iosb_client_ptr(io) );
        req->pos   = offset ? offset->QuadPart : 0;
        wine_server_add_data( req, buffer, size );
        status = wine_server_call( req );
        wait_handle = wine_server_ptr_handle( reply->wait );
        options     = reply->options;
        if (wait_handle && status != STATUS_PENDING)
            set_sync_iosb( io, status, reply->size, options );
    }
    SERVER_END_REQ;

    if (status != STATUS_PENDING) free( async );

    if (wait_handle) status = wait_async( wait_handle, (options & FILE_SYNCHRONOUS_IO_ALERT) );
    return status;
}

/* do an ioctl call through the server */
static NTSTATUS server_ioctl_file( HANDLE handle, HANDLE event,
                                   PIO_APC_ROUTINE apc, PVOID apc_context,
                                   IO_STATUS_BLOCK *io, UINT code,
                                   const void *in_buffer, UINT in_size,
                                   PVOID out_buffer, UINT out_size )
{
    struct async_irp *async;
    unsigned int status;
    HANDLE wait_handle;
    ULONG options;

    if (!(async = (struct async_irp *)alloc_fileio( sizeof(*async), irp_completion, handle )))
        return STATUS_NO_MEMORY;
    async->buffer  = out_buffer;
    async->size    = out_size;

    SERVER_START_REQ( ioctl )
    {
        req->code        = code;
        req->async       = server_async( handle, &async->io, event, apc, apc_context, iosb_client_ptr(io) );
        wine_server_add_data( req, in_buffer, in_size );
        if ((code & 3) != METHOD_BUFFERED) wine_server_add_data( req, out_buffer, out_size );
        wine_server_set_reply( req, out_buffer, out_size );
        status = virtual_locked_server_call( req );
        wait_handle = wine_server_ptr_handle( reply->wait );
        options     = reply->options;
        if (wait_handle && status != STATUS_PENDING)
            set_sync_iosb( io, status, wine_server_reply_size( reply ), options );
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_SUPPORTED)
        WARN("Unsupported ioctl %x (device=%x access=%x func=%x method=%x)\n",
             code, code >> 16, (code >> 14) & 3, (code >> 2) & 0xfff, code & 3);

    if (status != STATUS_PENDING) free( async );

    if (wait_handle) status = wait_async( wait_handle, (options & FILE_SYNCHRONOUS_IO_ALERT) );
    return status;
}


struct io_timeouts
{
    int interval;   /* max interval between two bytes */
    int total;      /* total timeout for the whole operation */
    int end_time;   /* absolute time of end of operation */
};

/* retrieve the I/O timeouts to use for a given handle */
static unsigned int get_io_timeouts( HANDLE handle, enum server_fd_type type, ULONG count, BOOL is_read,
                                     struct io_timeouts *timeouts )
{
    timeouts->interval = timeouts->total = -1;

    switch(type)
    {
    case FD_TYPE_SERIAL:
    {
        /* GetCommTimeouts */
        SERIAL_TIMEOUTS st;

        if (sync_ioctl( handle, IOCTL_SERIAL_GET_TIMEOUTS, NULL, 0, &st, sizeof(st) ))
            break;

        if (is_read)
        {
            if (st.ReadIntervalTimeout)
                timeouts->interval = st.ReadIntervalTimeout;

            if (st.ReadTotalTimeoutMultiplier || st.ReadTotalTimeoutConstant)
            {
                timeouts->total = st.ReadTotalTimeoutConstant;
                if (st.ReadTotalTimeoutMultiplier != MAXDWORD)
                    timeouts->total += count * st.ReadTotalTimeoutMultiplier;
            }
            else if (st.ReadIntervalTimeout == MAXDWORD)
                timeouts->interval = timeouts->total = 0;
        }
        else  /* write */
        {
            if (st.WriteTotalTimeoutMultiplier || st.WriteTotalTimeoutConstant)
            {
                timeouts->total = st.WriteTotalTimeoutConstant;
                if (st.WriteTotalTimeoutMultiplier != MAXDWORD)
                    timeouts->total += count * st.WriteTotalTimeoutMultiplier;
            }
        }
        break;
    }
    case FD_TYPE_SOCKET:
    case FD_TYPE_CHAR:
        if (is_read) timeouts->interval = 0;  /* return as soon as we got something */
        break;
    default:
        break;
    }
    if (timeouts->total != -1) timeouts->end_time = NtGetTickCount() + timeouts->total;
    return STATUS_SUCCESS;
}


/* retrieve the timeout for the next wait, in milliseconds */
static inline int get_next_io_timeout( const struct io_timeouts *timeouts, ULONG already )
{
    int ret = -1;

    if (timeouts->total != -1)
    {
        ret = timeouts->end_time - NtGetTickCount();
        if (ret < 0) ret = 0;
    }
    if (already && timeouts->interval != -1)
    {
        if (ret == -1 || ret > timeouts->interval) ret = timeouts->interval;
    }
    return ret;
}


/* retrieve the avail_mode flag for async reads */
static NTSTATUS get_io_avail_mode( HANDLE handle, enum server_fd_type type, BOOL *avail_mode )
{
    NTSTATUS status = STATUS_SUCCESS;

    switch(type)
    {
    case FD_TYPE_SERIAL:
    {
        /* GetCommTimeouts */
        SERIAL_TIMEOUTS st;

        if (!(status = sync_ioctl( handle, IOCTL_SERIAL_GET_TIMEOUTS, NULL, 0, &st, sizeof(st) )))
        {
            *avail_mode = (!st.ReadTotalTimeoutMultiplier &&
                           !st.ReadTotalTimeoutConstant &&
                           st.ReadIntervalTimeout == MAXDWORD);
        }
        break;
    }
    case FD_TYPE_SOCKET:
    case FD_TYPE_CHAR:
        *avail_mode = TRUE;
        break;
    default:
        *avail_mode = FALSE;
        break;
    }
    return status;
}

/* register an async I/O for a file read; helper for NtReadFile */
static unsigned int register_async_file_read( HANDLE handle, HANDLE event,
                                              PIO_APC_ROUTINE apc, void *apc_user,
                                              client_ptr_t iosb, void *buffer,
                                              ULONG already, ULONG length, BOOL avail_mode )
{
    struct async_fileio_read *fileio;
    unsigned int status;

    if (!(fileio = (struct async_fileio_read *)alloc_fileio( sizeof(*fileio), async_read_proc, handle )))
        return STATUS_NO_MEMORY;

    fileio->already = already;
    fileio->count = length;
    fileio->buffer = buffer;
    fileio->avail_mode = avail_mode;

    SERVER_START_REQ( register_async )
    {
        req->type   = ASYNC_TYPE_READ;
        req->count  = length;
        req->async  = server_async( handle, &fileio->io, event, apc, apc_user, iosb );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    if (status != STATUS_PENDING) free( fileio );
    return status;
}

static void add_completion( HANDLE handle, ULONG_PTR value, NTSTATUS status, ULONG info, BOOL async )
{
    SERVER_START_REQ( add_fd_completion )
    {
        req->handle      = wine_server_obj_handle( handle );
        req->cvalue      = value;
        req->status      = status;
        req->information = info;
        req->async       = async;
        wine_server_call( req );
    }
    SERVER_END_REQ;
}

/* notify direct completion of async and close the wait handle if it is no longer needed */
void set_async_direct_result( HANDLE *async_handle, unsigned int options, IO_STATUS_BLOCK *io,
                              NTSTATUS status, ULONG_PTR information, BOOL mark_pending )
{
    unsigned int ret;

    /* if we got STATUS_ALERTED, we must have a valid async handle */
    assert( *async_handle );

    if (!NT_ERROR(status) && status != STATUS_PENDING)
        set_sync_iosb( io, status, information, options );

    SERVER_START_REQ( set_async_direct_result )
    {
        req->handle       = wine_server_obj_handle( *async_handle );
        req->status       = status;
        req->information  = information;
        req->mark_pending = mark_pending;
        ret = wine_server_call( req );
        if (ret == STATUS_SUCCESS)
            *async_handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    if (ret != STATUS_SUCCESS)
        ERR( "cannot report I/O result back to server: %#x\n", ret );
}

/* complete async file I/O, signaling completion in all ways necessary */
void file_complete_async( HANDLE handle, unsigned int options, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                          IO_STATUS_BLOCK *io, NTSTATUS status, ULONG_PTR information )
{
    ULONG_PTR iosb_ptr = iosb_client_ptr(io);

    set_sync_iosb( io, status, information, options );
    if (event) NtSetEvent( event, NULL );
    if (apc)
        NtQueueApcThread( GetCurrentThread(), (PNTAPCFUNC)apc, (ULONG_PTR)apc_user, iosb_ptr, 0 );
    else if (apc_user && !(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)))
        add_completion( handle, (ULONG_PTR)apc_user, status, information, FALSE );
}


static unsigned int set_pending_write( HANDLE device )
{
    unsigned int status;

    SERVER_START_REQ( set_serial_info )
    {
        req->handle = wine_server_obj_handle( device );
        req->flags  = SERIALINFO_PENDING_WRITE;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/******************************************************************************
 *              NtReadFile   (NTDLL.@)
 */
#ifdef WINE_IOS
/* iOS-Madeira ml487 (#78): the steamloopback JS-boot lottery. Roughly half of all
 * runs die because Steam's UI JavaScript arrives corrupt — `SyntaxError:
 * Invalid or unexpected token` in library.js (whole run lost, no dial, no retry
 * path), or a partial hit where a lazily-loaded chunk fails (`ChunkLoadError:
 * Loading chunk 2664 failed`) and the login form renders with NO TEXT. The
 * files on disk are provably clean (node --check, 0 NULs), so the corruption
 * happens somewhere between the file and V8.
 *
 * This instruments the ONE boundary we own: the bytes NtReadFile hands back.
 * Every read of a steamui *.js file logs offset/length/result, an FNV-1a
 * checksum of the returned bytes, and the head/tail bytes (head/tail catch an
 * offset skew, which is the shape a webpack 'NNNNN:' token error implies).
 *
 * Reading the result: re-read the same file offline, compute the same checksum
 * per range, and compare. Checksums MATCH  => our read path is honest and the
 * corruption is downstream (scheme handler -> mojo pipe -> V8). Checksums
 * DIFFER, or head/tail are shifted => the defect is ours and this names the
 * exact offset. Either way the coin-flip becomes an address. */
/* ml488 CORRECTION: keying purely on HANDLE was WRONG — Windows recycles handle
 * numbers, so after a tracked .js was closed its handle value was reused for a
 * Chromium SQLite db and every read of THAT file was logged as library.js. The
 * ml487 run produced 8 such lines (head=53514c69 = "SQLi", plus off=24 len=16
 * header-field reads) and the verifier duly called them corruption. They were
 * not. Identity is now (dev, ino), captured by stat() at open and re-checked
 * with fstat() on the unix fd at read time, so a recycled handle can never be
 * mistaken for the file we meant to watch. */
#define IOS_JSTRACK_MAX 64
/* ml530 (#78): + the fields needed to arm srcwatch on the ASSEMBLED buffer.
 * Arming on a single read is useless — Steam reads this file in ~31 chunks, so
 * the first chunk's buffer is either refilled (noise) or only covers 1/31 of the
 * source. What we want is the whole thing, once the last byte has landed. */
static struct { HANDLE handle; dev_t dev; ino_t ino; char name[40];
                off_t size, got; uintptr_t lo, hi, last_end;
                int gaps, armed; } ios_js_track[IOS_JSTRACK_MAX];
static unsigned int ios_js_track_n;
static int ios_js_track_any;
static pthread_mutex_t ios_js_track_lock = PTHREAD_MUTEX_INITIALIZER;

static void ios_js_track_add( HANDLE handle, const char *unix_name )
{
    const char *base, *dot;
    struct stat st;

    if (!unix_name || !handle) return;
    if (!strstr( unix_name, "steamui" )) return;
    dot = strrchr( unix_name, '.' );
    if (!dot || strcmp( dot, ".js" )) return;
    if (stat( unix_name, &st ) == -1) return;

    base = strrchr( unix_name, '/' );
    base = base ? base + 1 : unix_name;

    pthread_mutex_lock( &ios_js_track_lock );
    if (ios_js_track_n < IOS_JSTRACK_MAX)
    {
        unsigned int i = ios_js_track_n;
        ios_js_track[i].handle = handle;
        ios_js_track[i].dev = st.st_dev;
        ios_js_track[i].ino = st.st_ino;
        ios_js_track[i].size = st.st_size;
        ios_js_track[i].got = 0;
        ios_js_track[i].gaps = 0;
        ios_js_track[i].armed = 0;
        snprintf( ios_js_track[i].name, sizeof(ios_js_track[i].name), "%s", base );
        ios_js_track_n = i + 1;
        ios_js_track_any = 1;
        dprintf( 2, "[js-open] %s handle=%p ino=%llu size=%llu rev=ml488\n", ios_js_track[i].name,
                 handle, (unsigned long long)st.st_ino, (unsigned long long)st.st_size );
    }
    pthread_mutex_unlock( &ios_js_track_lock );
}

/* Returns the tracked name only when the fd STILL refers to the same file. */
static int ios_js_track_find( HANDLE handle, int unix_fd )
{
    struct stat st;
    unsigned int i;

    if (!ios_js_track_any) return -1;   /* fast path: costs one load per read */
    for (i = 0; i < ios_js_track_n; i++)
    {
        if (ios_js_track[i].handle != handle) continue;
        if (unix_fd < 0 || fstat( unix_fd, &st ) == -1) return -1;
        if (st.st_dev != ios_js_track[i].dev || st.st_ino != ios_js_track[i].ino)
        {
            static int recycled_logged;
            if (recycled_logged < 8)
            {
                recycled_logged++;
                dprintf( 2, "[js-recycle] handle=%p was %s, now ino=%llu — not logging (rev=ml488)\n",
                         handle, ios_js_track[i].name, (unsigned long long)st.st_ino );
            }
            return -1;
        }
        return (int)i;
    }
    return -1;
}

static void ios_js_read_note( HANDLE handle, int unix_fd, const void *buffer, ULONG want, UINT got,
                              const LARGE_INTEGER *offset )
{
    static int reads_logged;
    const unsigned char *p = buffer;
    const char *name;
    unsigned int sum = 2166136261u;
    UINT i;
    int idx;

    if (!got) return;
    if ((idx = ios_js_track_find( handle, unix_fd )) < 0) return;
    name = ios_js_track[idx].name;

    /* ml530 (#78): accumulate this file's reads and, once the last byte has
     * landed, write-protect the assembled buffer so the next writer to it
     * identifies itself. Our reads deliver this file byte-perfect (ml489:
     * 73/73 MATCH, the failing file 100% verified) yet V8 reports
     * `SyntaxError: Invalid or unexpected token` on it — so the damage happens
     * after the read, and any write here is the corrupter.
     *
     * Only arm on a genuinely CONTIGUOUS assembly (gaps==0 and span==size):
     * if Steam read into a reused chunk buffer, lo..hi would be a small window
     * that later reads legitimately rewrite, and every fault would be noise. */
    {
        uintptr_t b0 = (uintptr_t)buffer, b1 = b0 + got;
        if (!ios_js_track[idx].got) { ios_js_track[idx].lo = b0; ios_js_track[idx].hi = b1; }
        else
        {
            if (b0 < ios_js_track[idx].lo) ios_js_track[idx].lo = b0;
            if (b1 > ios_js_track[idx].hi) ios_js_track[idx].hi = b1;
            if (b0 != ios_js_track[idx].last_end) ios_js_track[idx].gaps++;
        }
        ios_js_track[idx].last_end = b1;
        ios_js_track[idx].got += got;

        if (!ios_js_track[idx].armed && ios_js_track[idx].size &&
            ios_js_track[idx].got >= ios_js_track[idx].size)
        {
            unsigned long long span = (unsigned long long)(ios_js_track[idx].hi - ios_js_track[idx].lo);
            ios_js_track[idx].armed = 1;
            if (!ios_js_track[idx].gaps && span == (unsigned long long)ios_js_track[idx].size)
            {
                extern void ios_srcwatch_arm_for( const void *bits, unsigned long len, const char *tag );
                dprintf( 2, "[js-watch] %s fully read (%llu B, contiguous at %p) — arming srcwatch rev=ml530\n",
                         name, span, (void *)ios_js_track[idx].lo );
                ios_srcwatch_arm_for( (const void *)ios_js_track[idx].lo, (unsigned long)span, "js" );
            }
            else
                dprintf( 2, "[js-watch] %s fully read but NOT contiguous (gaps=%d span=%llu size=%llu) "
                            "— chunk buffer reused, not arming rev=ml530\n",
                         name, ios_js_track[idx].gaps, span,
                         (unsigned long long)ios_js_track[idx].size );
        }
    }

    if (reads_logged >= 512) return;
    reads_logged++;

    for (i = 0; i < got; i++) { sum ^= p[i]; sum *= 16777619u; }

    dprintf( 2, "[js-read] %s off=%lld want=%u got=%u sum=%08x head=%02x%02x%02x%02x "
                "tail=%02x%02x%02x%02x rev=ml488\n",
             name, offset ? (long long)offset->QuadPart : -1LL, (unsigned)want, (unsigned)got, sum,
             p[0], got > 1 ? p[1] : 0, got > 2 ? p[2] : 0, got > 3 ? p[3] : 0,
             got >= 4 ? p[got-4] : 0, got >= 3 ? p[got-3] : 0,
             got >= 2 ? p[got-2] : 0, p[got-1] );
}
#endif

#ifdef WINE_IOS
#define NtReadFile ios_inner_NtReadFile
#endif
NTSTATUS WINAPI NtReadFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                            IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                            LARGE_INTEGER *offset, ULONG *key )
{
    int result, unix_handle, needs_close;
    unsigned int options;
    struct io_timeouts timeouts;
    unsigned int status, ret_status;
    UINT total = 0;
    client_ptr_t iosb_ptr = iosb_client_ptr(io);
    enum server_fd_type type;
    ULONG_PTR cvalue = apc ? 0 : (ULONG_PTR)apc_user;
    BOOL send_completion = FALSE, async_read, timeout_init_done = FALSE;
#ifdef WINE_IOS
    int ios_positioned = 0;
#endif

    TRACE( "(%p,%p,%p,%p,%p,%p,0x%08x,%p,%p)\n",
           handle, event, apc, apc_user, io, buffer, length, offset, key );

    if (!io) return STATUS_ACCESS_VIOLATION;

    status = server_get_unix_fd( handle, FILE_READ_DATA, &unix_handle, &needs_close, &type, &options );
    if (status && status != STATUS_BAD_DEVICE_TYPE) return status;

    if (!virtual_check_buffer_for_write( buffer, length )) return STATUS_ACCESS_VIOLATION;

#ifdef WINE_IOS
    /* ml955: WHAT IS THE ANTI-TAMPER BLOCKING READ ON?
     *
     * Measured: with the sub-floor work in place a game's protection layer sits
     * for the whole run in kernelbase!ReadFile+0xac at 0% CPU, called from its
     * own low-address code. Its spawned launcher is still alive, so this is not
     * a read on a dead peer's handle. The handle is the missing fact, and each
     * answer points somewhere different -- a socket implies online
     * authentication, a pipe implies launcher IPC, a plain file implies
     * something about the install.
     *
     * server_get_unix_fd above already returns the SERVER'S object type, so the
     * classification is free -- no extra round trip, no fstat.
     *
     * Keyed on the HANDLE, one line each, not a flat call cap: Wine performs
     * thousands of reads during startup and a flat budget is spent long before
     * the interesting handle appears. (That exact mistake cost a run earlier in
     * this investigation -- probe the value in question, not the call count.) */
    {
        static HANDLE ml955_seen[48];
        static int ml955_n;
        int ml955_i, ml955_dup = 0;

        for (ml955_i = 0; ml955_i < ml955_n; ml955_i++)
            if (ml955_seen[ml955_i] == handle) { ml955_dup = 1; break; }
        if (!ml955_dup && ml955_n < (int)(sizeof(ml955_seen)/sizeof(ml955_seen[0])))
        {
            /* ml955 fix: this table was invented, not read. enum server_fd_type
             * (include/wine/server_protocol.h) has no PIPE and no MAILSLOT --
             * it is INVALID, FILE, DIR, SOCKET, SERIAL, CHAR, DEVICE -- so the
             * old table reported CHAR as "PIPE" and DEVICE as "MAILSLOT".
             * Indexed by the enum constants so it cannot drift again. Note a
             * named pipe end reports FD_TYPE_DEVICE (server/named_pipe.c), and
             * an fd class names neither the peer nor any protocol. */
            static const char *ml955_types[FD_TYPE_NB_TYPES];
            ml955_types[FD_TYPE_INVALID] = "INVALID";
            ml955_types[FD_TYPE_FILE]    = "FILE";
            ml955_types[FD_TYPE_DIR]     = "DIR";
            ml955_types[FD_TYPE_SOCKET]  = "SOCKET";
            ml955_types[FD_TYPE_SERIAL]  = "SERIAL";
            ml955_types[FD_TYPE_CHAR]    = "CHAR";
            ml955_types[FD_TYPE_DEVICE]  = "DEVICE";
            ml955_seen[ml955_n++] = handle;
            ERR( "ml955 [read-src] #%d handle=%p type=%s(%d) options=%08x len=%u offset=%s%I64x async=%d\n",
                 ml955_n, handle,
                 ((int)type >= 0 && (int)type < FD_TYPE_NB_TYPES && ml955_types[(int)type])
                     ? ml955_types[(int)type] : "?",
                 (int)type, options, length,
                 offset ? "" : "(none) ", offset ? offset->QuadPart : 0,
                 !(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) );
        }
    }
#endif

    if (status == STATUS_BAD_DEVICE_TYPE)
    {
#ifdef WINE_IOS
        IOS_FSA( ios_fs_read_srv, 1 );      /* wineserver round trip for the data itself */
#endif
        return server_read_file( handle, event, apc, apc_user, io, buffer, length, offset, key );
    }

    async_read = !(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT));

    if (type == FD_TYPE_FILE)
    {
        if (async_read && (!offset || offset->QuadPart < 0))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }

        if (offset && offset->QuadPart != FILE_USE_FILE_POINTER_POSITION)
        {
            /* async I/O doesn't make sense on regular files */
            while ((result = virtual_locked_pread( unix_handle, buffer, length, offset->QuadPart )) == -1)
            {
                if (errno != EINTR)
                {
                    status = errno_to_status( errno );
                    goto done;
                }
            }
            if (!async_read) /* update file pointer position */
                lseek( unix_handle, offset->QuadPart + result, SEEK_SET );

#ifdef WINE_IOS
            /* ml910: the good path — one pread() straight off the cached
             * unix fd, no wineserver round trip.  The only fixed extra cost
             * is the lseek above, which a synchronous handle needs so that
             * FilePositionInformation and pointer-relative reads stay
             * correct; nothing here does a redundant fstat per read. */
            IOS_FSA( ios_fs_read_pos, 1 );
            ios_positioned = 1;
#endif
            total = result;
            status = (total || !length) ? STATUS_SUCCESS : STATUS_END_OF_FILE;
            goto done;
        }
    }
    else if (type == FD_TYPE_SERIAL || type == FD_TYPE_DEVICE)
    {
        if (async_read && (!offset || offset->QuadPart < 0))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
    }
    else if (type == FD_TYPE_SOCKET)
    {
        status = sock_read( handle, unix_handle, event, apc, apc_user, io, buffer, length );
        if (needs_close) close( unix_handle );
        return status;
    }

    if (type == FD_TYPE_SERIAL && async_read && length)
    {
        /* an asynchronous serial port read with a read interval timeout needs to
           skip the synchronous read to make sure that the server starts the read
           interval timer after the first read */
        if ((status = get_io_timeouts( handle, type, length, TRUE, &timeouts ))) goto err;
        if (timeouts.interval > 0)
        {
            status = register_async_file_read( handle, event, apc, apc_user, iosb_ptr,
                                               buffer, total, length, FALSE );
            goto err;
        }
    }

    for (;;)
    {
        if ((result = virtual_locked_read( unix_handle, (char *)buffer + total, length - total )) >= 0)
        {
            total += result;
            if (!result || total == length)
            {
                if (total)
                {
                    status = STATUS_SUCCESS;
                    goto done;
                }
                switch (type)
                {
                case FD_TYPE_FILE:
                case FD_TYPE_CHAR:
                case FD_TYPE_DEVICE:
                    status = length ? STATUS_END_OF_FILE : STATUS_SUCCESS;
                    goto done;
                case FD_TYPE_SERIAL:
                    if (!length)
                    {
                        status = STATUS_SUCCESS;
                        goto done;
                    }
                    break;
                default:
                    status = STATUS_PIPE_BROKEN;
                    goto err;
                }
            }
            else if (type == FD_TYPE_FILE) continue;  /* no async I/O on regular files */
        }
        else if (errno != EAGAIN)
        {
            if (errno == EINTR) continue;
            if (!total) status = errno_to_status( errno );
            goto err;
        }

        if (async_read)
        {
            BOOL avail_mode;

            if ((status = get_io_avail_mode( handle, type, &avail_mode ))) goto err;
            if (total && avail_mode)
            {
                status = STATUS_SUCCESS;
                goto done;
            }
            status = register_async_file_read( handle, event, apc, apc_user, iosb_ptr,
                                               buffer, total, length, avail_mode );
            goto err;
        }
        else  /* synchronous read, wait for the fd to become ready */
        {
            struct pollfd pfd;
            int ret, timeout;

            if (!timeout_init_done)
            {
                timeout_init_done = TRUE;
                if ((status = get_io_timeouts( handle, type, length, TRUE, &timeouts ))) goto err;
                if (event) NtResetEvent( event, NULL );
            }
            timeout = get_next_io_timeout( &timeouts, total );

            pfd.fd = unix_handle;
            pfd.events = POLLIN;

            if (!timeout || !(ret = poll( &pfd, 1, timeout )))
            {
                if (total)  /* return with what we got so far */
                    status = STATUS_SUCCESS;
                else
                    status = STATUS_TIMEOUT;
                goto done;
            }
            if (ret == -1 && errno != EINTR)
            {
                status = errno_to_status( errno );
                goto done;
            }
            /* will now restart the read */
        }
    }

done:
#ifdef WINE_IOS
    /* ml487 (#78): single choke point — every read path above reaches here. */
    if (status == STATUS_SUCCESS && total)
        ios_js_read_note( handle, unix_handle, buffer, length, total, offset );
    ios_video_read_note( handle, status, total, offset );
    IOS_FSA( ios_fs_read_bytes, total );
    if (!ios_positioned) IOS_FSA( ios_fs_read_sync, 1 );
#endif
    send_completion = cvalue != 0;

err:
    if (needs_close) close( unix_handle );
    if (status == STATUS_SUCCESS || (status == STATUS_END_OF_FILE && (!async_read || type == FD_TYPE_FILE)))
    {
        set_sync_iosb( io, status, total, options );
        TRACE("= SUCCESS (%u)\n", total);
        if (event) NtSetEvent( event, NULL );
        if (apc && (!status || async_read)) NtQueueApcThread( GetCurrentThread(), (PNTAPCFUNC)apc,
                                                              (ULONG_PTR)apc_user, iosb_ptr, 0 );
    }
    else
    {
        TRACE("= 0x%08x\n", status);
        if (status != STATUS_PENDING && event) NtResetEvent( event, NULL );
    }

    ret_status = async_read && type == FD_TYPE_FILE && (status == STATUS_SUCCESS || status == STATUS_END_OF_FILE)
            ? STATUS_PENDING : status;

    if (send_completion && async_read)
        add_completion( handle, cvalue, status, total, ret_status == STATUS_PENDING );
    return ret_status;
}
#ifdef WINE_IOS
#undef NtReadFile
NTSTATUS WINAPI NtReadFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                            IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                            LARGE_INTEGER *offset, ULONG *key )
{
    unsigned long long t0 = ios_fs_now_us();
    NTSTATUS status = ios_inner_NtReadFile( handle, event, apc, apc_user, io, buffer, length, offset, key );
    ios_fs_note( IOS_OP_READ, t0, ios_fs_now_us() );
    return status;
}
#endif


/******************************************************************************
 *              NtReadFileScatter   (NTDLL.@)
 */
NTSTATUS WINAPI NtReadFileScatter( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                   IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments,
                                   ULONG length, LARGE_INTEGER *offset, ULONG *key )
{
    int result, unix_handle, needs_close;
    unsigned int options, status;
    UINT pos = 0, total = 0;
    client_ptr_t iosb_ptr = iosb_client_ptr(io);
    enum server_fd_type type;
    ULONG_PTR cvalue = apc ? 0 : (ULONG_PTR)apc_user;
    BOOL send_completion = FALSE;

    TRACE( "(%p,%p,%p,%p,%p,%p,0x%08x,%p,%p),partial stub!\n",
           file, event, apc, apc_user, io, segments, length, offset, key );

    if (!io) return STATUS_ACCESS_VIOLATION;

    status = server_get_unix_fd( file, FILE_READ_DATA, &unix_handle, &needs_close, &type, &options );
    if (status) return status;

    if ((type != FD_TYPE_FILE) ||
        (options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) ||
        !(options & FILE_NO_INTERMEDIATE_BUFFERING))
    {
        status = STATUS_INVALID_PARAMETER;
        goto error;
    }

    while (length)
    {
        if (offset && offset->QuadPart != FILE_USE_FILE_POINTER_POSITION)
            result = pread( unix_handle, (char *)segments->Buffer + pos,
                            min( length - pos, page_size - pos ), offset->QuadPart + total );
        else
            result = read( unix_handle, (char *)segments->Buffer + pos, min( length - pos, page_size - pos ) );

        if (result == -1)
        {
            if (errno == EINTR) continue;
            status = errno_to_status( errno );
            break;
        }
        if (!result) break;
        total += result;
        length -= result;
        if ((pos += result) == page_size)
        {
            pos = 0;
            segments++;
        }
    }

    if (total == 0) status = STATUS_END_OF_FILE;

    send_completion = cvalue != 0;

    if (needs_close) close( unix_handle );
    set_sync_iosb( io, status, total, options );
    TRACE("= 0x%08x (%u)\n", status, total);
    if (event) NtSetEvent( event, NULL );
    if (apc) NtQueueApcThread( GetCurrentThread(), (PNTAPCFUNC)apc, (ULONG_PTR)apc_user, iosb_ptr, 0 );
    if (send_completion) add_completion( file, cvalue, status, total, TRUE );

    return STATUS_PENDING;

error:
    if (needs_close) close( unix_handle );
    if (event) NtResetEvent( event, NULL );
    TRACE("= 0x%08x\n", status);
    return status;
}


#ifdef WINE_IOS
/* ml1180: a managed program may catch its exception and keep presenting a
 * loading screen forever. Its text log then has the failure, while our SEH
 * log only has a handled null dereference. Mirror a bounded error excerpt
 * from successful regular-file writes, without changing guest I/O results.
 * No filename lookup for ordinary binary writes; no scans of the prefix.
 * A fixed app-lifetime budget and consecutive dedup keep this low volume. */
static void ios_guest_log_error( int fd, const void *buffer, unsigned int length )
{
    static int enabled = -1, reported;
    static unsigned int emitted;
    static unsigned long long previous_hash;
    char text[1025], lower[1025], path[PATH_MAX];
    const char *name, *ext;
    unsigned int i, n, serial;
    unsigned long long hash = 14695981039346656037ULL;
    int mode = __atomic_load_n( &enabled, __ATOMIC_RELAXED );
    int saved_errno = errno;

    if (mode < 0)
    {
        const char *env = getenv( "MADEIRA_GUEST_LOG_ERRORS" );
        mode = !env || strcmp( env, "0" );
        __atomic_store_n( &enabled, mode, __ATOMIC_RELAXED );
    }
    if (!__atomic_exchange_n( &reported, 1, __ATOMIC_RELAXED ))
        dprintf( 2, "[guest-log] ml1300 text-log support; error excerpts=%d limit=32 (MADEIRA_GUEST_LOG_ERRORS=0 disables)\n", !!mode );
    if (!mode || length < 5) goto out;
    if (__atomic_load_n( &emitted, __ATOMIC_RELAXED ) >= 32) goto out;
    n = min( length, sizeof(text) - 1 );
    for (i = 0; i < n; ++i)
    {
        unsigned char c = ((const unsigned char *)buffer)[i];
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') goto out;
        text[i] = c < 32 ? ' ' : c;
        lower[i] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
        hash = (hash ^ c) * 1099511628211ULL;
    }
    text[n] = lower[n] = 0;
    if (!strstr( lower, "exception" ) && !strstr( lower, "error" ) &&
        !strstr( lower, "failed" ) && !strstr( lower, "unsupported" )) goto out;
    if (fcntl( fd, F_GETPATH, path ) == -1) goto out;
    name = strrchr( path, '/' );
    name = name ? name + 1 : path;
    ext = strrchr( name, '.' );
    /* only *.log and output_log.txt; never scan arbitrary text files */
    if ((!ext || strcasecmp( ext, ".log" )) && strcasecmp( name, "output_log.txt" )) goto out;
    if (__atomic_exchange_n( &previous_hash, hash, __ATOMIC_RELAXED ) == hash) goto out;
    serial = __atomic_fetch_add( &emitted, 1, __ATOMIC_RELAXED );
    if (serial < 32)
        dprintf( 2, "[guest-log] ml1180 #%u tid=%04x bytes=%u excerpt=%s%s\n", serial + 1,
                 GetCurrentThreadId(), length, text, length > n ? " [truncated]" : "" );
out:
    errno = saved_errno;
}
#endif

/******************************************************************************
 *              NtWriteFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                             IO_STATUS_BLOCK *io, const void *buffer, ULONG length,
                             LARGE_INTEGER *offset, ULONG *key )
{
    int result, unix_handle, needs_close;
    unsigned int options;
    struct io_timeouts timeouts;
    unsigned int status, ret_status;
    UINT total = 0;
    client_ptr_t iosb_ptr = iosb_client_ptr(io);
    enum server_fd_type type;
    ULONG_PTR cvalue = apc ? 0 : (ULONG_PTR)apc_user;
    BOOL send_completion = FALSE, async_write, append_write = FALSE, timeout_init_done = FALSE;
    LARGE_INTEGER offset_eof;

    TRACE( "(%p,%p,%p,%p,%p,%p,0x%08x,%p,%p)\n",
           handle, event, apc, apc_user, io, buffer, length, offset, key );

    if (!io) return STATUS_ACCESS_VIOLATION;

    status = server_get_unix_fd( handle, FILE_WRITE_DATA, &unix_handle, &needs_close, &type, &options );
    if (status == STATUS_ACCESS_DENIED)
    {
        status = server_get_unix_fd( handle, FILE_APPEND_DATA, &unix_handle,
                                     &needs_close, &type, &options );
        append_write = TRUE;
    }
    if (status && status != STATUS_BAD_DEVICE_TYPE) return status;

    async_write = !(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT));

    if (!virtual_check_buffer_for_read( buffer, length ))
    {
        status = STATUS_INVALID_USER_BUFFER;
        goto done;
    }

    if (status == STATUS_BAD_DEVICE_TYPE)
        return server_write_file( handle, event, apc, apc_user, io, buffer, length, offset, key );

    if (type == FD_TYPE_FILE)
    {
        if (async_write &&
            (!offset || (offset->QuadPart < 0 && offset->QuadPart != FILE_WRITE_TO_END_OF_FILE)))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }

        if (append_write)
        {
            offset_eof.QuadPart = FILE_WRITE_TO_END_OF_FILE;
            offset = &offset_eof;
        }

        if (offset && offset->QuadPart != FILE_USE_FILE_POINTER_POSITION)
        {
            off_t off = offset->QuadPart;

            if (offset->QuadPart == FILE_WRITE_TO_END_OF_FILE)
            {
                struct stat st;

                if (fstat( unix_handle, &st ) == -1)
                {
                    status = errno_to_status( errno );
                    goto done;
                }
                off = st.st_size;
            }
            else if (offset->QuadPart < 0)
            {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }

            /* async I/O doesn't make sense on regular files */
            while ((result = pwrite( unix_handle, buffer, length, off )) == -1)
            {
                if (errno != EINTR)
                {
                    if (errno == EFAULT) status = STATUS_INVALID_USER_BUFFER;
                    else status = errno_to_status( errno );
                    goto done;
                }
            }

            if (!async_write) /* update file pointer position */
                lseek( unix_handle, off + result, SEEK_SET );

            total = result;
            status = STATUS_SUCCESS;
            goto done;
        }
    }
    else if (type == FD_TYPE_SERIAL || type == FD_TYPE_DEVICE)
    {
        if (async_write &&
            (!offset || (offset->QuadPart < 0 && offset->QuadPart != FILE_WRITE_TO_END_OF_FILE)))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
    }
    else if (type == FD_TYPE_SOCKET)
    {
        status = sock_write( handle, unix_handle, event, apc, apc_user, io, buffer, length );
        if (needs_close) close( unix_handle );
        return status;
    }

    for (;;)
    {
        result = write( unix_handle, (const char *)buffer + total, length - total );

        if (result >= 0)
        {
            total += result;
            if (total == length)
            {
                status = STATUS_SUCCESS;
                goto done;
            }
            if (type == FD_TYPE_FILE) continue;  /* no async I/O on regular files */
        }
        else if (errno != EAGAIN)
        {
            if (errno == EINTR) continue;
            if (!total)
            {
                if (errno == EFAULT) status = STATUS_INVALID_USER_BUFFER;
                else status = errno_to_status( errno );
            }
            goto err;
        }

        if (async_write)
        {
            struct async_fileio_write *fileio;

            fileio = (struct async_fileio_write *)alloc_fileio( sizeof(*fileio), async_write_proc, handle );
            if (!fileio)
            {
                status = STATUS_NO_MEMORY;
                goto err;
            }
            fileio->already = total;
            fileio->count = length;
            fileio->buffer = buffer;

            SERVER_START_REQ( register_async )
            {
                req->type   = ASYNC_TYPE_WRITE;
                req->count  = length;
                req->async  = server_async( handle, &fileio->io, event, apc, apc_user, iosb_ptr );
                status = wine_server_call( req );
            }
            SERVER_END_REQ;

            if (status != STATUS_PENDING) free( fileio );
            goto err;
        }
        else  /* synchronous write, wait for the fd to become ready */
        {
            struct pollfd pfd;
            int ret, timeout;

            if (!timeout_init_done)
            {
                timeout_init_done = TRUE;
                if ((status = get_io_timeouts( handle, type, length, FALSE, &timeouts )))
                    goto err;
                if (event) NtResetEvent( event, NULL );
            }
            timeout = get_next_io_timeout( &timeouts, total );

            pfd.fd = unix_handle;
            pfd.events = POLLOUT;

            if (!timeout || !(ret = poll( &pfd, 1, timeout )))
            {
                /* return with what we got so far */
                status = total ? STATUS_SUCCESS : STATUS_TIMEOUT;
                goto done;
            }
            if (ret == -1 && errno != EINTR)
            {
                status = errno_to_status( errno );
                goto done;
            }
            /* will now restart the write */
        }
    }

done:
    send_completion = cvalue != 0;

err:
#ifdef WINE_IOS
    if (status == STATUS_SUCCESS && type == FD_TYPE_FILE && total)
        ios_guest_log_error( unix_handle, buffer, total );
#endif
    if (needs_close) close( unix_handle );

    if (type == FD_TYPE_SERIAL && (status == STATUS_SUCCESS || status == STATUS_PENDING))
        set_pending_write( handle );

    if (status == STATUS_SUCCESS)
    {
        set_sync_iosb( io, status, total, options );
        TRACE("= SUCCESS (%u)\n", total);
        if (event) NtSetEvent( event, NULL );
        if (apc) NtQueueApcThread( GetCurrentThread(), (PNTAPCFUNC)apc, (ULONG_PTR)apc_user, iosb_ptr, 0 );
    }
    else
    {
        TRACE("= 0x%08x\n", status);
        if (status != STATUS_PENDING && event) NtResetEvent( event, NULL );
    }

    ret_status = async_write && type == FD_TYPE_FILE && status == STATUS_SUCCESS ? STATUS_PENDING : status;
    if (send_completion && async_write)
        add_completion( handle, cvalue, status, total, ret_status == STATUS_PENDING );
    return ret_status;
}


/******************************************************************************
 *              NtWriteFileGather   (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteFileGather( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                   IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments,
                                   ULONG length, LARGE_INTEGER *offset, ULONG *key )
{
    int result, unix_handle, needs_close;
    unsigned int options, status;
    UINT pos = 0, total = 0;
    enum server_fd_type type;

    TRACE( "(%p,%p,%p,%p,%p,%p,0x%08x,%p,%p),partial stub!\n",
           file, event, apc, apc_user, io, segments, length, offset, key );

    if (length % page_size) return STATUS_INVALID_PARAMETER;
    if (!io) return STATUS_ACCESS_VIOLATION;

    status = server_get_unix_fd( file, FILE_WRITE_DATA, &unix_handle, &needs_close, &type, &options );
    if (status) return status;

    if ((type != FD_TYPE_FILE) ||
        (options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) ||
        !(options & FILE_NO_INTERMEDIATE_BUFFERING))
    {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    while (length)
    {
        if (offset && offset->QuadPart != FILE_USE_FILE_POINTER_POSITION)
            result = pwrite( unix_handle, (char *)segments->Buffer + pos,
                             page_size - pos, offset->QuadPart + total );
        else
            result = write( unix_handle, (char *)segments->Buffer + pos, page_size - pos );

        if (result == -1)
        {
            if (errno == EINTR) continue;
            if (errno == EFAULT)
            {
                status = STATUS_INVALID_USER_BUFFER;
                goto done;
            }
            status = errno_to_status( errno );
            break;
        }
        if (!result)
        {
            status = STATUS_DISK_FULL;
            break;
        }
        total += result;
        length -= result;
        if ((pos += result) == page_size)
        {
            pos = 0;
            segments++;
        }
    }

 done:
    if (needs_close) close( unix_handle );
    if (status == STATUS_SUCCESS)
    {
        file_complete_async( file, options, event, apc, apc_user, io, status, total );
        TRACE("= SUCCESS (%u)\n", total);
    }
    else
    {
        TRACE("= 0x%08x\n", status);
        if (status != STATUS_PENDING && event) NtResetEvent( event, NULL );
    }
    return status;
}


/******************************************************************************
 *              NtDeviceIoControlFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtDeviceIoControlFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                       IO_STATUS_BLOCK *io, ULONG code, void *in_buffer, ULONG in_size,
                                       void *out_buffer, ULONG out_size )
{
    ULONG device = (code >> 16);
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    TRACE( "(%p,%p,%p,%p,%p,0x%08x,%p,0x%08x,%p,0x%08x)\n",
           handle, event, apc, apc_context, io, code,
           in_buffer, in_size, out_buffer, out_size );

    /* some broken applications call this frequently with INVALID_HANDLE_VALUE,
     * and run slowly if we make a server call every time */
    if (HandleToLong( handle ) == ~0)
        return STATUS_INVALID_HANDLE;

    switch (device)
    {
    case FILE_DEVICE_BEEP:
    case FILE_DEVICE_NETWORK:
        status = sock_ioctl( handle, event, apc, apc_context, io, code, in_buffer, in_size, out_buffer, out_size );
        break;
    case FILE_DEVICE_DISK:
    case FILE_DEVICE_CD_ROM:
    case FILE_DEVICE_DVD:
    case FILE_DEVICE_CONTROLLER:
    case FILE_DEVICE_MASS_STORAGE:
        status = cdrom_DeviceIoControl( handle, event, apc, apc_context, io, code,
                                        in_buffer, in_size, out_buffer, out_size );
        break;
    case FILE_DEVICE_SERIAL_PORT:
        status = serial_DeviceIoControl( handle, event, apc, apc_context, io, code,
                                         in_buffer, in_size, out_buffer, out_size );
        break;
    case FILE_DEVICE_TAPE:
        status = tape_DeviceIoControl( handle, event, apc, apc_context, io, code,
                                       in_buffer, in_size, out_buffer, out_size );
        break;
    }

    if (status == STATUS_NOT_SUPPORTED || status == STATUS_BAD_DEVICE_TYPE)
        return server_ioctl_file( handle, event, apc, apc_context, io, code,
                                  in_buffer, in_size, out_buffer, out_size );
    return status;
}


/* helper for internal ioctl calls */
NTSTATUS sync_ioctl( HANDLE file, ULONG code, void *in_buffer, ULONG in_size, void *out_buffer, ULONG out_size )
{
    IO_STATUS_BLOCK32 io32;
    IO_STATUS_BLOCK io;

    /* the 32-bit iosb is filled for overlapped file handles */
    io.Pointer = &io32;
    return NtDeviceIoControlFile( file, NULL, NULL, NULL, &io, code, in_buffer, in_size, out_buffer, out_size );
}


/* Tell Valgrind to ignore any holes in structs we will be passing to the
 * server */
static void ignore_server_ioctl_struct_holes( ULONG code, const void *in_buffer, ULONG in_size )
{
#ifdef VALGRIND_MAKE_MEM_DEFINED
# define IGNORE_STRUCT_HOLE(buf, size, t, f1, f2) \
    do { \
        if (FIELD_OFFSET(t, f1) + sizeof(((t *)0)->f1) < FIELD_OFFSET(t, f2)) \
            if ((size) >= FIELD_OFFSET(t, f2)) \
                VALGRIND_MAKE_MEM_DEFINED( \
                    (const char *)(buf) + FIELD_OFFSET(t, f1) + sizeof(((t *)0)->f1), \
                    FIELD_OFFSET(t, f2) - FIELD_OFFSET(t, f1) + sizeof(((t *)0)->f1)); \
    } while (0)

    switch (code)
    {
    case FSCTL_PIPE_WAIT:
        IGNORE_STRUCT_HOLE(in_buffer, in_size, FILE_PIPE_WAIT_FOR_BUFFER, TimeoutSpecified, Name);
        break;
    }
#endif
}


/******************************************************************************
 *              NtFsControlFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtFsControlFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                 IO_STATUS_BLOCK *io, ULONG code, void *in_buffer, ULONG in_size,
                                 void *out_buffer, ULONG out_size )
{
    unsigned int options;
    int fd, needs_close;
    ULONG_PTR size = 0;
    NTSTATUS status;

    TRACE( "(%p,%p,%p,%p,%p,0x%08x,%p,0x%08x,%p,0x%08x)\n",
           handle, event, apc, apc_context, io, code,
           in_buffer, in_size, out_buffer, out_size );

    if (!io) return STATUS_INVALID_PARAMETER;

    status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, &options );
    if (status && status != STATUS_BAD_DEVICE_TYPE)
        return status;
    if (needs_close) close( fd );

    ignore_server_ioctl_struct_holes( code, in_buffer, in_size );

    switch (code)
    {
    case FSCTL_DISMOUNT_VOLUME:
        status = server_ioctl_file( handle, event, apc, apc_context, io, code,
                                    in_buffer, in_size, out_buffer, out_size );
        if (!status) status = unmount_device( handle );
        return status;

    case FSCTL_PIPE_IMPERSONATE:
        FIXME("FSCTL_PIPE_IMPERSONATE: impersonating self\n");
        return server_ioctl_file( handle, event, apc, apc_context, io, code,
                                  in_buffer, in_size, out_buffer, out_size );

    case FSCTL_IS_VOLUME_MOUNTED:
    case FSCTL_LOCK_VOLUME:
    case FSCTL_UNLOCK_VOLUME:
        FIXME("stub! return success - Unsupported fsctl %x (device=%x access=%x func=%x method=%x)\n",
              code, code >> 16, (code >> 14) & 3, (code >> 2) & 0xfff, code & 3);
        status = STATUS_SUCCESS;
        break;

    case FSCTL_GET_RETRIEVAL_POINTERS:
    {
        RETRIEVAL_POINTERS_BUFFER *buffer = (RETRIEVAL_POINTERS_BUFFER *)out_buffer;

        FIXME("stub: FSCTL_GET_RETRIEVAL_POINTERS\n");

        if (out_size >= sizeof(RETRIEVAL_POINTERS_BUFFER))
        {
            buffer->ExtentCount                 = 1;
            buffer->StartingVcn.QuadPart        = 1;
            buffer->Extents[0].NextVcn.QuadPart = 0;
            buffer->Extents[0].Lcn.QuadPart     = 0;
            size = sizeof(RETRIEVAL_POINTERS_BUFFER);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case FSCTL_GET_OBJECT_ID:
    {
        FILE_OBJECTID_BUFFER *info = out_buffer;
        int fd, needs_close;
        struct stat st;

        if (out_size >= sizeof(*info))
        {
            status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, NULL );
            if (status) break;
            fstat( fd, &st );
            if (needs_close) close( fd );
            memset( info, 0, sizeof(*info) );
            memcpy( info->ObjectId, &st.st_dev, sizeof(st.st_dev) );
            memcpy( info->ObjectId + 8, &st.st_ino, sizeof(st.st_ino) );
            size = sizeof(*info);
        }
        else status = STATUS_BUFFER_TOO_SMALL;
        break;
    }

    case FSCTL_SET_SPARSE:
        TRACE("FSCTL_SET_SPARSE: Ignoring request\n");
        status = STATUS_SUCCESS;
        break;
    default:
        return server_ioctl_file( handle, event, apc, apc_context, io, code,
                                  in_buffer, in_size, out_buffer, out_size );
    }

    if (!NT_ERROR(status) && status != STATUS_PENDING)
        file_complete_async( handle, options, event, apc, apc_context, io, status, size );
    return status;
}


/******************************************************************************
 *              NtFlushBuffersFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushBuffersFile( HANDLE handle, IO_STATUS_BLOCK *io )
{
    return NtFlushBuffersFileEx( handle, 0, NULL, 0, io );
}


/******************************************************************************
 *              NtFlushBuffersFileEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushBuffersFileEx( HANDLE handle, ULONG flags, void *params, ULONG size, IO_STATUS_BLOCK *io )
{
    NTSTATUS ret;
    HANDLE wait_handle;
    enum server_fd_type type;
    int fd, needs_close;

    TRACE( "(%p,0x%08x,%p,0x%08x,%p)\n", handle, flags, params, size, io );

    if (flags) FIXME( "flags 0x%08x ignored\n", flags );
    if (params || size) FIXME( "params %p/0x%08x ignored\n", params, size );

    if (!io || !virtual_check_buffer_for_write( io, sizeof(*io) )) return STATUS_ACCESS_VIOLATION;

    ret = server_get_unix_fd( handle, FILE_WRITE_DATA, &fd, &needs_close, &type, NULL );
    if (ret == STATUS_ACCESS_DENIED)
        ret = server_get_unix_fd( handle, FILE_APPEND_DATA, &fd, &needs_close, &type, NULL );

    if (!ret && (type == FD_TYPE_FILE || type == FD_TYPE_DIR || type == FD_TYPE_CHAR))
    {
        if (fsync(fd)) ret = errno_to_status( errno );
        io->Status      = ret;
        io->Information = 0;
    }
    else if (!ret && type == FD_TYPE_SERIAL)
    {
        ret = serial_FlushBuffersFile( fd );
    }
    else if (ret != STATUS_ACCESS_DENIED)
    {
        struct async_irp *async;

        if (!(async = (struct async_irp *)alloc_fileio( sizeof(*async), irp_completion, handle )))
            return STATUS_NO_MEMORY;
        async->buffer  = NULL;
        async->size    = 0;

        SERVER_START_REQ( flush )
        {
            req->async = server_async( handle, &async->io, NULL, NULL, NULL, iosb_client_ptr(io) );
            ret = wine_server_call( req );
            wait_handle = wine_server_ptr_handle( reply->event );
            if (wait_handle && ret != STATUS_PENDING)
            {
                io->Status      = ret;
                io->Information = 0;
            }
        }
        SERVER_END_REQ;

        if (ret != STATUS_PENDING) free( async );

        if (wait_handle) ret = wait_async( wait_handle, FALSE );
    }

    if (needs_close) close( fd );
    return ret;
}


static NTSTATUS cancel_io( HANDLE handle, IO_STATUS_BLOCK *io, IO_STATUS_BLOCK *io_status,
                           BOOL only_thread )
{
    HANDLE cancel_handle;
    unsigned int status;

    SERVER_START_REQ( cancel_async )
    {
        req->handle      = wine_server_obj_handle( handle );
        req->iosb        = wine_server_client_ptr( io );
        req->only_thread = only_thread;
        if (!(status = wine_server_call( req )))
            cancel_handle = wine_server_ptr_handle( reply->cancel_handle );
    }
    SERVER_END_REQ;

    if (!status && cancel_handle)
    {
        NtWaitForSingleObject( cancel_handle, TRUE, NULL );
        NtClose( cancel_handle );
    }
    else if (status == STATUS_INVALID_HANDLE)
    {
        return status;
    }

    io_status->Status = status;
    io_status->Information = 0;

    return status;
}


/**************************************************************************
 *           NtCancelIoFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtCancelIoFile( HANDLE handle, IO_STATUS_BLOCK *io_status )
{
    TRACE( "%p %p\n", handle, io_status );

    return cancel_io( handle, NULL, io_status, TRUE );
}


/**************************************************************************
 *           NtCancelIoFileEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtCancelIoFileEx( HANDLE handle, IO_STATUS_BLOCK *io, IO_STATUS_BLOCK *io_status )
{
    TRACE( "%p %p %p\n", handle, io, io_status );

    return cancel_io( handle, io, io_status, FALSE );
}


/**************************************************************************
 *           NtCancelSynchronousIoFile (NTDLL.@)
 */
NTSTATUS WINAPI NtCancelSynchronousIoFile( HANDLE handle, IO_STATUS_BLOCK *io, IO_STATUS_BLOCK *io_status )
{
    unsigned int status;

    TRACE( "(%p %p %p)\n", handle, io, io_status );

    SERVER_START_REQ( cancel_sync )
    {
        req->handle = wine_server_obj_handle( handle );
        req->iosb   = wine_server_client_ptr( io );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    io_status->Status = status;
    io_status->Information = 0;
    return status;
}

/******************************************************************
 *           NtLockFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtLockFile( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void* apc_user,
                            IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset,
                            LARGE_INTEGER *count, ULONG *key, BOOLEAN dont_wait, BOOLEAN exclusive )
{
    static int warn;
    unsigned int ret;
    HANDLE handle;
    BOOLEAN async;

    if (apc || io_status || key)
    {
        FIXME("Unimplemented yet parameter\n");
        return STATUS_NOT_IMPLEMENTED;
    }
    if (apc_user && !warn++) FIXME("I/O completion on lock not implemented yet\n");

    for (;;)
    {
        SERVER_START_REQ( lock_file )
        {
            req->handle      = wine_server_obj_handle( file );
            req->offset      = offset->QuadPart;
            req->count       = count->QuadPart;
            req->shared      = !exclusive;
            req->wait        = !dont_wait;
            ret = wine_server_call( req );
            handle = wine_server_ptr_handle( reply->handle );
            async  = reply->overlapped;
        }
        SERVER_END_REQ;
        if (ret != STATUS_PENDING)
        {
            if (!ret && event) NtSetEvent( event, NULL );
            return ret;
        }
        if (async)
        {
            FIXME( "Async I/O lock wait not implemented, might deadlock\n" );
            if (handle) NtClose( handle );
            return STATUS_PENDING;
        }
        if (handle)
        {
            NtWaitForSingleObject( handle, FALSE, NULL );
            NtClose( handle );
        }
        else  /* Unix lock conflict, sleep a bit and retry */
        {
            LARGE_INTEGER time;
            time.QuadPart = -100 * (ULONGLONG)10000;
            NtDelayExecution( FALSE, &time );
        }
    }
}


/******************************************************************
 *           NtUnlockFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnlockFile( HANDLE handle, IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset,
                              LARGE_INTEGER *count, ULONG *key )
{
    unsigned int status;

    TRACE( "%p %p %s %s\n",
           handle, io_status, wine_dbgstr_longlong(offset->QuadPart), wine_dbgstr_longlong(count->QuadPart) );

    io_status->Information = 0;
    if (key)
    {
        FIXME("Unimplemented yet parameter\n");
        return (io_status->Status = STATUS_NOT_IMPLEMENTED);
    }

    SERVER_START_REQ( unlock_file )
    {
        req->handle = wine_server_obj_handle( handle );
        req->offset = offset->QuadPart;
        req->count  = count->QuadPart;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    return (io_status->Status = status);
}


static BOOL read_changes_apc( void *user, ULONG_PTR *info, unsigned int *status )
{
    struct async_fileio_read_changes *fileio = user;
    int size = 0;

    if (*status == STATUS_ALERTED)
    {
        SERVER_START_REQ( read_change )
        {
            req->handle = wine_server_obj_handle( fileio->io.handle );
            wine_server_set_reply( req, fileio->data, fileio->data_size );
            *status = wine_server_call( req );
            size = wine_server_reply_size( reply );
        }
        SERVER_END_REQ;

        if (*status == STATUS_SUCCESS && fileio->buffer)
        {
            FILE_NOTIFY_INFORMATION *pfni = fileio->buffer;
            int i, left = fileio->buffer_size;
            DWORD *last_entry_offset = NULL;
            struct filesystem_event *event = (struct filesystem_event*)fileio->data;

            while (size && left >= sizeof(*pfni))
            {
                DWORD len = (left - offsetof(FILE_NOTIFY_INFORMATION, FileName)) / sizeof(WCHAR);

                /* convert to an NT style path */
                for (i = 0; i < event->len; i++)
                    if (event->name[i] == '/') event->name[i] = '\\';

                pfni->Action = event->action;
                pfni->FileNameLength = ntdll_umbstowcs( event->name, event->len, pfni->FileName, len );
                last_entry_offset = &pfni->NextEntryOffset;

                if (pfni->FileNameLength == len) break;

                i = offsetof(FILE_NOTIFY_INFORMATION, FileName[pfni->FileNameLength]);
                pfni->FileNameLength *= sizeof(WCHAR);
                pfni->NextEntryOffset = i;
                pfni = (FILE_NOTIFY_INFORMATION*)((char*)pfni + i);
                left -= i;

                i = (offsetof(struct filesystem_event, name[event->len])
                     + sizeof(int)-1) / sizeof(int) * sizeof(int);
                event = (struct filesystem_event*)((char*)event + i);
                size -= i;
            }

            if (size)
            {
                *status = STATUS_NOTIFY_ENUM_DIR;
                size = 0;
            }
            else
            {
                if (last_entry_offset) *last_entry_offset = 0;
                size = fileio->buffer_size - left;
            }
        }
        else
        {
            *status = STATUS_NOTIFY_ENUM_DIR;
            size = 0;
        }
    }

    *info = size;
    release_fileio( &fileio->io );
    return TRUE;
}

#define FILE_NOTIFY_ALL        (  \
 FILE_NOTIFY_CHANGE_FILE_NAME   | \
 FILE_NOTIFY_CHANGE_DIR_NAME    | \
 FILE_NOTIFY_CHANGE_ATTRIBUTES  | \
 FILE_NOTIFY_CHANGE_SIZE        | \
 FILE_NOTIFY_CHANGE_LAST_WRITE  | \
 FILE_NOTIFY_CHANGE_LAST_ACCESS | \
 FILE_NOTIFY_CHANGE_CREATION    | \
 FILE_NOTIFY_CHANGE_SECURITY   )

/******************************************************************************
 *              NtNotifyChangeDirectoryFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtNotifyChangeDirectoryFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                                             void *apc_context, IO_STATUS_BLOCK *iosb, void *buffer,
                                             ULONG buffer_size, ULONG filter, BOOLEAN subtree )
{
    struct async_fileio_read_changes *fileio;
    unsigned int status;
    ULONG size = max( 4096, buffer_size );

    TRACE( "%p %p %p %p %p %p %u %u %d\n",
           handle, event, apc, apc_context, iosb, buffer, buffer_size, filter, subtree );

    if (!iosb) return STATUS_ACCESS_VIOLATION;
    if (filter == 0 || (filter & ~FILE_NOTIFY_ALL)) return STATUS_INVALID_PARAMETER;

    fileio = (struct async_fileio_read_changes *)alloc_fileio(
        offsetof(struct async_fileio_read_changes, data[size]), read_changes_apc, handle );
    if (!fileio) return STATUS_NO_MEMORY;

    fileio->buffer      = buffer;
    fileio->buffer_size = buffer_size;
    fileio->data_size   = size;

    SERVER_START_REQ( read_directory_changes )
    {
        req->filter    = filter;
        req->want_data = (buffer != NULL);
        req->subtree   = subtree;
        req->async     = server_async( handle, &fileio->io, event, apc, apc_context, iosb_client_ptr(iosb) );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    if (status != STATUS_PENDING) free( fileio );
    return status;
}


#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__)
/* helper for FILE_GetDeviceInfo to hide some platform differences in fstatfs */
static inline void get_device_info_fstatfs( FILE_FS_DEVICE_INFORMATION *info, const char *fstypename,
                                            unsigned int flags )
{
    if (!strcmp("cd9660", fstypename) || !strcmp("udf", fstypename))
    {
        info->DeviceType = FILE_DEVICE_CD_ROM_FILE_SYSTEM;
        /* Don't assume read-only, let the mount options set it below */
        info->Characteristics |= FILE_REMOVABLE_MEDIA;
    }
    else if (!strcmp("nfs", fstypename) || !strcmp("nwfs", fstypename) ||
             !strcmp("smbfs", fstypename) || !strcmp("afpfs", fstypename))
    {
        info->DeviceType = FILE_DEVICE_NETWORK_FILE_SYSTEM;
        info->Characteristics |= FILE_REMOTE_DEVICE;
    }
    else if (!strcmp("procfs", fstypename))
        info->DeviceType = FILE_DEVICE_VIRTUAL_DISK;
    else
        info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;

    if (flags & MNT_RDONLY)
        info->Characteristics |= FILE_READ_ONLY_DEVICE;

    if (!(flags & MNT_LOCAL))
    {
        info->DeviceType = FILE_DEVICE_NETWORK_FILE_SYSTEM;
        info->Characteristics |= FILE_REMOTE_DEVICE;
    }
}
#endif

static inline BOOL is_device_placeholder( int fd )
{
    static const char wine_placeholder[] = "Wine device placeholder";
    char buffer[sizeof(wine_placeholder)-1];

    if (pread( fd, buffer, sizeof(wine_placeholder) - 1, 0 ) != sizeof(wine_placeholder) - 1)
        return FALSE;
    return !memcmp( buffer, wine_placeholder, sizeof(wine_placeholder) - 1 );
}

NTSTATUS get_device_info( int fd, FILE_FS_DEVICE_INFORMATION *info )
{
    struct stat st;

    info->Characteristics = 0;
    if (fstat( fd, &st ) < 0) return errno_to_status( errno );
    if (S_ISCHR( st.st_mode ))
    {
        info->DeviceType = FILE_DEVICE_UNKNOWN;
#ifdef linux
        switch(major(st.st_rdev))
        {
        case MEM_MAJOR:
            info->DeviceType = FILE_DEVICE_NULL;
            break;
        case TTY_MAJOR:
            info->DeviceType = FILE_DEVICE_SERIAL_PORT;
            break;
        case LP_MAJOR:
            info->DeviceType = FILE_DEVICE_PARALLEL_PORT;
            break;
        case SCSI_TAPE_MAJOR:
            info->DeviceType = FILE_DEVICE_TAPE;
            break;
        }
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__APPLE__)
        {
            int d_type;
            if (ioctl(fd, FIODTYPE, &d_type) == 0)
            {
                switch(d_type)
                {
                case D_TAPE:
                    info->DeviceType = FILE_DEVICE_TAPE;
                    break;
                case D_DISK:
                    info->DeviceType = FILE_DEVICE_DISK;
#if defined(__APPLE__)
                    if (major(st.st_rdev) == 3 && minor(st.st_rdev) == 2) info->DeviceType = FILE_DEVICE_NULL;
#endif
                    break;
                case D_TTY:
                    info->DeviceType = FILE_DEVICE_SERIAL_PORT;
                    break;
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
                case D_MEM:
                    info->DeviceType = FILE_DEVICE_NULL;
                    break;
#endif
                }
                /* no special d_type for parallel ports */
            }
        }
#endif
    }
    else if (S_ISBLK( st.st_mode ))
    {
        info->DeviceType = FILE_DEVICE_DISK;
    }
    else if (S_ISFIFO( st.st_mode ) || S_ISSOCK( st.st_mode ))
    {
        info->DeviceType = FILE_DEVICE_NAMED_PIPE;
    }
    else if (is_device_placeholder( fd ))
    {
        info->DeviceType = FILE_DEVICE_DISK;
    }
    else  /* regular file or directory */
    {
#if defined(linux) && defined(HAVE_FSTATFS)
        struct statfs stfs;

        /* check for floppy disk */
        if (major(st.st_dev) == FLOPPY_MAJOR)
            info->Characteristics |= FILE_REMOVABLE_MEDIA;

        if (fstatfs( fd, &stfs ) < 0) stfs.f_type = 0;
        switch (stfs.f_type)
        {
        case 0x9660:      /* iso9660 */
        case 0x9fa1:      /* supermount */
        case 0x15013346:  /* udf */
            info->DeviceType = FILE_DEVICE_CD_ROM_FILE_SYSTEM;
            info->Characteristics |= FILE_REMOVABLE_MEDIA|FILE_READ_ONLY_DEVICE;
            break;
        case 0x6969:  /* nfs */
        case 0xff534d42: /* cifs */
        case 0xfe534d42: /* smb2 */
        case 0x517b:  /* smbfs */
        case 0x564c:  /* ncpfs */
            info->DeviceType = FILE_DEVICE_NETWORK_FILE_SYSTEM;
            info->Characteristics |= FILE_REMOTE_DEVICE;
            break;
        case 0x1373:      /* devfs */
        case 0x9fa0:      /* procfs */
            info->DeviceType = FILE_DEVICE_VIRTUAL_DISK;
            break;
        case 0x01021994:  /* tmpfs */
        case 0x28cd3d45:  /* cramfs */
            /* Don't map these to FILE_DEVICE_VIRTUAL_DISK by default. Virtual
             * filesystems are rare on Windows, and some programs refuse to
             * recognize them as valid. */
        default:
            info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
            break;
        }
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__)
        struct statfs stfs;

        if (fstatfs( fd, &stfs ) < 0)
            info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
        else
            get_device_info_fstatfs( info, stfs.f_fstypename, stfs.f_flags );
#elif defined(__NetBSD__)
        struct statvfs stfs;

        if (fstatvfs( fd, &stfs) < 0)
            info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
        else
            get_device_info_fstatfs( info, stfs.f_fstypename, stfs.f_flag );
#elif defined(sun)
        /* Use dkio to work out device types */
        {
# include <sys/dkio.h>
# include <sys/vtoc.h>
            struct dk_cinfo dkinf;
            int retval = ioctl(fd, DKIOCINFO, &dkinf);
            if(retval==-1){
                WARN("Unable to get disk device type information - assuming a disk like device\n");
                info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
            }
            switch (dkinf.dki_ctype)
            {
            case DKC_CDROM:
                info->DeviceType = FILE_DEVICE_CD_ROM_FILE_SYSTEM;
                info->Characteristics |= FILE_REMOVABLE_MEDIA|FILE_READ_ONLY_DEVICE;
                break;
            case DKC_NCRFLOPPY:
            case DKC_SMSFLOPPY:
            case DKC_INTEL82072:
            case DKC_INTEL82077:
                info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
                info->Characteristics |= FILE_REMOVABLE_MEDIA;
                break;
            case DKC_MD:
            /* Don't map these to FILE_DEVICE_VIRTUAL_DISK by default. Virtual
             * filesystems are rare on Windows, and some programs refuse to
             * recognize them as valid. */
            default:
                info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
            }
        }
#else
        static int warned;
        if (!warned++) FIXME( "device info not properly supported on this platform\n" );
        info->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
#endif
        info->Characteristics |= FILE_DEVICE_IS_MOUNTED;
    }
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtQueryVolumeInformationFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryVolumeInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                              void *buffer, ULONG length,
                                              FS_INFORMATION_CLASS info_class )
{
    int fd, needs_close;
    unsigned int status;

    status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, NULL );
    if (status == STATUS_BAD_DEVICE_TYPE)
    {
        struct async_irp *async;
        HANDLE wait_handle;

        if (!(async = (struct async_irp *)alloc_fileio( sizeof(*async), irp_completion, handle )))
            return STATUS_NO_MEMORY;
        async->buffer  = buffer;
        async->size    = length;

        SERVER_START_REQ( get_volume_info )
        {
            req->async = server_async( handle, &async->io, NULL, NULL, NULL, iosb_client_ptr(io) );
            req->handle = wine_server_obj_handle( handle );
            req->info_class = info_class;
            wine_server_set_reply( req, buffer, length );
            status = wine_server_call( req );
            if (status != STATUS_PENDING)
            {
                io->Status = status;
                io->Information = wine_server_reply_size( reply );
            }
            wait_handle = wine_server_ptr_handle( reply->wait );
        }
        SERVER_END_REQ;
        if (status != STATUS_PENDING) free( async );
        if (wait_handle) status = wait_async( wait_handle, FALSE );
        return status;
    }
    else if (status) return io->Status = status;

    io->Information = 0;

    switch( info_class )
    {
    case FileFsLabelInformation:
        FIXME( "%p: label info not supported\n", handle );
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case FileFsSizeInformation:
        if (length < sizeof(FILE_FS_SIZE_INFORMATION))
            status = STATUS_BUFFER_TOO_SMALL;
        else
        {
            FILE_FS_SIZE_INFORMATION *info = buffer;
            FILE_FS_FULL_SIZE_INFORMATION full_info;

            if ((status = get_full_size_info(fd, &full_info)) == STATUS_SUCCESS)
            {
                info->TotalAllocationUnits = full_info.TotalAllocationUnits;
                info->AvailableAllocationUnits = full_info.CallerAvailableAllocationUnits;
                info->SectorsPerAllocationUnit = full_info.SectorsPerAllocationUnit;
                info->BytesPerSector = full_info.BytesPerSector;
                io->Information = sizeof(*info);
            }
        }
        break;

    case FileFsDeviceInformation:
        if (length < sizeof(FILE_FS_DEVICE_INFORMATION))
            status = STATUS_BUFFER_TOO_SMALL;
        else
        {
            FILE_FS_DEVICE_INFORMATION *info = buffer;

            if ((status = get_device_info( fd, info )) == STATUS_SUCCESS)
                io->Information = sizeof(*info);
        }
        break;

    case FileFsAttributeInformation:
    {
        static const WCHAR fatW[] = {'F','A','T'};
        static const WCHAR fat32W[] = {'F','A','T','3','2'};
        static const WCHAR ntfsW[] = {'N','T','F','S'};
        static const WCHAR cdfsW[] = {'C','D','F','S'};
        static const WCHAR udfW[] = {'U','D','F'};

        FILE_FS_ATTRIBUTE_INFORMATION *info = buffer;
        struct mountmgr_unix_drive drive;
        enum mountmgr_fs_type fs_type = MOUNTMGR_FS_TYPE_NTFS;

        if (length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        if (!get_mountmgr_fs_info( handle, fd, &drive, sizeof(drive) )) fs_type = drive.fs_type;
        else
        {
            struct statfs stfs;

            if (!fstatfs( fd, &stfs ))
            {
#if defined(linux) && defined(HAVE_FSTATFS)
                switch (stfs.f_type)
                {
                case 0x9660:
                    fs_type = MOUNTMGR_FS_TYPE_ISO9660;
                    break;
                case 0x15013346:
                    fs_type = MOUNTMGR_FS_TYPE_UDF;
                    break;
                case 0x4d44:
                    fs_type = MOUNTMGR_FS_TYPE_FAT32;
                    break;
                }
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__)
                if (!strcmp( stfs.f_fstypename, "cd9660" ))
                    fs_type = MOUNTMGR_FS_TYPE_ISO9660;
                else if (!strcmp( stfs.f_fstypename, "udf" ))
                    fs_type = MOUNTMGR_FS_TYPE_UDF;
                else if (!strcmp( stfs.f_fstypename, "msdos" )) /* FreeBSD < 5, Apple */
                    fs_type = MOUNTMGR_FS_TYPE_FAT32;
                else if (!strcmp( stfs.f_fstypename, "msdosfs" )) /* FreeBSD >= 5 */
                    fs_type = MOUNTMGR_FS_TYPE_FAT32;
#endif
            }
        }

        switch (fs_type)
        {
        case MOUNTMGR_FS_TYPE_ISO9660:
            info->FileSystemAttributes = FILE_READ_ONLY_VOLUME;
            info->MaximumComponentNameLength = 221;
            info->FileSystemNameLength = min( sizeof(cdfsW), length - offsetof( FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName ) );
            memcpy(info->FileSystemName, cdfsW, info->FileSystemNameLength);
            break;
        case MOUNTMGR_FS_TYPE_UDF:
            info->FileSystemAttributes = FILE_READ_ONLY_VOLUME | FILE_UNICODE_ON_DISK | FILE_CASE_SENSITIVE_SEARCH;
            info->MaximumComponentNameLength = 255;
            info->FileSystemNameLength = min( sizeof(udfW), length - offsetof( FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName ) );
            memcpy(info->FileSystemName, udfW, info->FileSystemNameLength);
            break;
        case MOUNTMGR_FS_TYPE_FAT:
            info->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES; /* FIXME */
            info->MaximumComponentNameLength = 255;
            info->FileSystemNameLength = min( sizeof(fatW), length - offsetof( FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName ) );
            memcpy(info->FileSystemName, fatW, info->FileSystemNameLength);
            break;
        case MOUNTMGR_FS_TYPE_FAT32:
            info->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES; /* FIXME */
            info->MaximumComponentNameLength = 255;
            info->FileSystemNameLength = min( sizeof(fat32W), length - offsetof( FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName ) );
            memcpy(info->FileSystemName, fat32W, info->FileSystemNameLength);
            break;
        default:
            info->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_PERSISTENT_ACLS;
            info->MaximumComponentNameLength = 255;
            info->FileSystemNameLength = min( sizeof(ntfsW), length - offsetof( FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName ) );
            memcpy(info->FileSystemName, ntfsW, info->FileSystemNameLength);
            break;
        }

        io->Information = offsetof( FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName ) + info->FileSystemNameLength;
        status = STATUS_SUCCESS;
        break;
    }

    case FileFsVolumeInformation:
    {
        FILE_FS_VOLUME_INFORMATION *info = buffer;
        ULONGLONG data[64];
        struct mountmgr_unix_drive *drive = (struct mountmgr_unix_drive *)data;
        const WCHAR *label;

        if (length < sizeof(FILE_FS_VOLUME_INFORMATION))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        if (get_mountmgr_fs_info( handle, fd, drive, sizeof(data) ))
        {
            /* iOS-Madeira ml1030: THE MOUNT MANAGER IS NOT A PRECONDITION FOR
             * "WHICH VOLUME IS THIS".
             *
             * FileFsVolumeInformation is the only volume class that hard-fails
             * when \Device\MountPointManager cannot be opened; FileFsAttribute,
             * FileFsDevice and FileFsSize all fall back to statfs already.  On a
             * host with no mount manager that single STATUS_NOT_IMPLEMENTED
             * makes GetVolumeInformation() — and with it every install check,
             * licence check and "what drive am I on" heuristic that asks for a
             * serial or a label — return FALSE with ERROR_CALL_NOT_IMPLEMENTED
             * for EVERY path on the system, because kernelbase issues this query
             * whenever `label` or `serial` is non-NULL and returns FALSE on any
             * failure (dlls/kernelbase/volume.c, GetVolumeInformationByHandleW).
             *
             * Windows always answers this class for a local volume, so
             * "not implemented" is not a legal answer; a synthesized but stable
             * one is strictly closer to the truth.  The label is genuinely empty
             * here (there is nothing that could name it), and SupportsObjects
             * agrees with the NTFS that FileFsAttributeInformation reports on the
             * same fallback path.
             *
             * MADEIRA_VOLUME_FALLBACK=0 restores the refusal exactly. */
            static int fallback_enabled = -1;

            if (fallback_enabled < 0)
            {
                const char *s = getenv( "MADEIRA_VOLUME_FALLBACK" );
                fallback_enabled = (s && (*s == '0' || *s == 'n' || *s == 'N')) ? 0 : 1;
            }
            if (!fallback_enabled)
            {
                status = STATUS_NOT_IMPLEMENTED;
                break;
            }

            info->VolumeCreationTime.QuadPart = 0;
            info->VolumeSerialNumber = get_volume_serial_fallback( fd, drive->letter );
            info->VolumeLabelLength = 0;
            info->SupportsObjects = TRUE;
            io->Information = offsetof( FILE_FS_VOLUME_INFORMATION, VolumeLabel );
            status = STATUS_SUCCESS;

            {
                static int reported;
                if (!reported++)
                    ERR( "no mount manager: answering FileFsVolumeInformation from statfs "
                         "(serial %08lx, empty label); MADEIRA_VOLUME_FALLBACK=0 to refuse instead\n",
                         (unsigned long)info->VolumeSerialNumber );
            }
            break;
        }

        label = (WCHAR *)((char *)drive + drive->label_offset);
        info->VolumeCreationTime.QuadPart = 0; /* FIXME */
        info->VolumeSerialNumber = drive->serial;
        info->VolumeLabelLength = min( wcslen( label ) * sizeof(WCHAR),
                                       length - offsetof( FILE_FS_VOLUME_INFORMATION, VolumeLabel ) );
        info->SupportsObjects = (drive->fs_type == MOUNTMGR_FS_TYPE_NTFS);
        memcpy( info->VolumeLabel, label, info->VolumeLabelLength );
        io->Information = offsetof( FILE_FS_VOLUME_INFORMATION, VolumeLabel ) + info->VolumeLabelLength;
        status = STATUS_SUCCESS;
        break;
    }

    case FileFsControlInformation:
        FIXME( "%p: control info not supported\n", handle );
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case FileFsFullSizeInformation:
        if (length < sizeof(FILE_FS_FULL_SIZE_INFORMATION))
            status = STATUS_BUFFER_TOO_SMALL;
        else
        {
            FILE_FS_FULL_SIZE_INFORMATION *info = buffer;
            if ((status = get_full_size_info(fd, info)) == STATUS_SUCCESS)
                io->Information = sizeof(*info);
        }
        break;

    case FileFsFullSizeInformationEx:
        if (length < sizeof(FILE_FS_FULL_SIZE_INFORMATION_EX))
            status = STATUS_BUFFER_TOO_SMALL;
        else
        {
            FILE_FS_FULL_SIZE_INFORMATION_EX *info = buffer;
            if ((status = get_full_size_info_ex(fd, info)) == STATUS_SUCCESS)
                io->Information = sizeof(*info);
        }
        break;

    case FileFsObjectIdInformation:
        FIXME( "%p: object id info not supported\n", handle );
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case FileFsMaximumInformation:
        FIXME( "%p: maximum info not supported\n", handle );
        status = STATUS_NOT_IMPLEMENTED;
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    if (needs_close) close( fd );
    return io->Status = status;
}


/******************************************************************************
 *              NtSetVolumeInformationFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetVolumeInformationFile( HANDLE handle, IO_STATUS_BLOCK *io, void *info,
                                            ULONG length, FS_INFORMATION_CLASS class )
{
    FIXME( "(%p,%p,%p,0x%08x,0x%08x) stub\n", handle, io, info, length, class );
    return STATUS_SUCCESS;
}


/******************************************************************
 *           NtQueryEaFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryEaFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                               BOOLEAN single_entry, void *list, ULONG list_len,
                               ULONG *index, BOOLEAN restart )
{
    int fd, needs_close;
    NTSTATUS status;

    FIXME( "(%p,%p,%p,%d,%d,%p,%d,%p,%d) semi-stub\n",
           handle, io, buffer, length, single_entry, list, list_len, index, restart );

    if ((status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, NULL )))
        return status;

    if (buffer && length)
        memset( buffer, 0, length );

    if (needs_close) close( fd );
    return STATUS_NO_EAS_ON_FILE;
}


/******************************************************************
 *           NtSetEaFile   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetEaFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length )
{
    FIXME( "(%p,%p,%p,%d) stub\n", handle, io, buffer, length );
    return STATUS_ACCESS_DENIED;
}


/* convert type information from server format; helper for NtQueryObject */
static void *put_object_type_info( OBJECT_TYPE_INFORMATION *p, struct object_type_info *info )
{
    const ULONG align = sizeof(DWORD_PTR) - 1;

    memset( p, 0, sizeof(*p) );
    p->TypeName.Buffer               = (WCHAR *)(p + 1);
    p->TypeName.Length               = info->name_len;
    p->TypeName.MaximumLength        = info->name_len + sizeof(WCHAR);
    p->TotalNumberOfObjects          = info->obj_count;
    p->TotalNumberOfHandles          = info->handle_count;
    p->HighWaterNumberOfObjects      = info->obj_max;
    p->HighWaterNumberOfHandles      = info->handle_max;
    p->TypeIndex                     = info->index + 2;
    p->GenericMapping.GenericRead    = info->mapping.read;
    p->GenericMapping.GenericWrite   = info->mapping.write;
    p->GenericMapping.GenericExecute = info->mapping.exec;
    p->GenericMapping.GenericAll     = info->mapping.all;
    p->ValidAccessMask               = info->valid_access;
    memcpy( p->TypeName.Buffer, info + 1, info->name_len );
    p->TypeName.Buffer[info->name_len / sizeof(WCHAR)] = 0;
    return (char *)(p + 1) + ((p->TypeName.MaximumLength + align) & ~align);
}

/**************************************************************************
 *           NtQueryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryObject( HANDLE handle, OBJECT_INFORMATION_CLASS info_class,
                               void *ptr, ULONG len, ULONG *used_len )
{
    unsigned int status;

    TRACE("(%p,0x%08x,%p,0x%08x,%p)\n", handle, info_class, ptr, len, used_len);

    if (used_len) *used_len = 0;

    switch (info_class)
    {
    case ObjectBasicInformation:
    {
        OBJECT_BASIC_INFORMATION *p = ptr;

        if (len < sizeof(*p)) return STATUS_INFO_LENGTH_MISMATCH;

        SERVER_START_REQ( get_object_info )
        {
            req->handle = wine_server_obj_handle( handle );
            status = wine_server_call( req );
            if (status == STATUS_SUCCESS)
            {
                memset( p, 0, sizeof(*p) );
                p->GrantedAccess = reply->access;
                p->PointerCount = reply->ref_count;
                p->HandleCount = reply->handle_count;
                if (used_len) *used_len = sizeof(*p);
            }
        }
        SERVER_END_REQ;
        break;
    }

    case ObjectNameInformation:
    {
        OBJECT_NAME_INFORMATION *p = ptr;

        SERVER_START_REQ( get_object_name )
        {
            req->handle = wine_server_obj_handle( handle );
            if (len > sizeof(*p) + sizeof(WCHAR))
                wine_server_set_reply( req, p + 1, len - sizeof(*p) - sizeof(WCHAR) );
            status = wine_server_call( req );
            if (status == STATUS_SUCCESS)
            {
                if (!reply->total)  /* no name */
                {
                    if (len < sizeof(*p)) status = STATUS_INFO_LENGTH_MISMATCH;
                    else memset( p, 0, sizeof(*p) );
                    if (used_len) *used_len = sizeof(*p);
                }
                else
                {
                    ULONG res = wine_server_reply_size( reply );
                    p->Name.Buffer = (WCHAR *)(p + 1);
                    p->Name.Length = res;
                    p->Name.MaximumLength = res + sizeof(WCHAR);
                    p->Name.Buffer[res / sizeof(WCHAR)] = 0;
                    if (used_len) *used_len = sizeof(*p) + p->Name.MaximumLength;
                }
            }
            else if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW)
            {
                if (len < sizeof(*p)) status = STATUS_INFO_LENGTH_MISMATCH;
                if (used_len) *used_len = sizeof(*p) + reply->total + sizeof(WCHAR);
            }
        }
        SERVER_END_REQ;
        break;
    }

    case ObjectTypeInformation:
    {
        OBJECT_TYPE_INFORMATION *p = ptr;
        char buffer[sizeof(struct object_type_info) + 64];
        struct object_type_info *info = (struct object_type_info *)buffer;

        SERVER_START_REQ( get_object_type )
        {
            req->handle = wine_server_obj_handle( handle );
            wine_server_set_reply( req, buffer, sizeof(buffer) );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        if (status) break;
        if (sizeof(*p) + info->name_len + sizeof(WCHAR) <= len)
        {
            put_object_type_info( p, info );
            if (used_len) *used_len = sizeof(*p) + p->TypeName.MaximumLength;
        }
        else
        {
            if (used_len) *used_len = sizeof(*p) + info->name_len + sizeof(WCHAR);
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
        break;
    }

    case ObjectTypesInformation:
    {
        OBJECT_TYPES_INFORMATION *types = ptr;
        OBJECT_TYPE_INFORMATION *p;
        struct object_type_info *buffer;
        /* assume at most 32 types, with an average 16-char name */
        UINT size = 32 * (sizeof(struct object_type_info) + 16 * sizeof(WCHAR));
        UINT i, count, pos, total, align = sizeof(DWORD_PTR) - 1;

        buffer = malloc( size );
        SERVER_START_REQ( get_object_types )
        {
            wine_server_set_reply( req, buffer, size );
            status = wine_server_call( req );
            count = reply->count;
        }
        SERVER_END_REQ;
        if (!status)
        {
            if (len >= sizeof(*types)) types->NumberOfTypes = count;
            total = (sizeof(*types) + align) & ~align;
            p = (OBJECT_TYPE_INFORMATION *)((char *)ptr + total);
            for (i = pos = 0; i < count; i++)
            {
                struct object_type_info *info = (struct object_type_info *)((char *)buffer + pos);
                pos += sizeof(*info) + ((info->name_len + 3) & ~3);
                total += sizeof(*p) + ((info->name_len + sizeof(WCHAR) + align) & ~align);
                if (total <= len) p = put_object_type_info( p, info );
            }
            if (used_len) *used_len = total;
            if (total > len) status = STATUS_INFO_LENGTH_MISMATCH;
        }
        else if (status == STATUS_BUFFER_OVERFLOW) FIXME( "size %u too small\n", size );

        free( buffer );
        break;
    }

    case ObjectHandleFlagInformation:
    {
        OBJECT_HANDLE_FLAG_INFORMATION* p = ptr;

        if (len < sizeof(*p)) return STATUS_INVALID_BUFFER_SIZE;

        SERVER_START_REQ( set_handle_info )
        {
            req->handle = wine_server_obj_handle( handle );
            req->flags  = 0;
            req->mask   = 0;
            status = wine_server_call( req );
            if (status == STATUS_SUCCESS)
            {
                p->Inherit = (reply->old_flags & HANDLE_FLAG_INHERIT) != 0;
                p->ProtectFromClose = (reply->old_flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0;
                if (used_len) *used_len = sizeof(*p);
            }
        }
        SERVER_END_REQ;
        break;
    }

    default:
        FIXME("Unsupported information class %u\n", info_class);
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }
    return status;
}


/**************************************************************************
 *           NtSetInformationObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationObject( HANDLE handle, OBJECT_INFORMATION_CLASS info_class,
                                        void *ptr, ULONG len )
{
    unsigned int status;

    TRACE("(%p,0x%08x,%p,0x%08x)\n", handle, info_class, ptr, len);

    switch (info_class)
    {
    case ObjectHandleFlagInformation:
    {
        OBJECT_HANDLE_FLAG_INFORMATION* p = ptr;

        if (len < sizeof(*p)) return STATUS_INVALID_BUFFER_SIZE;

        SERVER_START_REQ( set_handle_info )
        {
            req->handle = wine_server_obj_handle( handle );
            req->mask   = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
            if (p->Inherit) req->flags |= HANDLE_FLAG_INHERIT;
            if (p->ProtectFromClose) req->flags |= HANDLE_FLAG_PROTECT_FROM_CLOSE;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    break;
    }

    default:
        FIXME("Unsupported information class %u\n", info_class);
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }
    return status;
}
