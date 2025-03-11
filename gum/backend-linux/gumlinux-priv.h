/*
 * Copyright (C) 2022-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_LINUX_PRIV_H__
#define __GUM_LINUX_PRIV_H__

#include <dlfcn.h>
#include <glib.h>
#include <pthread.h>
#include <unistd.h>

G_BEGIN_DECLS

typedef struct _GumProcMapsIter GumProcMapsIter;

typedef struct _GumLinuxPThread GumLinuxPThread;
typedef struct _GumGlibcList GumGlibcList;
typedef int GumGlibcLock;

struct _GumProcMapsIter
{
  gint fd;
  gchar buffer[(2 * PATH_MAX) + 1];
  gchar * read_cursor;
  gchar * write_cursor;
};

struct _GumLinuxPThreadSpec
{
  int (* set_name) (pthread_t thread, const char * name);

#if defined (HAVE_GLIBC)
  GumGlibcList * stack_used;
  GumGlibcList * stack_user;
  GumGlibcLock * stack_lock;
#elif defined (HAVE_MUSL)
  GumLinuxPThread * main_thread;
  void (* tl_lock) (void);
  void (* tl_unlock) (void);
#elif defined (HAVE_ANDROID)
  GumLinuxPThread ** thread_list;
  pthread_rwlock_t * thread_list_lock;
#endif

  gpointer start_impl;
  gpointer start_c11_impl;
  guint start_routine_offset;
  guint start_parameter_offset;

  gpointer terminate_impl;
};

struct _GumGlibcList
{
  GumGlibcList * next;
  GumGlibcList * prev;
};

struct _GumLinuxPThread
{
#if defined (HAVE_GLIBC)
  union
  {
# if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    guint8 tcb_header[704];
# endif
    gpointer padding[24];
  } header;
  GumGlibcList list;
  pid_t tid;
#elif defined (HAVE_MUSL)
  gpointer self;
# ifdef HAVE_I386
  gpointer dtv;
# endif
  GumLinuxPThread * prev;
  GumLinuxPThread * next;
  gpointer sysinfo;
# ifdef HAVE_I386
  gsize canary;
# endif
  int tid;
  int errno_val;
  volatile int detach_state;
  volatile int cancel;
  volatile guint8 canceldisable;
  volatile guint8 cancelasync;
  guint8 tsd_used : 1;
  guint8 dlerror_flag : 1;
  guint8 * map_base;
  gsize map_size;
  gpointer stack;
#elif defined (HAVE_ANDROID)
  GumLinuxPThread * next;
  GumLinuxPThread * prev;
  pid_t tid;
#endif
};

G_GNUC_INTERNAL const Dl_info * _gum_process_get_libc_info (void);

G_GNUC_INTERNAL void gum_proc_maps_iter_init_for_self (GumProcMapsIter * iter);
G_GNUC_INTERNAL void gum_proc_maps_iter_init_for_pid (GumProcMapsIter * iter,
    pid_t pid);
G_GNUC_INTERNAL void gum_proc_maps_iter_destroy (GumProcMapsIter * iter);

G_GNUC_INTERNAL gboolean gum_proc_maps_iter_next (GumProcMapsIter * iter,
    const gchar ** line);

G_GNUC_INTERNAL gboolean _gum_try_translate_vdso_name (gchar * name);

G_GNUC_INTERNAL void _gum_acquire_dumpability (void);
G_GNUC_INTERNAL void _gum_release_dumpability (void);

G_END_DECLS

#endif
