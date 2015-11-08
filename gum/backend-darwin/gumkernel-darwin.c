/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumkernel.h"

#include "gumdarwin.h"

#include <mach/mach.h>

static mach_port_t gum_kernel_get_task (void);
static mach_port_t gum_kernel_do_init (void);

gboolean
gum_kernel_api_is_available (void)
{
  return gum_kernel_get_task () != MACH_PORT_NULL;
}

guint8 *
gum_kernel_read (GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return NULL;

  return gum_darwin_read (task, address, len, n_bytes_read);
}

gboolean
gum_kernel_write (GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return FALSE;

  return gum_darwin_write (task, address, bytes, len);
}

void
gum_kernel_enumerate_threads (GumFoundThreadFunc func,
                              gpointer user_data)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return;

  gum_darwin_enumerate_threads (task, func, user_data);
}

void
gum_kernel_enumerate_ranges (GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return;

  gum_darwin_enumerate_ranges (task, prot, func, user_data);
}

static mach_port_t
gum_kernel_get_task (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, (GThreadFunc) gum_kernel_do_init, NULL);

  return (mach_port_t) init_once.retval;
}

static mach_port_t
gum_kernel_do_init (void)
{
  mach_port_t task = MACH_PORT_NULL;

  task_for_pid (mach_task_self (), 0, &task);

  return task;
}

