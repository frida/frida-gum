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

