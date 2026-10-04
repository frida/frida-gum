/*
 * Copyright (C) 2018-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjs.h"

#include "gumscriptbackend.h"

#ifdef G_OS_UNIX
static gint gumjs_runtime_pid;
#endif

void
gumjs_runtime_on_created (void)
{
#ifdef G_OS_UNIX
  g_atomic_int_compare_and_exchange (&gumjs_runtime_pid, 0,
      (gint) gum_process_get_id ());
#endif
}

gboolean
gumjs_runtime_belongs_to_this_process (void)
{
#ifdef G_OS_UNIX
  gint created;

  created = g_atomic_int_get (&gumjs_runtime_pid);
  if (created == 0)
    return TRUE;

  return created == (gint) gum_process_get_id ();
#else
  return TRUE;
#endif
}

void
gumjs_prepare_to_fork (void)
{
  gum_script_scheduler_stop (gum_script_backend_get_scheduler ());
}

void
gumjs_recover_from_fork_in_parent (void)
{
  gum_script_scheduler_start (gum_script_backend_get_scheduler ());
}

void
gumjs_recover_from_fork_in_child (void)
{
#ifdef G_OS_UNIX
  g_atomic_int_set (&gumjs_runtime_pid, (gint) gum_process_get_id ());
#endif
  gum_script_scheduler_start (gum_script_backend_get_scheduler ());
}
