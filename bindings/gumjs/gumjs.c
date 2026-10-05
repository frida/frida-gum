/*
 * Copyright (C) 2018-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjs.h"

#include "gumscriptbackend.h"

#ifdef HAVE_QUICKJS
# include "gumquickscriptbackend-priv.h"
#endif

void
gumjs_prepare_to_fork (void)
{
  gum_script_scheduler_prepare_to_fork (gum_script_backend_get_scheduler ());
}

void
gumjs_recover_from_fork_in_parent (void)
{
  gum_script_scheduler_recover_from_fork_in_parent (
      gum_script_backend_get_scheduler ());
}

void
gumjs_recover_from_fork_in_child (void)
{
#ifdef HAVE_QUICKJS
  gum_quick_script_backend_recover_from_fork_in_child ();
#endif
  gum_script_scheduler_recover_from_fork_in_child (
      gum_script_backend_get_scheduler ());
}
