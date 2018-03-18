/*
 * Copyright (C) 2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjs.h"

#include "gumscriptscheduler-priv.h"

void
gumjs_prepare_to_fork (void)
{
  _gum_script_scheduler_prepare_to_fork ();
}

void
gumjs_recover_from_fork_in_parent (void)
{
  _gum_script_scheduler_recover_from_fork ();
}

void
gumjs_recover_from_fork_in_child (void)
{
  _gum_script_scheduler_recover_from_fork ();
}
