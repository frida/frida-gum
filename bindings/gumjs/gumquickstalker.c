/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickstalker.h"

void
_gum_quick_stalker_init (GumQuickStalker * self,
                         GumQuickCodeWriter * writer,
                         GumQuickInstruction * instruction,
                         GumQuickCore * core)
{
  self->writer = writer;
  self->instruction = instruction;
  self->core = core;

  self->stalker = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;
}

void
_gum_quick_stalker_flush (GumQuickStalker * self)
{
}

void
_gum_quick_stalker_dispose (GumQuickStalker * self)
{
}

void
_gum_quick_stalker_finalize (GumQuickStalker * self)
{
  g_clear_object (&self->stalker);
}

GumStalker *
_gum_quick_stalker_get (GumQuickStalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

void
_gum_quick_stalker_process_pending (GumQuickStalker * self,
                                    GumQuickScope * scope)
{
  if (scope->pending_stalker_level > 0)
  {
    gum_stalker_follow_me (_gum_quick_stalker_get (self),
        scope->pending_stalker_transformer, scope->pending_stalker_sink);
  }
  else if (scope->pending_stalker_level < 0)
  {
    gum_stalker_unfollow_me (_gum_quick_stalker_get (self));
  }
  scope->pending_stalker_level = 0;

  g_clear_object (&scope->pending_stalker_sink);
  g_clear_object (&scope->pending_stalker_transformer);
}
