/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_STALKER_H__
#define __GUM_V8_STALKER_H__

#include "gumv8core.h"

struct GumV8Stalker
{
  GumV8Core * core;
  GumStalker * stalker;
  GumEventSink * sink;
  guint queue_capacity;
  guint queue_drain_interval;
  gint pending_follow_level;

  GumPersistent<v8::ObjectTemplate>::type * probe_args;
};

G_GNUC_INTERNAL void _gum_v8_stalker_init (GumV8Stalker * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_stalker_realize (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_flush (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_dispose (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_finalize (GumV8Stalker * self);

G_GNUC_INTERNAL GumStalker * _gum_v8_stalker_get (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_process_pending (
    GumV8Stalker * self);

#endif
