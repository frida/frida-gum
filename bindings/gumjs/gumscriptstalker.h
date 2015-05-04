/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_STALKER_H__
#define __GUM_SCRIPT_STALKER_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptStalker GumScriptStalker;

struct _GumScriptStalker
{
  GumScriptCore * core;
  GMainContext * main_context;
  GumStalker * stalker;

  GumEventSink * sink;
  guint queue_capacity;
  guint queue_drain_interval;
  gint pending_follow_level;

  GumPersistent<v8::ObjectTemplate>::type * probe_args;
};

G_GNUC_INTERNAL void _gum_script_stalker_init (GumScriptStalker * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_stalker_realize (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_flush (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_dispose (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_finalize (GumScriptStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_script_stalker_get (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_process_pending (
    GumScriptStalker * self);

#endif
