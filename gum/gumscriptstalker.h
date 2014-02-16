/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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
G_GNUC_INTERNAL void _gum_script_stalker_dispose (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_finalize (GumScriptStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_script_stalker_get (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_process_pending (
    GumScriptStalker * self);

#endif
