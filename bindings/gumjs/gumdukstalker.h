/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_STALKER_H__
#define __GUM_DUK_STALKER_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukProbeArgs GumDukProbeArgs;

struct _GumDukStalker
{
  GumDukCore * core;
  GumStalker * stalker;
  guint queue_capacity;
  guint queue_drain_interval;

  GumDukHeapPtr probe_args;

  GumDukProbeArgs * cached_probe_args;
  gboolean cached_probe_args_in_use;
};

G_GNUC_INTERNAL void _gum_duk_stalker_init (GumDukStalker * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_stalker_flush (GumDukStalker * self);
G_GNUC_INTERNAL void _gum_duk_stalker_dispose (GumDukStalker * self);
G_GNUC_INTERNAL void _gum_duk_stalker_finalize (GumDukStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_duk_stalker_get (GumDukStalker * self);
G_GNUC_INTERNAL void _gum_duk_stalker_process_pending (GumDukStalker * self,
    GumDukScope * scope);

G_END_DECLS

#endif
