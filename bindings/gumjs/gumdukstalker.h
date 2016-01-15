/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUKRIPT_STALKER_H__
#define __GUM_DUKRIPT_STALKER_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukStalker GumDukStalker;

struct _GumDukStalker
{
  GumDukCore * core;
  GumStalker * stalker;
  guint queue_capacity;
  guint queue_drain_interval;
};

G_GNUC_INTERNAL void _gum_duk_stalker_init (GumDukStalker * self,
    GumDukCore * core, duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_stalker_flush (GumDukStalker * self,
    duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_stalker_dispose (GumDukStalker * self,
    duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_stalker_finalize (GumDukStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_duk_stalker_get (GumDukStalker * self);

G_END_DECLS

#endif
