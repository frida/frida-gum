/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_STALKER_H__
#define __GUM_JSCRIPT_STALKER_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscStalker GumJscStalker;

struct _GumJscStalker
{
  GumJscCore * core;
  GumStalker * stalker;
  guint queue_capacity;
  guint queue_drain_interval;
};

G_GNUC_INTERNAL void _gum_jsc_stalker_init (GumJscStalker * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_stalker_flush (GumJscStalker * self);
G_GNUC_INTERNAL void _gum_jsc_stalker_dispose (GumJscStalker * self);
G_GNUC_INTERNAL void _gum_jsc_stalker_finalize (GumJscStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_jsc_stalker_get (GumJscStalker * self);

G_END_DECLS

#endif
