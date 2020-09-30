/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_STALKER_H__
#define __GUM_QUICK_STALKER_H__

#include "gumquickcore.h"

G_BEGIN_DECLS

typedef struct _GumQuickCodeWriter GumQuickCodeWriter;
typedef struct _GumQuickInstruction GumQuickInstruction;

struct _GumQuickStalker
{
  GumQuickCodeWriter * writer;
  GumQuickInstruction * instruction;
  GumQuickCore * core;

  GumStalker * stalker;
  guint queue_capacity;
  guint queue_drain_interval;
};

struct _GumQuickCodeWriter
{
  gint placeholder;
};

struct _GumQuickInstruction
{
  gint placeholder;
};

G_GNUC_INTERNAL void _gum_quick_stalker_init (GumQuickStalker * self,
    GumQuickCodeWriter * writer, GumQuickInstruction * instruction,
    GumQuickCore * core);
G_GNUC_INTERNAL void _gum_quick_stalker_flush (GumQuickStalker * self);
G_GNUC_INTERNAL void _gum_quick_stalker_dispose (GumQuickStalker * self);
G_GNUC_INTERNAL void _gum_quick_stalker_finalize (GumQuickStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_quick_stalker_get (GumQuickStalker * self);
G_GNUC_INTERNAL void _gum_quick_stalker_process_pending (GumQuickStalker * self,
    GumQuickScope * scope);

G_END_DECLS

#endif
