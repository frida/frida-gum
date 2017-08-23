/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_STALKER_H__
#define __GUM_DUK_STALKER_H__

#include "gumdukcodewriter.h"
#include "gumdukcore.h"
#include "gumdukinstruction.h"

G_BEGIN_DECLS

typedef struct _GumDukStalkerIterator GumDukStalkerIterator;
typedef struct _GumDukProbeArgs GumDukProbeArgs;

struct _GumDukStalker
{
  GumDukCodeWriter * writer;
  GumDukInstruction * instruction;
  GumDukCore * core;

  GumStalker * stalker;
  guint queue_capacity;
  guint queue_drain_interval;

  GSource * flush_timer;

  GumDukHeapPtr iterator;
  GumDukHeapPtr probe_args;

  GumDukStalkerIterator * cached_iterator;
  gboolean cached_iterator_in_use;

  GumDukInstructionValue * cached_instruction;
  gboolean cached_instruction_in_use;

  GumDukProbeArgs * cached_probe_args;
  gboolean cached_probe_args_in_use;
};

G_GNUC_INTERNAL void _gum_duk_stalker_init (GumDukStalker * self,
    GumDukCodeWriter * writer, GumDukInstruction * instruction,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_stalker_flush (GumDukStalker * self);
G_GNUC_INTERNAL void _gum_duk_stalker_dispose (GumDukStalker * self);
G_GNUC_INTERNAL void _gum_duk_stalker_finalize (GumDukStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_duk_stalker_get (GumDukStalker * self);
G_GNUC_INTERNAL void _gum_duk_stalker_process_pending (GumDukStalker * self,
    GumDukScope * scope);

G_END_DECLS

#endif
