/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_STALKER_H__
#define __GUM_V8_STALKER_H__

#include "gumv8codewriter.h"
#include "gumv8core.h"
#include "gumv8instruction.h"

struct GumV8StalkerIterator;

struct GumV8Stalker
{
  GumV8CodeWriter * writer;
  GumV8Instruction * instruction;
  GumV8Core * core;
  GumStalker * stalker;
  guint queue_capacity;
  guint queue_drain_interval;

  GumPersistent<v8::FunctionTemplate>::type * iterator;
  GumPersistent<v8::ObjectTemplate>::type * probe_args;

  GumPersistent<v8::Object>::type * iterator_value;

  GumV8StalkerIterator * cached_iterator;
  gboolean cached_iterator_in_use;

  GumV8NativeWriter * cached_writer;
  gboolean cached_writer_in_use;

  GumV8InstructionValue * cached_instruction;
  gboolean cached_instruction_in_use;
};

G_GNUC_INTERNAL void _gum_v8_stalker_init (GumV8Stalker * self,
    GumV8CodeWriter * writer, GumV8Instruction * instruction,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_stalker_realize (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_flush (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_dispose (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_finalize (GumV8Stalker * self);

G_GNUC_INTERNAL GumStalker * _gum_v8_stalker_get (GumV8Stalker * self);
G_GNUC_INTERNAL void _gum_v8_stalker_process_pending (
    GumV8Stalker * self, ScriptStalkerScope * scope);

#endif
