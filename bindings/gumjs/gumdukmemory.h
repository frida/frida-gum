/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_MEMORY_H__
#define __GUM_DUK_MEMORY_H__

#include "gumdukcore.h"

#include <gum/gummemoryaccessmonitor.h>

G_BEGIN_DECLS

typedef struct _GumDukMemory GumDukMemory;

struct _GumDukMemory
{
  GumDukCore * core;

  GumMemoryAccessMonitor * monitor;
  GumDukHeapPtr on_access;

  GumDukHeapPtr memory_access_details;
};

G_GNUC_INTERNAL void _gum_duk_memory_init (GumDukMemory * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_memory_dispose (GumDukMemory * self);
G_GNUC_INTERNAL void _gum_duk_memory_finalize (GumDukMemory * self);

G_END_DECLS

#endif
