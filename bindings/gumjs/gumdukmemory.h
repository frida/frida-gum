/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUKRIPT_MEMORY_H__
#define __GUM_DUKRIPT_MEMORY_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukMemory GumDukMemory;

struct _GumDukMemory
{
  GumDukCore * core;
};

G_GNUC_INTERNAL void _gum_duk_memory_init (GumDukMemory * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_memory_dispose (GumDukMemory * self);
G_GNUC_INTERNAL void _gum_duk_memory_finalize (GumDukMemory * self);

G_END_DECLS

#endif
