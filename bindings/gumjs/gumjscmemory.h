/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_MEMORY_H__
#define __GUM_JSCRIPT_MEMORY_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscMemory GumJscMemory;

struct _GumJscMemory
{
  GumJscCore * core;
};

G_GNUC_INTERNAL void _gum_jsc_memory_init (GumJscMemory * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_memory_dispose (GumJscMemory * self);
G_GNUC_INTERNAL void _gum_jsc_memory_finalize (GumJscMemory * self);

G_END_DECLS

#endif
