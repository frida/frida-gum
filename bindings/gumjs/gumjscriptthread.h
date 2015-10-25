/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_THREAD_H__
#define __GUM_JSCRIPT_THREAD_H__

#include "gumjscriptcore.h"

#include <gum/gumbacktracer.h>

G_BEGIN_DECLS

typedef struct _GumScriptThread GumScriptThread;

struct _GumScriptThread
{
  GumScriptCore * core;

  GumBacktracer * accurate_backtracer;
  GumBacktracer * fuzzy_backtracer;
};

G_GNUC_INTERNAL void _gum_script_thread_init (GumScriptThread * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_thread_dispose (GumScriptThread * self);
G_GNUC_INTERNAL void _gum_script_thread_finalize (GumScriptThread * self);

G_END_DECLS

#endif
