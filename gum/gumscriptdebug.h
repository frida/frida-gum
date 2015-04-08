/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_DEBUG_H__
#define __GUM_SCRIPT_DEBUG_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptDebug GumScriptDebug;

struct _GumScriptDebug
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL gboolean _gum_script_debug_enable_remote_debugger (
    v8::Isolate * isolate, guint16 port, GError ** error);
G_GNUC_INTERNAL void _gum_script_debug_disable_remote_debugger (void);

G_GNUC_INTERNAL void _gum_script_debug_init (GumScriptDebug * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_debug_realize (GumScriptDebug * self);
G_GNUC_INTERNAL void _gum_script_debug_dispose (GumScriptDebug * self);
G_GNUC_INTERNAL void _gum_script_debug_finalize (GumScriptDebug * self);

#endif
