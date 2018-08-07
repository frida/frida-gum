/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_SCRIPT_BACKEND_H__
#define __GUM_V8_SCRIPT_BACKEND_H__

#include "gumscriptbackend.h"
#include "gumscriptscheduler.h"

G_BEGIN_DECLS

#define GUM_V8_TYPE_SCRIPT_BACKEND (gum_v8_script_backend_get_type ())
G_DECLARE_FINAL_TYPE (GumV8ScriptBackend, gum_v8_script_backend, GUM_V8,
    SCRIPT_BACKEND, GObject)

G_GNUC_INTERNAL gpointer gum_v8_script_backend_get_platform (
    GumV8ScriptBackend * self);
G_GNUC_INTERNAL gpointer gum_v8_script_backend_get_isolate (
    GumV8ScriptBackend * self);
G_GNUC_INTERNAL GumScriptScheduler * gum_v8_script_backend_get_scheduler (
    GumV8ScriptBackend * self);

G_END_DECLS

#endif
