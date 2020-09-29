/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_SCRIPT_BACKEND_H__
#define __GUM_QUICK_SCRIPT_BACKEND_H__

#include "gumscriptbackend.h"

#include <quickjs.h>

G_BEGIN_DECLS

#define GUM_QUICK_TYPE_SCRIPT_BACKEND (gum_quick_script_backend_get_type ())
G_DECLARE_FINAL_TYPE (GumQuickScriptBackend, gum_quick_script_backend,
    GUM_QUICK, SCRIPT_BACKEND, GObject)

G_GNUC_INTERNAL JSRuntime * gum_quick_script_backend_make_runtime (
    GumQuickScriptBackend * self);
G_GNUC_INTERNAL JSValue gum_quick_script_backend_compile_program (
    GumQuickScriptBackend * self, JSContext * ctx, const gchar * name,
    const gchar * source, GError ** error);
G_GNUC_INTERNAL JSValue gum_quick_script_backend_read_program (
    GumQuickScriptBackend * self, JSContext * ctx, GBytes * bytecode,
    GError ** error);
G_GNUC_INTERNAL GRecMutex * gum_quick_script_backend_get_scope_mutex (
    GumQuickScriptBackend * self);
G_GNUC_INTERNAL GumScriptScheduler * gum_quick_script_backend_get_scheduler (
    GumQuickScriptBackend * self);

G_END_DECLS

#endif
