/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_SCRIPT_BACKEND_PRIV_H__
#define __GUM_QUICK_SCRIPT_BACKEND_PRIV_H__

#include "gumquickscriptbackend.h"

#include <quickjs.h>

G_BEGIN_DECLS

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
G_GNUC_INTERNAL gboolean gum_quick_script_backend_is_scope_mutex_trapped (
    GumQuickScriptBackend * self);
G_GNUC_INTERNAL void gum_quick_script_backend_mark_scope_mutex_trapped (
    GumQuickScriptBackend * self);

G_END_DECLS

#endif
