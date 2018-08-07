/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_SCRIPT_BACKEND_H__
#define __GUM_DUK_SCRIPT_BACKEND_H__

#include "gumscriptbackend.h"
#include "gumscriptscheduler.h"

G_BEGIN_DECLS

#define GUM_DUK_TYPE_SCRIPT_BACKEND (gum_duk_script_backend_get_type ())
G_DECLARE_FINAL_TYPE (GumDukScriptBackend, gum_duk_script_backend, GUM_DUK,
    SCRIPT_BACKEND, GObject)

G_GNUC_INTERNAL gpointer gum_duk_script_backend_create_heap (
    GumDukScriptBackend * self);
G_GNUC_INTERNAL gboolean gum_duk_script_backend_push_program (
    GumDukScriptBackend * self, gpointer ctx, const gchar * name,
    const gchar * source, GError ** error);
G_GNUC_INTERNAL GumScriptScheduler * gum_duk_script_backend_get_scheduler (
    GumDukScriptBackend * self);

G_END_DECLS

#endif
