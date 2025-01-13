/*
 * Copyright (C) 2020-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_SCRIPT_PRIV_H__
#define __GUM_QUICK_SCRIPT_PRIV_H__

#include "gumquickscript.h"

#include <quickjs.h>

G_BEGIN_DECLS

typedef guint GumScriptState;
typedef struct _GumQuickWorker GumQuickWorker;

enum _GumScriptState
{
  GUM_SCRIPT_STATE_CREATED,
  GUM_SCRIPT_STATE_LOADING,
  GUM_SCRIPT_STATE_LOADED,
  GUM_SCRIPT_STATE_UNLOADING,
  GUM_SCRIPT_STATE_UNLOADED
};

G_GNUC_INTERNAL GumScriptState _gum_quick_script_get_state (
    GumQuickScript * self);

G_GNUC_INTERNAL GumQuickWorker * _gum_quick_script_make_worker (
    GumQuickScript * self, const gchar * url, JSValue on_message);
G_GNUC_INTERNAL GumQuickWorker * _gum_quick_worker_ref (
    GumQuickWorker * worker);
G_GNUC_INTERNAL void _gum_quick_worker_unref (GumQuickWorker * worker);
G_GNUC_INTERNAL void _gum_quick_worker_terminate (GumQuickWorker * self);
G_GNUC_INTERNAL void _gum_quick_worker_post (GumQuickWorker * self,
    const gchar * message, GBytes * data);

G_GNUC_INTERNAL JSValue _gum_quick_script_rethrow_parse_error_with_decorations (
    GumQuickScript * self, JSContext * ctx, const gchar * name);

G_GNUC_INTERNAL void _gum_quick_panic (JSContext * ctx, const gchar * prefix);

G_END_DECLS

#endif
