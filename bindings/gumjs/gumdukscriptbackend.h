/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_SCRIPT_BACKEND_H__
#define __GUM_DUK_SCRIPT_BACKEND_H__

#include "gumscriptbackend.h"
#include "gumscriptscheduler.h"

#define GUM_DUK_TYPE_SCRIPT_BACKEND (gum_duk_script_backend_get_type ())
#define GUM_DUK_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_DUK_TYPE_SCRIPT_BACKEND, GumDukScriptBackend))
#define GUM_DUK_SCRIPT_BACKEND_CAST(obj) ((GumDukScriptBackend *) (obj))
#define GUM_DUK_SCRIPT_BACKEND_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_DUK_TYPE_SCRIPT_BACKEND, GumDukScriptBackendClass))
#define GUM_DUK_IS_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_DUK_TYPE_SCRIPT_BACKEND))
#define GUM_DUK_IS_SCRIPT_BACKEND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_DUK_TYPE_SCRIPT_BACKEND))
#define GUM_DUK_SCRIPT_BACKEND_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_DUK_TYPE_SCRIPT_BACKEND, GumDukScriptBackendClass))

typedef struct _GumDukScriptBackend GumDukScriptBackend;
typedef struct _GumDukScriptBackendClass GumDukScriptBackendClass;

typedef struct _GumDukScriptBackendPrivate GumDukScriptBackendPrivate;

struct _GumDukScriptBackend
{
  GObject parent;

  GumDukScriptBackendPrivate * priv;
};

struct _GumDukScriptBackendClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_duk_script_backend_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL gpointer gum_duk_script_backend_create_heap (
    GumDukScriptBackend * self);
G_GNUC_INTERNAL gboolean gum_duk_script_backend_push_program (
    GumDukScriptBackend * self, gpointer ctx, const gchar * name,
    const gchar * source, GError ** error);
G_GNUC_INTERNAL GumScriptScheduler * gum_duk_script_backend_get_scheduler (
    GumDukScriptBackend * self);

G_END_DECLS

#endif
