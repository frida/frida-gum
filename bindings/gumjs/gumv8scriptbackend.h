/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_SCRIPT_BACKEND_H__
#define __GUM_V8_SCRIPT_BACKEND_H__

#include "gumscriptbackend.h"
#include "gumscriptscheduler.h"

#define GUM_V8_TYPE_SCRIPT_BACKEND (gum_v8_script_backend_get_type ())
#define GUM_V8_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_V8_TYPE_SCRIPT_BACKEND, GumV8ScriptBackend))
#define GUM_V8_SCRIPT_BACKEND_CAST(obj) ((GumV8ScriptBackend *) (obj))
#define GUM_V8_SCRIPT_BACKEND_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_V8_TYPE_SCRIPT_BACKEND, GumV8ScriptBackendClass))
#define GUM_V8_IS_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_V8_TYPE_SCRIPT_BACKEND))
#define GUM_V8_IS_SCRIPT_BACKEND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_V8_TYPE_SCRIPT_BACKEND))
#define GUM_V8_SCRIPT_BACKEND_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_V8_TYPE_SCRIPT_BACKEND, GumV8ScriptBackendClass))

typedef struct _GumV8ScriptBackend GumV8ScriptBackend;
typedef struct _GumV8ScriptBackendClass GumV8ScriptBackendClass;

typedef struct _GumV8ScriptBackendPrivate GumV8ScriptBackendPrivate;

struct _GumV8ScriptBackend
{
  GObject parent;

  GumV8ScriptBackendPrivate * priv;
};

struct _GumV8ScriptBackendClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_v8_script_backend_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL gpointer gum_v8_script_backend_get_platform (
    GumV8ScriptBackend * self);
G_GNUC_INTERNAL gpointer gum_v8_script_backend_get_isolate (
    GumV8ScriptBackend * self);
G_GNUC_INTERNAL GumScriptScheduler * gum_v8_script_backend_get_scheduler (
    GumV8ScriptBackend * self);

G_END_DECLS

#endif
