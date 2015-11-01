/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSC_SCRIPT_BACKEND_H__
#define __GUM_JSC_SCRIPT_BACKEND_H__

#include "gumscriptbackend.h"
#include "gumscriptscheduler.h"

#define GUM_JSC_TYPE_SCRIPT_BACKEND (gum_jsc_script_backend_get_type ())
#define GUM_JSC_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_JSC_TYPE_SCRIPT_BACKEND, GumJscScriptBackend))
#define GUM_JSC_SCRIPT_BACKEND_CAST(obj) ((GumJscScriptBackend *) (obj))
#define GUM_JSC_SCRIPT_BACKEND_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_JSC_TYPE_SCRIPT_BACKEND, GumJscScriptBackendClass))
#define GUM_JSC_IS_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_JSC_TYPE_SCRIPT_BACKEND))
#define GUM_JSC_IS_SCRIPT_BACKEND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_JSC_TYPE_SCRIPT_BACKEND))
#define GUM_JSC_SCRIPT_BACKEND_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_JSC_TYPE_SCRIPT_BACKEND, GumJscScriptBackendClass))

typedef struct _GumJscScriptBackend GumJscScriptBackend;
typedef struct _GumJscScriptBackendClass GumJscScriptBackendClass;

typedef struct _GumJscScriptBackendPrivate GumJscScriptBackendPrivate;

struct _GumJscScriptBackend
{
  GObject parent;

  GumJscScriptBackendPrivate * priv;
};

struct _GumJscScriptBackendClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_jsc_script_backend_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL GumScriptScheduler * gum_jsc_script_backend_get_scheduler (
    GumJscScriptBackend * self);

G_END_DECLS

#endif
