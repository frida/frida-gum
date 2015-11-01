/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSC_SCRIPT_H__
#define __GUM_JSC_SCRIPT_H__

#include "gumscript.h"

#define GUM_JSC_TYPE_SCRIPT (gum_jsc_script_get_type ())
#define GUM_JSC_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_JSC_TYPE_SCRIPT, GumJscScript))
#define GUM_JSC_SCRIPT_CAST(obj) ((GumJscScript *) (obj))
#define GUM_JSC_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_JSC_TYPE_SCRIPT, GumJscScriptClass))
#define GUM_JSC_IS_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_JSC_TYPE_SCRIPT))
#define GUM_JSC_IS_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_JSC_TYPE_SCRIPT))
#define GUM_JSC_SCRIPT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_JSC_TYPE_SCRIPT, GumJscScriptClass))

typedef struct _GumJscScript GumJscScript;
typedef struct _GumJscScriptClass GumJscScriptClass;

typedef struct _GumJscScriptPrivate GumJscScriptPrivate;

struct _GumJscScript
{
  GObject parent;

  GumJscScriptPrivate * priv;
};

struct _GumJscScriptClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_jsc_script_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL gboolean gum_jsc_script_create_context (GumJscScript * self,
    GError ** error);

G_END_DECLS

#endif
