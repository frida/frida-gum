/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_SCRIPT_H__
#define __GUM_DUK_SCRIPT_H__

#include "gumscript.h"

#define GUM_DUK_TYPE_SCRIPT (gum_duk_script_get_type ())
#define GUM_DUK_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_DUK_TYPE_SCRIPT, GumDukScript))
#define GUM_DUK_SCRIPT_CAST(obj) ((GumDukScript *) (obj))
#define GUM_DUK_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_DUK_TYPE_SCRIPT, GumDukScriptClass))
#define GUM_DUK_IS_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_DUK_TYPE_SCRIPT))
#define GUM_DUK_IS_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_DUK_TYPE_SCRIPT))
#define GUM_DUK_SCRIPT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_DUK_TYPE_SCRIPT, GumDukScriptClass))

typedef struct _GumDukScript GumDukScript;
typedef struct _GumDukScriptClass GumDukScriptClass;

typedef struct _GumDukScriptPrivate GumDukScriptPrivate;

struct _GumDukScript
{
  GObject parent;

  GumDukScriptPrivate * priv;
};

struct _GumDukScriptClass
{
  GObjectClass parent_class;

  void (* debugger_detached) (GumDukScript * script);
  void (* debugger_output) (GumDukScript * script, GBytes * bytes);
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_duk_script_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL gboolean gum_duk_script_create_context (GumDukScript * self,
    GError ** error);

G_GNUC_INTERNAL void gum_duk_script_attach_debugger (GumDukScript * self);
G_GNUC_INTERNAL void gum_duk_script_detach_debugger (GumDukScript * self);
G_GNUC_INTERNAL void gum_duk_script_post_to_debugger (GumDukScript * self,
    GBytes * bytes);

G_END_DECLS

#endif
