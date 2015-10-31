/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_SCRIPT_H__
#define __GUM_V8_SCRIPT_H__

#include <gio/gio.h>

#define GUM_V8_TYPE_SCRIPT (gum_v8_script_get_type ())
#define GUM_V8_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_V8_TYPE_SCRIPT, GumV8Script))
#define GUM_V8_SCRIPT_CAST(obj) ((GumV8Script *) (obj))
#define GUM_V8_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_V8_TYPE_SCRIPT, GumV8ScriptClass))
#define GUM_IS_V8_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_V8_TYPE_SCRIPT))
#define GUM_IS_V8_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_V8_TYPE_SCRIPT))
#define GUM_V8_SCRIPT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_V8_TYPE_SCRIPT, GumV8ScriptClass))

typedef struct _GumV8Script GumV8Script;
typedef struct _GumV8ScriptClass GumV8ScriptClass;

typedef struct _GumV8ScriptPrivate GumV8ScriptPrivate;

struct _GumV8Script
{
  GObject parent;

  GumV8ScriptPrivate * priv;
};

struct _GumV8ScriptClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_v8_script_get_type (void) G_GNUC_CONST;

gboolean gum_v8_script_create_context (GumV8Script * self, GError ** error);

G_END_DECLS

#endif
