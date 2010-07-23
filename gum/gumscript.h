/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __GUM_SCRIPT_H__
#define __GUM_SCRIPT_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/guminvocationcontext.h>

#define GUM_TYPE_SCRIPT (gum_script_get_type ())
#define GUM_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_SCRIPT, GumScript))
#define GUM_SCRIPT_CAST(obj) ((GumScript *) (obj))
#define GUM_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_SCRIPT, GumScriptClass))
#define GUM_IS_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_SCRIPT))
#define GUM_IS_SCRIPT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_SCRIPT))
#define GUM_SCRIPT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_SCRIPT, GumScriptClass))

G_BEGIN_DECLS

typedef struct _GumScript           GumScript;
typedef struct _GumScriptClass      GumScriptClass;
typedef struct _GumScriptPrivate    GumScriptPrivate;

typedef void (* GumScriptMessageHandler) (GumScript * script, GVariant * msg,
    gpointer user_data);

struct _GumScript
{
  GObject parent;

  GumScriptPrivate * priv;
};

struct _GumScriptClass
{
  GObjectClass parent_class;
};

GUM_API GType gum_script_get_type (void) G_GNUC_CONST;

GUM_API GumScript * gum_script_from_string (const gchar * script_text,
    GError ** error);

GUM_API void gum_script_set_message_handler (GumScript * self,
    GumScriptMessageHandler func, gpointer data, GDestroyNotify notify);

GUM_API void gum_script_execute (GumScript * self, GumInvocationContext * ctx);

GUM_API gpointer gum_script_get_code_address (GumScript * self);
GUM_API guint gum_script_get_code_size (GumScript * self);

G_END_DECLS

#endif
