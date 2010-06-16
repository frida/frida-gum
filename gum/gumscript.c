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

#include "gumscript.h"

#include <gio/gio.h> /* FIXME: piggy-backing on IOError for now */
#define VC_EXTRALEAN
#include <windows.h> /* To be removed */

struct _GumScriptPrivate
{
  guint foo;
};

#define GUM_SCRIPT_GET_PRIVATE(o) ((o)->priv)

static void gum_script_finalize (GObject * object);

G_DEFINE_TYPE (GumScript, gum_script, G_TYPE_OBJECT);

static void
gum_script_class_init (GumScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumScriptPrivate));

  object_class->finalize = gum_script_finalize;
}

static void
gum_script_init (GumScript * self)
{
  GumScriptPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_SCRIPT, GumScriptPrivate);
  priv = GUM_SCRIPT_GET_PRIVATE (self);
}

static void
gum_script_finalize (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);

  G_OBJECT_CLASS (gum_script_parent_class)->finalize (object);
}

GumScript *
gum_script_from_string (const gchar * str,
                        GError ** error)
{
  return GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT, NULL));
}

void
gum_script_execute (GumScript * self,
                    GumCpuContext * cpu_context,
                    void * stack_arguments)
{
  DWORD last_error;

  last_error = GetLastError ();
  MessageBeep (MB_ICONERROR);
  SetLastError (last_error);
}
