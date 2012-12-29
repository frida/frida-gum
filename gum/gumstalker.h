/*
 * Copyright (C) 2009-2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C)      2010 Karl Trygve Kalleberg <karltk@boblycat.org>
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

#ifndef __GUM_STALKER_H__
#define __GUM_STALKER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/gumeventsink.h>

#define GUM_TYPE_STALKER (gum_stalker_get_type ())
#define GUM_STALKER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_STALKER, GumStalker))
#define GUM_STALKER_CAST(obj) ((GumStalker *) (obj))
#define GUM_STALKER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_STALKER, GumStalkerClass))
#define GUM_IS_STALKER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_STALKER))
#define GUM_IS_STALKER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_STALKER))
#define GUM_STALKER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_STALKER, GumStalkerClass))

G_BEGIN_DECLS

typedef struct _GumStalker           GumStalker;
typedef struct _GumStalkerClass      GumStalkerClass;
typedef struct _GumStalkerPrivate    GumStalkerPrivate;

typedef guint GumProbeId;
typedef struct _GumCallSite GumCallSite;
typedef void (* GumCallProbeCallback) (GumCallSite * site, gpointer user_data);

struct _GumStalker
{
  GObject parent;

  GumStalkerPrivate * priv;
};

struct _GumStalkerClass
{
  GObjectClass parent_class;
};

struct _GumCallSite
{
  gpointer block_address;
  gpointer stack_data;
  GumCpuContext * cpu_context;
};

GUM_API GType gum_stalker_get_type (void) G_GNUC_CONST;

GUM_API GumStalker * gum_stalker_new (void);

GUM_API void gum_stalker_follow_me (GumStalker * self, GumEventSink * sink);
GUM_API void gum_stalker_unfollow_me (GumStalker * self);
GUM_API gboolean gum_stalker_is_following_me (GumStalker * self);

GUM_API GumProbeId gum_stalker_add_call_probe (GumStalker * self,
    gpointer target_address, GumCallProbeCallback callback, gpointer data);
GUM_API void gum_stalker_remove_call_probe (GumStalker * self,
    GumProbeId id);

G_END_DECLS

#endif
