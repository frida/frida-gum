/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_COBJECT_TRACKER_H__
#define __GUM_COBJECT_TRACKER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>
#include <gum/gumlist.h>

#define GUM_TYPE_COBJECT_TRACKER (gum_cobject_tracker_get_type ())
#define GUM_COBJECT_TRACKER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_COBJECT_TRACKER, GumCObjectTracker))
#define GUM_COBJECT_TRACKER_CAST(obj) ((GumCObjectTracker *) (obj))
#define GUM_COBJECT_TRACKER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_COBJECT_TRACKER, GumCObjectTrackerClass))
#define GUM_IS_COBJECT_TRACKER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_COBJECT_TRACKER))
#define GUM_IS_COBJECT_TRACKER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_COBJECT_TRACKER))
#define GUM_COBJECT_TRACKER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_COBJECT_TRACKER, GumCObjectTrackerClass))

typedef struct _GumCObjectTracker GumCObjectTracker;
typedef struct _GumCObjectTrackerClass GumCObjectTrackerClass;

typedef struct _GumCObjectTrackerPrivate GumCObjectTrackerPrivate;

struct _GumCObjectTracker
{
  GObject parent;

  GumCObjectTrackerPrivate * priv;
};

struct _GumCObjectTrackerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_cobject_tracker_get_type (void) G_GNUC_CONST;

GUM_API GumCObjectTracker * gum_cobject_tracker_new (void);
GUM_API GumCObjectTracker * gum_cobject_tracker_new_with_backtracer (
    GumBacktracer * backtracer);

GUM_API void gum_cobject_tracker_track (GumCObjectTracker * self,
    const gchar * type_name, gpointer type_constructor);

GUM_API void gum_cobject_tracker_begin (GumCObjectTracker * self);
GUM_API void gum_cobject_tracker_end (GumCObjectTracker * self);

GUM_API guint gum_cobject_tracker_peek_total_count (GumCObjectTracker * self,
    const gchar * type_name);
GUM_API GumList * gum_cobject_tracker_peek_object_list (
    GumCObjectTracker * self);

G_END_DECLS

#endif
