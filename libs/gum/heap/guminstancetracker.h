/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INSTANCE_TRACKER_H__
#define __GUM_INSTANCE_TRACKER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

#define GUM_TYPE_INSTANCE_TRACKER (gum_instance_tracker_get_type ())
#define GUM_INSTANCE_TRACKER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_INSTANCE_TRACKER, GumInstanceTracker))
#define GUM_INSTANCE_TRACKER_CAST(obj) ((GumInstanceTracker *) (obj))
#define GUM_INSTANCE_TRACKER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_INSTANCE_TRACKER, GumInstanceTrackerClass))
#define GUM_IS_INSTANCE_TRACKER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_INSTANCE_TRACKER))
#define GUM_IS_INSTANCE_TRACKER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_INSTANCE_TRACKER))
#define GUM_INSTANCE_TRACKER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_INSTANCE_TRACKER, GumInstanceTrackerClass))

typedef struct _GumInstanceTracker GumInstanceTracker;
typedef struct _GumInstanceTrackerClass GumInstanceTrackerClass;
typedef struct _GumInstanceTrackerPrivate GumInstanceTrackerPrivate;
typedef struct _GumInstanceVTable GumInstanceVTable;
typedef struct _GumInstanceDetails GumInstanceDetails;

typedef gboolean (* GumFilterInstanceTypeFunc) (
    GumInstanceTracker * tracker, GType gtype, gpointer user_data);
typedef void (* GumWalkInstanceFunc) (GumInstanceDetails * id,
    gpointer user_data);

struct _GumInstanceTracker
{
  GObject parent;

  GumInstanceTrackerPrivate * priv;
};

struct _GumInstanceTrackerClass
{
  GObjectClass parent_class;
};

struct _GumInstanceVTable
{
  GTypeInstance * (* create_instance) (GType type);
  void (* free_instance) (GTypeInstance * instance);

  G_CONST_RETURN gchar * (* type_id_to_name) (GType type);
};

struct _GumInstanceDetails
{
  gconstpointer address;
  guint ref_count;
  const gchar * type_name;
};

G_BEGIN_DECLS

GUM_API GType gum_instance_tracker_get_type (void) G_GNUC_CONST;

GUM_API GumInstanceTracker * gum_instance_tracker_new (void);

GUM_API void gum_instance_tracker_begin (GumInstanceTracker * self,
    GumInstanceVTable * vtable);
GUM_API void gum_instance_tracker_end (GumInstanceTracker * self);

GUM_API const GumInstanceVTable * gum_instance_tracker_get_current_vtable (
    GumInstanceTracker * self);

GUM_API void gum_instance_tracker_set_type_filter_function (
    GumInstanceTracker * self, GumFilterInstanceTypeFunc filter,
    gpointer user_data);

GUM_API guint gum_instance_tracker_peek_total_count (GumInstanceTracker * self,
    const gchar * type_name);
GUM_API GList * gum_instance_tracker_peek_instances (GumInstanceTracker * self);
GUM_API void gum_instance_tracker_walk_instances (GumInstanceTracker * self,
    GumWalkInstanceFunc func, gpointer user_data);

/*< Internal API */
void gum_instance_tracker_add_instance (GumInstanceTracker * self,
    gpointer instance, GType instance_type);
void gum_instance_tracker_remove_instance (GumInstanceTracker * self,
    gpointer instance, GType instance_type);

G_END_DECLS

#endif
