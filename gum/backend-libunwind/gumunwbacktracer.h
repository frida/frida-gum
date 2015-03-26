/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_UNW_BACKTRACER_H__
#define __GUM_UNW_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_UNW_BACKTRACER (gum_unw_backtracer_get_type ())
#define GUM_UNW_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_UNW_BACKTRACER, GumUnwBacktracer))
#define GUM_UNW_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_UNW_BACKTRACER, GumUnwBacktracerClass))
#define GUM_IS_UNW_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_UNW_BACKTRACER))
#define GUM_IS_UNW_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_UNW_BACKTRACER))
#define GUM_UNW_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_UNW_BACKTRACER, GumUnwBacktracerClass))

typedef struct _GumUnwBacktracer GumUnwBacktracer;
typedef struct _GumUnwBacktracerClass GumUnwBacktracerClass;

struct _GumUnwBacktracer
{
  GObject parent;
};

struct _GumUnwBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_unw_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_unw_backtracer_new (void);

G_END_DECLS

#endif
