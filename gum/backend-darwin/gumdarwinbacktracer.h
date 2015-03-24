/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_BACKTRACER_H__
#define __GUM_DARWIN_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_DARWIN_BACKTRACER (gum_darwin_backtracer_get_type ())
#define GUM_DARWIN_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_DARWIN_BACKTRACER, GumDarwinBacktracer))
#define GUM_DARWIN_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_DARWIN_BACKTRACER, GumDarwinBacktracerClass))
#define GUM_IS_DARWIN_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_DARWIN_BACKTRACER))
#define GUM_IS_DARWIN_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_DARWIN_BACKTRACER))
#define GUM_DARWIN_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_DARWIN_BACKTRACER, GumDarwinBacktracerClass))

typedef struct _GumDarwinBacktracer GumDarwinBacktracer;
typedef struct _GumDarwinBacktracerClass GumDarwinBacktracerClass;

struct _GumDarwinBacktracer
{
  GObject parent;
};

struct _GumDarwinBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_darwin_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_darwin_backtracer_new (void);

G_END_DECLS

#endif
