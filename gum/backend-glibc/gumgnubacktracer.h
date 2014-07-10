/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_GNU_BACKTRACER_H__
#define __GUM_GNU_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_GNU_BACKTRACER (gum_gnu_backtracer_get_type ())
#define GUM_GNU_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_GNU_BACKTRACER, GumGnuBacktracer))
#define GUM_GNU_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_GNU_BACKTRACER, GumGnuBacktracerClass))
#define GUM_IS_GNU_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_GNU_BACKTRACER))
#define GUM_IS_GNU_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_GNU_BACKTRACER))
#define GUM_GNU_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_GNU_BACKTRACER, GumGnuBacktracerClass))

typedef struct _GumGnuBacktracer GumGnuBacktracer;
typedef struct _GumGnuBacktracerClass GumGnuBacktracerClass;

struct _GumGnuBacktracer
{
  GObject parent;
};

struct _GumGnuBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_gnu_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_gnu_backtracer_new (void);

G_END_DECLS

#endif
