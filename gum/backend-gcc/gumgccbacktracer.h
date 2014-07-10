/*
 * Copyright (C) 2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_GCC_BACKTRACER_H__
#define __GUM_GCC_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_GCC_BACKTRACER (gum_gcc_backtracer_get_type ())
#define GUM_GCC_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_GCC_BACKTRACER, GumGccBacktracer))
#define GUM_GCC_BACKTRACER_CAST(obj) ((GumGccBacktracer *) (obj))
#define GUM_GCC_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_GCC_BACKTRACER, GumGccBacktracerClass))
#define GUM_IS_GCC_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_GCC_BACKTRACER))
#define GUM_IS_GCC_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_GCC_BACKTRACER))
#define GUM_GCC_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_GCC_BACKTRACER, GumGccBacktracerClass))

typedef struct _GumGccBacktracer GumGccBacktracer;
typedef struct _GumGccBacktracerClass GumGccBacktracerClass;

typedef struct _GumGccBacktracerPrivate GumGccBacktracerPrivate;

struct _GumGccBacktracer
{
  GObject parent;
};

struct _GumGccBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_gcc_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_gcc_backtracer_new (void);

G_END_DECLS

#endif
