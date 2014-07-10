/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __FAKE_BACKTRACER_H__
#define __FAKE_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gum.h>

#define GUM_TYPE_FAKE_BACKTRACER (gum_fake_backtracer_get_type ())
#define GUM_FAKE_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_FAKE_BACKTRACER, GumFakeBacktracer))
#define GUM_FAKE_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_FAKE_BACKTRACER, GumFakeBacktracerClass))
#define GUM_IS_FAKE_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_FAKE_BACKTRACER))
#define GUM_IS_FAKE_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_FAKE_BACKTRACER))
#define GUM_FAKE_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_FAKE_BACKTRACER, GumFakeBacktracerClass))

typedef struct _GumFakeBacktracer GumFakeBacktracer;
typedef struct _GumFakeBacktracerClass GumFakeBacktracerClass;

struct _GumFakeBacktracer
{
  GObject parent;

  const GumReturnAddress * ret_addrs;
  guint num_ret_addrs;
};

struct _GumFakeBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_fake_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_fake_backtracer_new (const GumReturnAddress * ret_addrs,
    guint num_ret_addrs);

G_END_DECLS

#endif
