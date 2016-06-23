/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MIPS_BACKTRACER_H__
#define __GUM_MIPS_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_MIPS_BACKTRACER (gum_mips_backtracer_get_type ())
#define GUM_MIPS_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_MIPS_BACKTRACER, GumMipsBacktracer))
#define GUM_MIPS_BACKTRACER_CAST(obj) ((GumMipsBacktracer *) (obj))
#define GUM_MIPS_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_MIPS_BACKTRACER, GumMipsBacktracerClass))
#define GUM_IS_MIPS_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_MIPS_BACKTRACER))
#define GUM_IS_MIPS_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_MIPS_BACKTRACER))
#define GUM_MIPS_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_MIPS_BACKTRACER, GumMipsBacktracerClass))

typedef struct _GumMipsBacktracer GumMipsBacktracer;
typedef struct _GumMipsBacktracerClass GumMipsBacktracerClass;

typedef struct _GumMipsBacktracerPrivate GumMipsBacktracerPrivate;

struct _GumMipsBacktracer
{
  GObject parent;

  GumMipsBacktracerPrivate * priv;
};

struct _GumMipsBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_mips_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_mips_backtracer_new (void);

G_END_DECLS

#endif
