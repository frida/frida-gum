/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM64_BACKTRACER_H__
#define __GUM_ARM64_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_ARM64_BACKTRACER (gum_arm64_backtracer_get_type ())
#define GUM_ARM64_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_ARM64_BACKTRACER, GumArm64Backtracer))
#define GUM_ARM64_BACKTRACER_CAST(obj) ((GumArm64Backtracer *) (obj))
#define GUM_ARM64_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_ARM64_BACKTRACER, GumArm64BacktracerClass))
#define GUM_IS_ARM64_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_ARM64_BACKTRACER))
#define GUM_IS_ARM64_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_ARM64_BACKTRACER))
#define GUM_ARM64_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_ARM64_BACKTRACER, GumArm64BacktracerClass))

typedef struct _GumArm64Backtracer GumArm64Backtracer;
typedef struct _GumArm64BacktracerClass GumArm64BacktracerClass;

typedef struct _GumArm64BacktracerPrivate GumArm64BacktracerPrivate;

struct _GumArm64Backtracer
{
  GObject parent;

  GumArm64BacktracerPrivate * priv;
};

struct _GumArm64BacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_arm64_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_arm64_backtracer_new (void);

G_END_DECLS

#endif
