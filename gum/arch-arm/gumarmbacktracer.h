/*
 * Copyright (C) 2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM_BACKTRACER_H__
#define __GUM_ARM_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_ARM_BACKTRACER (gum_arm_backtracer_get_type ())
#define GUM_ARM_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_ARM_BACKTRACER, GumArmBacktracer))
#define GUM_ARM_BACKTRACER_CAST(obj) ((GumArmBacktracer *) (obj))
#define GUM_ARM_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_ARM_BACKTRACER, GumArmBacktracerClass))
#define GUM_IS_ARM_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_ARM_BACKTRACER))
#define GUM_IS_ARM_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_ARM_BACKTRACER))
#define GUM_ARM_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_ARM_BACKTRACER, GumArmBacktracerClass))

typedef struct _GumArmBacktracer GumArmBacktracer;
typedef struct _GumArmBacktracerClass GumArmBacktracerClass;

typedef struct _GumArmBacktracerPrivate GumArmBacktracerPrivate;

struct _GumArmBacktracer
{
  GObject parent;

  GumArmBacktracerPrivate * priv;
};

struct _GumArmBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_arm_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_arm_backtracer_new (void);

G_END_DECLS

#endif
