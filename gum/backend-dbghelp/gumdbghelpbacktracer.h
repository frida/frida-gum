/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DBGHELP_BACKTRACER_H__
#define __GUM_DBGHELP_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gum.h>

#define GUM_TYPE_DBGHELP_BACKTRACER (gum_dbghelp_backtracer_get_type ())
#define GUM_DBGHELP_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_DBGHELP_BACKTRACER, GumDbghelpBacktracer))
#define GUM_DBGHELP_BACKTRACER_CAST(obj) ((GumDbghelpBacktracer *) (obj))
#define GUM_DBGHELP_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_DBGHELP_BACKTRACER, GumDbghelpBacktracerClass))
#define GUM_IS_DBGHELP_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_DBGHELP_BACKTRACER))
#define GUM_IS_DBGHELP_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_DBGHELP_BACKTRACER))
#define GUM_DBGHELP_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_DBGHELP_BACKTRACER, GumDbghelpBacktracerClass))

typedef struct _GumDbghelpBacktracer GumDbghelpBacktracer;
typedef struct _GumDbghelpBacktracerClass GumDbghelpBacktracerClass;
typedef struct _GumDbghelpBacktracerPrivate GumDbghelpBacktracerPrivate;

struct _GumDbghelpBacktracer
{
  GObject parent;

  GumDbghelpBacktracerPrivate * priv;
};

struct _GumDbghelpBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_dbghelp_backtracer_get_type (void) G_GNUC_CONST;

GUM_API GumBacktracer * gum_dbghelp_backtracer_new (void);

G_END_DECLS

#endif
