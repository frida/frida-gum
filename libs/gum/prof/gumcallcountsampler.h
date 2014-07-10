/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CALL_COUNT_SAMPLER_H__
#define __GUM_CALL_COUNT_SAMPLER_H__

#include "gumsampler.h"

#define GUM_TYPE_CALL_COUNT_SAMPLER (gum_call_count_sampler_get_type ())
#define GUM_CALL_COUNT_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_CALL_COUNT_SAMPLER, GumCallCountSampler))
#define GUM_CALL_COUNT_SAMPLER_CAST(obj) ((GumCallCountSampler *) (obj))
#define GUM_CALL_COUNT_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_CALL_COUNT_SAMPLER, GumCallCountSamplerClass))
#define GUM_IS_CALL_COUNT_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_CALL_COUNT_SAMPLER))
#define GUM_IS_CALL_COUNT_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_CALL_COUNT_SAMPLER))
#define GUM_CALL_COUNT_SAMPLER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_CALL_COUNT_SAMPLER, GumCallCountSamplerClass))

typedef struct _GumCallCountSampler GumCallCountSampler;
typedef struct _GumCallCountSamplerClass GumCallCountSamplerClass;

typedef struct _GumCallCountSamplerPrivate GumCallCountSamplerPrivate;

struct _GumCallCountSampler
{
  GObject parent;

  GumCallCountSamplerPrivate * priv;
};

struct _GumCallCountSamplerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_call_count_sampler_get_type (void) G_GNUC_CONST;

GUM_API GumSampler * gum_call_count_sampler_new (gpointer first_function, ...);
GUM_API GumSampler * gum_call_count_sampler_new_valist (gpointer first_function,
    va_list var_args);
GUM_API GumSampler * gum_call_count_sampler_new_by_name (
    const gchar * first_function_name, ...);
GUM_API GumSampler * gum_call_count_sampler_new_by_name_valist (
    const gchar * first_function_name, va_list var_args);

GUM_API void gum_call_count_sampler_add_function (GumCallCountSampler * self,
    gpointer function);

GUM_API GumSample gum_call_count_sampler_peek_total_count (
    GumCallCountSampler * self);

G_END_DECLS

#endif
