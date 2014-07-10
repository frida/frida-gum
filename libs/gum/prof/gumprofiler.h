/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROFILER_H__
#define __GUM_PROFILER_H__

#include "gumsampler.h"
#include "gumprofilereport.h"

#include <gum/guminvocationcontext.h>

#define GUM_TYPE_PROFILER (gum_profiler_get_type ())
#define GUM_PROFILER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_PROFILER, GumProfiler))
#define GUM_PROFILER_CAST(obj) ((GumProfiler *) (obj))
#define GUM_PROFILER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_PROFILER, GumProfilerClass))
#define GUM_IS_PROFILER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_PROFILER))
#define GUM_IS_PROFILER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_PROFILER))
#define GUM_PROFILER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_PROFILER, GumProfilerClass))

typedef struct _GumProfiler GumProfiler;
typedef struct _GumProfilerClass GumProfilerClass;

typedef struct _GumProfilerPrivate GumProfilerPrivate;

typedef enum
{
  GUM_INSTRUMENT_OK               =  0,
  GUM_INSTRUMENT_WRONG_SIGNATURE  = -1,
  GUM_INSTRUMENT_WAS_INSTRUMENTED = -2
} GumInstrumentReturn;

struct _GumProfiler
{
  GObject parent;

  GumProfilerPrivate * priv;
};

struct _GumProfilerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

typedef gboolean (* GumFunctionMatchFilterFunc) (const gchar * function_name,
    gpointer user_data);
typedef void (* GumWorstCaseInspectorFunc) (GumInvocationContext * context,
    gchar * output_buf, guint output_buf_len, gpointer user_data);

GUM_API GType gum_profiler_get_type (void) G_GNUC_CONST;

GUM_API GumProfiler * gum_profiler_new (void);

GUM_API void gum_profiler_instrument_functions_matching (GumProfiler * self,
    const gchar * match_str, GumSampler * sampler,
    GumFunctionMatchFilterFunc filter_func, gpointer user_data);
GUM_API GumInstrumentReturn gum_profiler_instrument_function (
    GumProfiler * self, gpointer function_address, GumSampler * sampler);
GUM_API GumInstrumentReturn gum_profiler_instrument_function_with_inspector (
    GumProfiler * self, gpointer function_address, GumSampler * sampler,
    GumWorstCaseInspectorFunc inspector_func, gpointer user_data);

GUM_API GumProfileReport * gum_profiler_generate_report (GumProfiler * self);

GUM_API guint gum_profiler_get_number_of_threads (GumProfiler * self);
GUM_API GumSample gum_profiler_get_total_duration_of (GumProfiler * self,
    guint thread_index, gpointer function_address);
GUM_API GumSample gum_profiler_get_worst_case_duration_of (GumProfiler * self,
    guint thread_index, gpointer function_address);
GUM_API const gchar * gum_profiler_get_worst_case_info_of (GumProfiler * self,
    guint thread_index, gpointer function_address);

G_END_DECLS

#endif
