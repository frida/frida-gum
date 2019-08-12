/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcallcountsampler.h"

#include "guminterceptor.h"
#include "gumsymbolutil.h"
#include "gumtls.h"

static void gum_call_count_sampler_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_call_count_sampler_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_call_count_sampler_dispose (GObject * object);
static void gum_call_count_sampler_finalize (GObject * object);

static GumSample gum_call_count_sampler_sample (GumSampler * sampler);

static void gum_call_count_sampler_on_enter (
    GumInvocationListener * listener, GumInvocationContext * context);
static void gum_call_count_sampler_on_leave (
    GumInvocationListener * listener, GumInvocationContext * context);

struct _GumCallCountSampler
{
  GObject parent;

  gboolean disposed;

  GumInterceptor * interceptor;

  volatile gint total_count;

  GumTlsKey tls_key;
  GMutex mutex;
  GSList * counters;
};

G_DEFINE_TYPE_EXTENDED (GumCallCountSampler,
                        gum_call_count_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                            gum_call_count_sampler_sampler_iface_init)
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_call_count_sampler_listener_iface_init))

static void
gum_call_count_sampler_class_init (GumCallCountSamplerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->dispose = gum_call_count_sampler_dispose;
  gobject_class->finalize = gum_call_count_sampler_finalize;
}

static void
gum_call_count_sampler_sampler_iface_init (gpointer g_iface,
                                           gpointer iface_data)
{
  GumSamplerInterface * iface = g_iface;

  iface->sample = gum_call_count_sampler_sample;
}

static void
gum_call_count_sampler_listener_iface_init (gpointer g_iface,
                                            gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_call_count_sampler_on_enter;
  iface->on_leave = gum_call_count_sampler_on_leave;
}

static void
gum_call_count_sampler_init (GumCallCountSampler * self)
{
  self->interceptor = gum_interceptor_obtain ();

  self->tls_key = gum_tls_key_new ();
  g_mutex_init (&self->mutex);
}

static void
gum_call_count_sampler_dispose (GObject * object)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_interceptor_detach_listener (self->interceptor,
        GUM_INVOCATION_LISTENER (self));
    g_object_unref (self->interceptor);
  }

  G_OBJECT_CLASS (gum_call_count_sampler_parent_class)->dispose (object);
}

static void
gum_call_count_sampler_finalize (GObject * object)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER (object);

  gum_tls_key_free (self->tls_key);
  g_mutex_clear (&self->mutex);

  g_slist_foreach (self->counters, (GFunc) g_free, NULL);
  g_slist_free (self->counters);

  G_OBJECT_CLASS (gum_call_count_sampler_parent_class)->finalize (object);
}

GumSampler *
gum_call_count_sampler_new (gpointer first_function,
                            ...)
{
  GumSampler * sampler;
  va_list args;

  va_start (args, first_function);
  sampler = gum_call_count_sampler_new_valist (first_function, args);
  va_end (args);

  return sampler;
}

GumSampler *
gum_call_count_sampler_new_valist (gpointer first_function,
                                   va_list args)
{
  GumCallCountSampler * sampler;
  GumInterceptor * interceptor;
  gpointer function;

  if (first_function == NULL)
    return g_object_new (GUM_TYPE_CALL_COUNT_SAMPLER, NULL);

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  sampler = g_object_new (GUM_TYPE_CALL_COUNT_SAMPLER, NULL);

  for (function = first_function;
      function != NULL;
      function = va_arg (args, gpointer))
  {
    gum_call_count_sampler_add_function (sampler, function);
  }

  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);

  return GUM_SAMPLER (sampler);
}

GumSampler *
gum_call_count_sampler_new_by_name (const gchar * first_function_name,
                                    ...)
{
  GumSampler * sampler;
  va_list args;

  va_start (args, first_function_name);
  sampler = gum_call_count_sampler_new_by_name_valist (first_function_name,
      args);
  va_end (args);

  return sampler;
}

GumSampler *
gum_call_count_sampler_new_by_name_valist (const gchar * first_function_name,
                                           va_list args)
{
  GumInterceptor * interceptor;
  const gchar * function_name;
  GumCallCountSampler * sampler;

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  sampler = g_object_new (GUM_TYPE_CALL_COUNT_SAMPLER, NULL);

  for (function_name = first_function_name; function_name != NULL;
      function_name = va_arg (args, const gchar *))
  {
    gpointer address;

    address = gum_find_function (function_name);
    g_assert (address != NULL);

    gum_call_count_sampler_add_function (sampler, address);
  }

  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);

  return GUM_SAMPLER (sampler);
}

void
gum_call_count_sampler_add_function (GumCallCountSampler * self,
                                     gpointer function)
{
  gum_interceptor_attach_listener (self->interceptor, function,
      GUM_INVOCATION_LISTENER (self), NULL);
}

GumSample
gum_call_count_sampler_peek_total_count (GumCallCountSampler * self)
{
  return g_atomic_int_get (&self->total_count);
}

static GumSample
gum_call_count_sampler_sample (GumSampler * sampler)
{
  GumCallCountSampler * self;
  GumSample * counter;

  self = GUM_CALL_COUNT_SAMPLER (sampler);

  counter = (GumSample *) gum_tls_key_get_value (self->tls_key);
  if (counter != NULL)
    return *counter;
  else
    return 0;
}

static void
gum_call_count_sampler_on_enter (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  GumCallCountSampler * self;
  GumSample * counter;

  self = GUM_CALL_COUNT_SAMPLER (listener);

  gum_interceptor_ignore_current_thread (self->interceptor);

  counter = (GumSample *) gum_tls_key_get_value (self->tls_key);
  if (counter == NULL)
  {
    counter = g_new0 (GumSample, 1);

    g_mutex_lock (&self->mutex);
    self->counters = g_slist_prepend (self->counters, counter);
    g_mutex_unlock (&self->mutex);

    gum_tls_key_set_value (self->tls_key, counter);
  }

  g_atomic_int_inc (&self->total_count);
  (*counter)++;
}

static void
gum_call_count_sampler_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER (listener);

  gum_interceptor_unignore_current_thread (self->interceptor);
}
