/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

struct _GumCallCountSamplerPrivate
{
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

  g_type_class_add_private (klass, sizeof (GumCallCountSamplerPrivate));

  gobject_class->dispose = gum_call_count_sampler_dispose;
  gobject_class->finalize = gum_call_count_sampler_finalize;
}

static void
gum_call_count_sampler_sampler_iface_init (gpointer g_iface,
                                           gpointer iface_data)
{
  GumSamplerIface * iface = (GumSamplerIface *) g_iface;

  (void) iface_data;

  iface->sample = gum_call_count_sampler_sample;
}

static void
gum_call_count_sampler_listener_iface_init (gpointer g_iface,
                                            gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_call_count_sampler_on_enter;
  iface->on_leave = gum_call_count_sampler_on_leave;
}

static void
gum_call_count_sampler_init (GumCallCountSampler * self)
{
  GumCallCountSamplerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_CALL_COUNT_SAMPLER, GumCallCountSamplerPrivate);
  priv = self->priv;

  priv->interceptor = gum_interceptor_obtain ();

  priv->tls_key = gum_tls_key_new ();
  g_mutex_init (&priv->mutex);
}

static void
gum_call_count_sampler_dispose (GObject * object)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER (object);
  GumCallCountSamplerPrivate * priv = self->priv;

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    gum_interceptor_detach_listener (priv->interceptor,
        GUM_INVOCATION_LISTENER (self));
    g_object_unref (priv->interceptor);
  }

  G_OBJECT_CLASS (gum_call_count_sampler_parent_class)->dispose (object);
}

static void
gum_call_count_sampler_finalize (GObject * object)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER (object);
  GumCallCountSamplerPrivate * priv = self->priv;

  gum_tls_key_free (priv->tls_key);
  g_mutex_clear (&priv->mutex);

  g_slist_foreach (priv->counters, (GFunc) g_free, NULL);
  g_slist_free (priv->counters);

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
                                   va_list var_args)
{
  GumInterceptor * interceptor;
  GumCallCountSampler * sampler;
  gpointer function;

  g_assert (first_function != NULL);

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  sampler = GUM_CALL_COUNT_SAMPLER (
      g_object_new (GUM_TYPE_CALL_COUNT_SAMPLER, NULL));

  for (function = first_function; function != NULL;
      function = va_arg (var_args, gpointer))
  {
    gum_call_count_sampler_add_function (sampler, function);
  }

  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);

  return GUM_SAMPLER_CAST (sampler);
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
                                           va_list var_args)
{
  GumInterceptor * interceptor;
  const gchar * function_name;
  GumCallCountSampler * sampler;

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  sampler = GUM_CALL_COUNT_SAMPLER (
      g_object_new (GUM_TYPE_CALL_COUNT_SAMPLER, NULL));

  for (function_name = first_function_name; function_name != NULL;
      function_name = va_arg (var_args, const gchar *))
  {
    gpointer address = gum_find_function (function_name);
    g_assert (address != NULL);

    gum_call_count_sampler_add_function (sampler, address);
  }

  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);

  return GUM_SAMPLER_CAST (sampler);
}

void
gum_call_count_sampler_add_function (GumCallCountSampler * self,
                                     gpointer function)
{
  GumCallCountSamplerPrivate * priv = self->priv;
  GumAttachReturn attach_ret;

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      function, GUM_INVOCATION_LISTENER (self), NULL);
  g_assert (attach_ret == GUM_ATTACH_OK);
}

GumSample
gum_call_count_sampler_peek_total_count (GumCallCountSampler * self)
{
  return g_atomic_int_get (&self->priv->total_count);
}

static GumSample
gum_call_count_sampler_sample (GumSampler * sampler)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER_CAST (sampler);
  GumSample * counter;

  counter = (GumSample *) gum_tls_key_get_value (self->priv->tls_key);
  if (counter != NULL)
    return *counter;
  else
    return 0;
}

static void
gum_call_count_sampler_on_enter (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER_CAST (listener);
  GumCallCountSamplerPrivate * priv = self->priv;
  GumSample * counter;

  (void) context;

  gum_interceptor_ignore_current_thread (priv->interceptor);

  counter = (GumSample *) gum_tls_key_get_value (priv->tls_key);
  if (counter == NULL)
  {
    counter = g_new0 (GumSample, 1);

    g_mutex_lock (&priv->mutex);
    priv->counters = g_slist_prepend (priv->counters, counter);
    g_mutex_unlock (&priv->mutex);

    gum_tls_key_set_value (priv->tls_key, counter);
  }

  g_atomic_int_inc (&priv->total_count);
  (*counter)++;
}

static void
gum_call_count_sampler_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER_CAST (listener);

  (void) context;

  gum_interceptor_unignore_current_thread (self->priv->interceptor);
}
