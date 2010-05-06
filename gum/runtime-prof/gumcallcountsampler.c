/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumcallcountsampler.h"
#include "guminterceptor.h"
#include "gumsymbolutil.h"

static void gum_call_count_sampler_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_call_count_sampler_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

static void gum_call_count_sampler_dispose (GObject * object);

static GumSample gum_call_count_sampler_sample (GumSampler * sampler);

static void gum_call_count_sampler_on_enter (
    GumInvocationListener * listener, GumInvocationContext * context,
    GumInvocationContext * parent_context, GumCpuContext * cpu_context,
    gpointer function_arguments);
static void gum_call_count_sampler_on_leave (
    GumInvocationListener * listener, GumInvocationContext * context,
    GumInvocationContext * parent_context, gpointer function_return_value);
static gpointer gum_call_count_sampler_provide_thread_data (
    GumInvocationListener * listener, gpointer function_instance_data,
    guint thread_id);

struct _GumCallCountSamplerPrivate
{
  gboolean disposed;
  GumInterceptor * interceptor;
  volatile gint total_count;
  GPrivate * tls_key;
};

#define GUM_CALL_COUNT_SAMPLER_GET_PRIVATE(o) ((o)->priv)

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
}

static void
gum_call_count_sampler_sampler_iface_init (gpointer g_iface,
                                             gpointer iface_data)
{
  GumSamplerIface * iface = (GumSamplerIface *) g_iface;

  iface->sample = gum_call_count_sampler_sample;
}

static void
gum_call_count_sampler_listener_iface_init (gpointer g_iface,
                                              gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = gum_call_count_sampler_on_enter;
  iface->on_leave = gum_call_count_sampler_on_leave;
  iface->provide_thread_data = gum_call_count_sampler_provide_thread_data;
}

static void
gum_call_count_sampler_init (GumCallCountSampler * self)
{
  GumCallCountSamplerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_CALL_COUNT_SAMPLER, GumCallCountSamplerPrivate);

  priv = GUM_CALL_COUNT_SAMPLER_GET_PRIVATE (self);

  priv->interceptor = gum_interceptor_obtain ();

  priv->tls_key = g_private_new (g_free);
}

static void
gum_call_count_sampler_dispose (GObject * object)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER (object);
  GumCallCountSamplerPrivate * priv =
      GUM_CALL_COUNT_SAMPLER_GET_PRIVATE (self);

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    gum_interceptor_detach_listener (priv->interceptor,
        GUM_INVOCATION_LISTENER (self));
    g_object_unref (priv->interceptor);
  }

  G_OBJECT_CLASS (gum_call_count_sampler_parent_class)->dispose (object);
}

GumSampler *
gum_call_count_sampler_new (gpointer first_function,
                            ...)
{
  GumCallCountSampler * sampler;
  va_list args;
  gpointer function;

  g_assert (first_function != NULL);

  sampler = g_object_new (GUM_TYPE_CALL_COUNT_SAMPLER, NULL);

  va_start (args, first_function);
  for (function = first_function; function != NULL;
      function = va_arg (args, gpointer))
  {
    gum_call_count_sampler_add_function (sampler, function);
  }

  return GUM_SAMPLER (sampler);
}

GumSampler *
gum_call_count_sampler_new_by_name (const gchar * first_function_name,
                                    ...)
{
  guint arg_count = 0, i;
  gpointer * addresses;
  va_list args;
  const gchar * function_name;
  GumCallCountSampler * sampler;

  va_start (args, first_function_name);
  for (function_name = first_function_name; function_name != NULL;
      function_name = va_arg (args, const gchar *))
  {
    arg_count++;
  }

  g_assert (arg_count > 0);
  addresses = alloca (arg_count * sizeof (gpointer));

  va_start (args, first_function_name);
  i = 0;
  for (function_name = first_function_name; function_name != NULL;
      function_name = va_arg (args, const gchar *))
  {
    addresses[i] = gum_find_function (function_name);
    g_assert (addresses[i] != NULL);

    i++;
  }

  sampler = g_object_new (GUM_TYPE_CALL_COUNT_SAMPLER, NULL);
  for (i = 0; i < arg_count; i++)
    gum_call_count_sampler_add_function (sampler, addresses[i]);

  return GUM_SAMPLER (sampler);
}

void
gum_call_count_sampler_add_function (GumCallCountSampler * self,
                                     gpointer function)
{
  GumCallCountSamplerPrivate * priv =
      GUM_CALL_COUNT_SAMPLER_GET_PRIVATE (self);
  GumAttachReturn attach_ret;

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      function, GUM_INVOCATION_LISTENER (self), NULL);
  g_assert (attach_ret == GUM_ATTACH_OK);
}

GumSample
gum_call_count_sampler_peek_total_count (GumCallCountSampler * self)
{
  GumCallCountSamplerPrivate * priv =
      GUM_CALL_COUNT_SAMPLER_GET_PRIVATE (self);

  return g_atomic_int_get (&priv->total_count);
}

static GumSample
gum_call_count_sampler_sample (GumSampler * sampler)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER_CAST (sampler);
  GumCallCountSamplerPrivate * priv =
      GUM_CALL_COUNT_SAMPLER_GET_PRIVATE (self);
  GumSample * counter;

  counter = g_private_get (priv->tls_key);
  if (counter != NULL)
    return *counter;
  else
    return 0;
}

static void
gum_call_count_sampler_on_enter (GumInvocationListener * listener,
                                 GumInvocationContext * context,
                                 GumInvocationContext * parent_context,
                                 GumCpuContext * cpu_context,
                                 gpointer function_arguments)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER_CAST (listener);
  GumCallCountSamplerPrivate * priv =
      GUM_CALL_COUNT_SAMPLER_GET_PRIVATE (self);
  GumSample * counter;

  gum_interceptor_ignore_caller (priv->interceptor);

  counter = g_private_get (priv->tls_key);
  if (counter == NULL)
  {
    counter = g_new0 (GumSample, 1);
    g_private_set (priv->tls_key, counter);
  }

  g_atomic_int_inc (&priv->total_count);
  (*counter)++;
}

static void
gum_call_count_sampler_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * context,
                                 GumInvocationContext * parent_context,
                                 gpointer function_return_value)
{
  GumCallCountSampler * self = GUM_CALL_COUNT_SAMPLER_CAST (listener);
  GumCallCountSamplerPrivate * priv =
      GUM_CALL_COUNT_SAMPLER_GET_PRIVATE (self);

  gum_interceptor_unignore_caller (priv->interceptor);
}

static gpointer
gum_call_count_sampler_provide_thread_data (GumInvocationListener * listener,
                                            gpointer function_instance_data,
                                            guint thread_id)
{
  return NULL;
}
