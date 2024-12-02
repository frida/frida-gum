/*
 * Copyright (C) 2011-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumusertimesampler.h"

#include <mach/mach.h>

struct _GumUserTimeSampler
{
  GObject parent;
  GumThreadId thread_id;
};

static void gum_user_time_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumSample gum_user_time_sampler_sample (GumSampler * sampler);

G_DEFINE_TYPE_EXTENDED (GumUserTimeSampler,
                        gum_user_time_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                        gum_user_time_sampler_iface_init))

static void
gum_user_time_sampler_class_init (GumUserTimeSamplerClass * klass)
{
}

static void
gum_user_time_sampler_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumSamplerInterface * iface = g_iface;

  iface->sample = gum_user_time_sampler_sample;
}

static void
gum_user_time_sampler_init (GumUserTimeSampler * self)
{
}

GumSampler *
gum_user_time_sampler_new (void)
{
  GumUserTimeSampler * sampler;

  sampler = g_object_new (GUM_TYPE_USER_TIME_SAMPLER, NULL);
  sampler->thread_id = gum_process_get_current_thread_id ();

  return GUM_SAMPLER (sampler);
}

GumSampler *
gum_user_time_sampler_new_with_thread_id (GumThreadId thread_id)
{
  GumUserTimeSampler * sampler;

  sampler = g_object_new (GUM_TYPE_USER_TIME_SAMPLER, NULL);
  sampler->thread_id = thread_id;

  return GUM_SAMPLER (sampler);
}

gboolean
gum_user_time_sampler_is_available (GumUserTimeSampler * self)
{
  return TRUE;
}

static GumSample
gum_user_time_sampler_sample (GumSampler * sampler)
{
  GumUserTimeSampler * user_time_sampler = (GumUserTimeSampler *) sampler;
  mach_port_t port = (mach_port_t) user_time_sampler->thread_id;
  thread_basic_info_data_t info;
  mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
  kern_return_t kr;

  kr = thread_info (port, THREAD_BASIC_INFO, (thread_info_t) &info,
      &info_count);

  if (kr != KERN_SUCCESS)
  {
    g_printerr ("thread_info failed: %d\n", kr);
    return 0;
  }

  return ((GumSample) info.user_time.seconds * G_USEC_PER_SEC) +
      info.user_time.microseconds;
}
