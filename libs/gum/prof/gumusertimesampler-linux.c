/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumusertimesampler.h"

#include <unistd.h>

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
  int thread_id = (int) user_time_sampler->thread_id;
  gchar * stat_path = NULL;
  gchar * stat_contents = NULL;
  gsize stat_len;
  GError * error = NULL;
  gchar ** fields = NULL;
  gchar ** iterator;
  guint num_fields = 0;
  guint64 clock_ticks;
  long ticks_per_sec;
  GumSample utime = 0;

  stat_path = g_strdup_printf ("/proc/%d/task/%d/stat", getpid (), thread_id);

  if (!g_file_get_contents (stat_path, &stat_contents, &stat_len, &error))
  {
    g_printerr ("Error reading file: %s\n", error->message);
    goto beach;
  }

  fields = g_strsplit (stat_contents, " ", -1);

  for (iterator = fields; *iterator != NULL; iterator++)
  {
    num_fields++;
  }

  if (num_fields < 14)
  {
    g_printerr ("Not enough fields: %u in '%s'\n", num_fields, stat_contents);
    goto beach;
  }

  clock_ticks = g_ascii_strtoull (fields[13], NULL, 10);

  ticks_per_sec = sysconf (_SC_CLK_TCK);

  utime = (clock_ticks * 1000000) / ticks_per_sec;

beach:
  g_strfreev (fields);
  g_free (stat_contents);
  g_free (stat_path);

  return utime;
}
