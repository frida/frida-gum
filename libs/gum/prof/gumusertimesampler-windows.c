/*
 * Copyright (C) 2008-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumusertimesampler.h"

#define _WIN32_LEAN_AND_MEAN
#undef WINVER
#undef _WIN32_WINNT
#define WINVER 0x0600
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tchar.h>

typedef BOOL (WINAPI * GetThreadTimesFunc) (HANDLE ThreadHandle,
    LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime,
    LPFILETIME lpUserTime);

struct _GumUserTimeSampler
{
  GObject parent;
  GumThreadId thread_id;

  GetThreadTimesFunc get_thread_times;
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
  HMODULE mod;

  sampler = g_object_new (GUM_TYPE_USER_TIME_SAMPLER, NULL);
  sampler->thread_id = gum_process_get_current_thread_id ();

  mod = GetModuleHandle (_T ("kernel32.dll"));
  g_assert (mod != NULL);

  sampler->get_thread_times = (GetThreadTimesFunc) GetProcAddress (mod,
      "GetThreadTimes");

  return GUM_SAMPLER (sampler);
}

GumSampler *
gum_user_time_sampler_new_with_thread_id (GumThreadId thread_id)
{
  GumUserTimeSampler * sampler;

  sampler = (GumUserTimeSampler *) gum_user_time_sampler_new ();
  sampler->thread_id = thread_id;

  return GUM_SAMPLER (sampler);
}

gboolean
gum_user_time_sampler_is_available (GumUserTimeSampler * self)
{
  return (self->get_thread_times != NULL);
}

static GumSample
gum_user_time_sampler_sample (GumSampler * sampler)
{
  GumUserTimeSampler * user_time_sampler = (GumUserTimeSampler *) sampler;
  DWORD thread_id = (DWORD) user_time_sampler->thread_id;
  HANDLE thread = NULL;
  FILETIME creationTime;
  FILETIME exitTime;
  FILETIME kernelTime;
  FILETIME userTime;
  GumSample result = 0;

  if (user_time_sampler->get_thread_times == NULL)
    goto beach;

  thread = OpenThread (THREAD_QUERY_LIMITED_INFORMATION, FALSE, thread_id);
  if (thread == NULL)
  {
    g_printerr ("Error openning thread: %u\n", GetLastError ());
    goto beach;
  }

  if (!user_time_sampler->get_thread_times (thread, &creationTime,
      &exitTime, &kernelTime, &userTime))
  {
    g_printerr ("Error querying user time: %u\n", GetLastError ());
    goto beach;
  }

  /* Timings on Windows are to 100-nanosecond granularity. Convert to u-secs */
  result = ((((GumSample) userTime.dwHighDateTime) << 32) +
      userTime.dwLowDateTime) / 10;

beach:
  if (thread != NULL)
    CloseHandle (thread);

  return result;
}
