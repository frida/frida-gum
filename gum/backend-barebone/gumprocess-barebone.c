/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

static void gum_throw_not_supported (GError ** error);

GumModule *
gum_process_get_libc_module (void)
{
  return NULL;
}

gboolean
gum_process_is_debugger_attached (void)
{
  return FALSE;
}

GumProcessId
gum_process_get_id (void)
{
  return 0;
}

G_GNUC_WEAK GumThreadId
gum_process_get_current_thread_id (void)
{
  G_PANIC_MISSING_IMPLEMENTATION ();
  return 1;
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  return FALSE;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data,
                           GumModifyThreadFlags flags)
{
  return FALSE;
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data,
                                GumThreadFlags flags)
{
}

gboolean
_gum_process_collect_main_module (GumModule * module,
                                  gpointer user_data)
{
  GumModule ** out = user_data;

  *out = g_object_ref (module);

  return FALSE;
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  return 0;
}

gint
gum_thread_get_system_error (void)
{
  return 0;
}

void
gum_thread_set_system_error (gint value)
{
}

gboolean
gum_thread_suspend (GumThreadId thread_id,
                    GError ** error)
{
  gum_throw_not_supported (error);
  return FALSE;
}

gboolean
gum_thread_resume (GumThreadId thread_id,
                   GError ** error)
{
  gum_throw_not_supported (error);
  return FALSE;
}

gboolean
gum_thread_set_hardware_breakpoint (GumThreadId thread_id,
                                    guint breakpoint_id,
                                    GumAddress address,
                                    GError ** error)
{
  gum_throw_not_supported (error);
  return FALSE;
}

gboolean
gum_thread_unset_hardware_breakpoint (GumThreadId thread_id,
                                      guint breakpoint_id,
                                      GError ** error)
{
  gum_throw_not_supported (error);
  return FALSE;
}

gboolean
gum_thread_set_hardware_watchpoint (GumThreadId thread_id,
                                    guint watchpoint_id,
                                    GumAddress address,
                                    gsize size,
                                    GumWatchConditions wc,
                                    GError ** error)
{
  gum_throw_not_supported (error);
  return FALSE;
}

gboolean
gum_thread_unset_hardware_watchpoint (GumThreadId thread_id,
                                      guint watchpoint_id,
                                      GError ** error)
{
  gum_throw_not_supported (error);
  return FALSE;
}

static void
gum_throw_not_supported (GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Not supported by the Barebone backend");
}
