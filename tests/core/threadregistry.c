/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry.h"

#include "testutil.h"

#define TESTCASE(NAME) \
    void test_thread_registry_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/ThreadRegistry", test_thread_registry, NAME)

TESTLIST_BEGIN (thread_registry)
  TESTENTRY (thread_registry_should_emit_signal_on_add)
TESTLIST_END ()

static gboolean print_thread (const GumThreadDetails * thread,
    gpointer user_data);
static void on_thread_added (GumThreadRegistry * registry,
    const GumThreadDetails * thread, gpointer user_data);
static void on_thread_renamed (GumThreadRegistry * registry,
    const GumThreadDetails * thread, const gchar * previous_name,
    gpointer user_data);
static void on_thread_removed (GumThreadRegistry * registry,
    const GumThreadDetails * thread, gpointer user_data);

static gpointer hello_proc (gpointer data);
static gpointer hello2_proc (gpointer data);

TESTCASE (thread_registry_should_emit_signal_on_add)
{
  GumThreadRegistry * registry;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  g_thread_unref (g_thread_new ("hello", hello_proc, GSIZE_TO_POINTER (1337)));

  registry = gum_thread_registry_obtain ();
  gum_thread_registry_enumerate_threads (registry, print_thread, NULL);
  g_signal_connect (registry, "thread-added", G_CALLBACK (on_thread_added),
      NULL);
  g_signal_connect (registry, "thread-renamed", G_CALLBACK (on_thread_renamed),
      NULL);
  g_signal_connect (registry, "thread-removed", G_CALLBACK (on_thread_removed),
      NULL);
  g_printerr ("Sleeping in PID %u...\n", gum_process_get_id ());
  while (TRUE)
    g_usleep (60 * G_USEC_PER_SEC);
}

static gboolean
print_thread (const GumThreadDetails * thread,
              gpointer user_data)
{
  g_printerr ("Found existing thread: id=%" G_GSIZE_MODIFIER "u name=\"%s\"\n",
      thread->id, thread->name);
  return TRUE;
}

static void
on_thread_added (GumThreadRegistry * registry,
                 const GumThreadDetails * thread,
                 gpointer user_data)
{
  g_printerr ("%s: id=%" G_GSIZE_MODIFIER "u name=\"%s\"\n",
      G_STRFUNC, thread->id, thread->name);
}

static void
on_thread_renamed (GumThreadRegistry * registry,
                   const GumThreadDetails * thread,
                   const gchar * previous_name,
                   gpointer user_data)
{
  g_printerr ("%s: id=%" G_GSIZE_MODIFIER "u name=\"%s\" "
      "previous_name=\"%s\"\n",
      G_STRFUNC, thread->id, thread->name, previous_name);
}

static void
on_thread_removed (GumThreadRegistry * registry,
                   const GumThreadDetails * thread,
                   gpointer user_data)
{
  g_printerr ("%s: id=%" G_GSIZE_MODIFIER "u name=\"%s\"\n",
      G_STRFUNC, thread->id, thread->name);
}

static gpointer
hello_proc (gpointer data)
{
  g_thread_unref (g_thread_new ("hello2", hello2_proc, GSIZE_TO_POINTER (1337)));

  while (TRUE)
  {
    g_printerr ("Hello! TID=%zu\n", gum_process_get_current_thread_id ());
    g_usleep (G_USEC_PER_SEC);
  }

  return NULL;
}

static gpointer
hello2_proc (gpointer data)
{
  while (TRUE)
  {
    g_printerr ("Hello2! TID=%zu\n", gum_process_get_current_thread_id ());
    g_usleep (G_USEC_PER_SEC);
  }

  return NULL;
}
