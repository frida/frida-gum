/*
 * Copyright (C) 2026 Kirby Kuehl <kkuehl@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <gum/gum.h>

typedef struct _Race Race;

struct _Race
{
  GMutex mutex;
  GCond cond;
  guint num_ready;
  gboolean started;
};

static gpointer count_modules_once_started (gpointer data);
static gboolean count_module (GumModule * module, gpointer user_data);

int
main (void)
{
  int result = 0;
  Race race;
  GThread * threads[32];
  guint i;

  gum_init ();

  g_mutex_init (&race.mutex);
  g_cond_init (&race.cond);
  race.num_ready = 0;
  race.started = FALSE;

  for (i = 0; i != G_N_ELEMENTS (threads); i++)
  {
    threads[i] = g_thread_new ("registry-racer", count_modules_once_started,
        &race);
  }

  g_mutex_lock (&race.mutex);
  while (race.num_ready != G_N_ELEMENTS (threads))
    g_cond_wait (&race.cond, &race.mutex);
  race.started = TRUE;
  g_cond_broadcast (&race.cond);
  g_mutex_unlock (&race.mutex);

  for (i = 0; i != G_N_ELEMENTS (threads); i++)
  {
    if (GPOINTER_TO_UINT (g_thread_join (threads[i])) == 0)
      result = 1;
  }

  return result;
}

static gpointer
count_modules_once_started (gpointer data)
{
  Race * race = data;
  guint num_modules = 0;

  g_mutex_lock (&race->mutex);
  race->num_ready++;
  g_cond_broadcast (&race->cond);
  while (!race->started)
    g_cond_wait (&race->cond, &race->mutex);
  g_mutex_unlock (&race->mutex);

  gum_process_enumerate_modules (count_module, &num_modules);

  return GUINT_TO_POINTER (num_modules);
}

static gboolean
count_module (GumModule * module,
              gpointer user_data)
{
  guint * num_modules = user_data;

  (*num_modules)++;

  return TRUE;
}
