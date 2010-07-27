/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gum.h"
#include "gummemory.h"

#include <glib-object.h>

static gpointer do_init (gpointer data);

void
gum_init (void)
{
  gum_init_with_features (GUM_FEATURE_DEFAULT);
}

void
gum_init_with_features (GumFeatureFlags features)
{
  static GOnce init_once = G_ONCE_INIT;
  g_once (&init_once, do_init, GINT_TO_POINTER (features));
}

static gpointer
do_init (gpointer data)
{
  GumFeatureFlags features = (GumFeatureFlags) GPOINTER_TO_INT (data);

  g_setenv ("G_SLICE", "always-malloc", TRUE);

  g_type_init ();

  if (!g_thread_supported ())
#ifdef _DEBUG
    g_thread_init_with_errorcheck_mutexes (NULL);
#else
    g_thread_init (NULL);
#endif

  gum_memory_init ();

  if ((features & GUM_FEATURE_SYMBOL_LOOKUP) != 0)
    gum_symbol_util_init ();

  return NULL;
}
