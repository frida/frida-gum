/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "../libs/gum/heap/gumallocatorprobe-priv.h"
#include "guminterceptor-priv.h"
#include "gummemory-priv.h"
#include "gumprintf.h"
#include "gumscript-priv.h"
#include "gumsymbolutil-priv.h"

#include <capstone.h>
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

void
gum_deinit (void)
{
#ifdef HAVE_V8
  _gum_script_deinit ();
#endif

#ifdef HAVE_LIBS
  _gum_allocator_probe_deinit ();
#endif

  _gum_interceptor_deinit ();

#ifdef HAVE_SYMBOL_BACKEND
  _gum_symbol_util_deinit ();
#endif

  _gum_memory_deinit ();
}

static gpointer
do_init (gpointer data)
{
  GumFeatureFlags features = (GumFeatureFlags) GPOINTER_TO_INT (data);
  cs_opt_mem gum_cs_mem_callbacks = {
    gum_malloc,
    gum_calloc,
    gum_realloc,
    gum_free,
    gum_vsnprintf
  };

  (void) features;

  if (!g_thread_supported ())
#ifdef _DEBUG
    g_thread_init_with_errorcheck_mutexes (NULL);
#else
    g_thread_init (NULL);
#endif

  g_type_init ();

  _gum_memory_init ();

  cs_option (0, CS_OPT_MEM, GPOINTER_TO_SIZE (&gum_cs_mem_callbacks));

#ifdef HAVE_SYMBOL_BACKEND
  if ((features & GUM_FEATURE_SYMBOL_LOOKUP) != 0)
    _gum_symbol_util_init ();
#endif

  _gum_interceptor_init ();

#ifdef HAVE_V8
  _gum_script_init ();
#endif

  return NULL;
}
