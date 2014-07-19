/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum.h"

#include "../libs/gum/heap/gumallocatorprobe-priv.h"
#include "guminterceptor-priv.h"
#include "gumprintf.h"
#include "gumscript-priv.h"
#include "gumsymbolutil-priv.h"

#include <capstone.h>
#include <glib-object.h>
#include <gio/gio.h>

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

  gum_memory_init ();

#if GLIB_CHECK_VERSION (2, 42, 0)
  glib_init ();
  gio_init ();
#endif

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
