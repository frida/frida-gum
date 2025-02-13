/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry.h"

#include "testutil.h"

#define TESTCASE(NAME) \
    void test_module_registry_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/ModuleRegistry", test_module_registry, NAME)

TESTLIST_BEGIN (module_registry)
  TESTENTRY (module_registry_should_emit_signal_on_add)
TESTLIST_END ()

static void on_module_added (GumModuleRegistry * registry, GumModule * module,
    gpointer user_data);
static void on_module_removed (GumModuleRegistry * registry, GumModule * module,
    gpointer user_data);

TESTCASE (module_registry_should_emit_signal_on_add)
{
  GumModuleRegistry * registry;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  registry = gum_module_registry_obtain ();
  g_signal_connect (registry, "module-added", G_CALLBACK (on_module_added),
      NULL);
  g_signal_connect (registry, "module-removed", G_CALLBACK (on_module_removed),
      NULL);
  g_printerr ("Sleeping in PID %u...\n", gum_process_get_id ());
  while (TRUE)
    g_usleep (60 * G_USEC_PER_SEC);
}

static void
on_module_added (GumModuleRegistry * registry,
                 GumModule * module,
                 gpointer user_data)
{
  g_printerr ("%s: path=\"%s\n", G_STRFUNC, gum_module_get_path (module));
}

static void
on_module_removed (GumModuleRegistry * registry,
                   GumModule * module,
                   gpointer user_data)
{
  g_printerr ("%s: path=\"%s\n", G_STRFUNC, gum_module_get_path (module));
}
