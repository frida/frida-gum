/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2026 Sam Sun <samsun@nvidia.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry.h"

#include "guminterceptor.h"
#include "testutil.h"

#ifdef HAVE_LINUX
# include "interceptor-callbacklistener.h"
# include <dlfcn.h>
#endif

#define TESTCASE(NAME) \
    void test_module_registry_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/ModuleRegistry", test_module_registry, NAME)

TESTLIST_BEGIN (module_registry)
  TESTENTRY (module_registry_should_emit_signal_on_add)
  TESTENTRY (hooks_should_be_discarded_when_module_unloads)
TESTLIST_END ()

static void on_module_added (GumModuleRegistry * registry, GumModule * module,
    gpointer user_data);
static void on_module_removed (GumModuleRegistry * registry, GumModule * module,
    gpointer user_data);

#ifdef HAVE_LINUX

# define GUM_TARGET_MODULE_FILENAME "module-registry-target.so"

typedef struct _TestModuleHooks TestModuleHooks;

struct _TestModuleHooks
{
  gboolean seen_add;
  gboolean seen_remove;
};

static void on_target_module_added (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static void on_target_module_removed (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static gboolean is_target_module (GumModule * module);

#endif

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

TESTCASE (hooks_should_be_discarded_when_module_unloads)
{
#ifdef HAVE_LINUX
  GumModuleRegistry * registry;
  GumInterceptor * interceptor;
  TestCallbackListener * listener;
  TestModuleHooks hooks = { 0, };
  gulong added_handler, removed_handler;
  gchar * data_dir, * target_path;
  void * handle;
  gpointer target;
  GumAttachReturn result;

  registry = gum_module_registry_obtain ();
  interceptor = gum_interceptor_obtain ();
  listener = test_callback_listener_new ();

  added_handler = g_signal_connect (registry, "module-added",
      G_CALLBACK (on_target_module_added), &hooks);
  removed_handler = g_signal_connect (registry, "module-removed",
      G_CALLBACK (on_target_module_removed), &hooks);

  data_dir = test_util_get_data_dir ();
  target_path = g_build_filename (data_dir, GUM_TARGET_MODULE_FILENAME, NULL);

  handle = dlopen (target_path, RTLD_NOW | RTLD_LOCAL);
  g_assert_nonnull (handle);
  g_assert_true (hooks.seen_add);

  target = dlsym (handle, "gum_module_registry_target_function");
  g_assert_nonnull (target);

  result = gum_interceptor_attach (interceptor, target,
      GUM_INVOCATION_LISTENER (listener), NULL);
  g_assert_cmpint (result, ==, GUM_ATTACH_OK);

  dlclose (handle);

  /*
   * If the C library unloaded the module (glibc does; musl keeps it resident),
   * its live hook must have been discarded without restoring the now-unmapped
   * prologue, so detaching afterwards has to be a safe no-op.
   */
  gum_interceptor_detach (interceptor, GUM_INVOCATION_LISTENER (listener));

  if (!hooks.seen_remove)
    g_test_skip ("dlclose did not unload the module on this platform");

  g_signal_handler_disconnect (registry, added_handler);
  g_signal_handler_disconnect (registry, removed_handler);
  g_object_unref (listener);

  g_free (target_path);
  g_free (data_dir);
#else
  g_test_skip ("only supported on Linux");
#endif
}

static void
on_module_added (GumModuleRegistry * registry,
                 GumModule * module,
                 gpointer user_data)
{
  g_printerr ("%s: path=\"%s\"\n", G_STRFUNC, gum_module_get_path (module));
}

static void
on_module_removed (GumModuleRegistry * registry,
                   GumModule * module,
                   gpointer user_data)
{
  g_printerr ("%s: path=\"%s\"\n", G_STRFUNC, gum_module_get_path (module));
}

#ifdef HAVE_LINUX

static void
on_target_module_added (GumModuleRegistry * registry,
                        GumModule * module,
                        gpointer user_data)
{
  TestModuleHooks * hooks = user_data;

  if (is_target_module (module))
    hooks->seen_add = TRUE;
}

static void
on_target_module_removed (GumModuleRegistry * registry,
                          GumModule * module,
                          gpointer user_data)
{
  TestModuleHooks * hooks = user_data;

  if (is_target_module (module))
    hooks->seen_remove = TRUE;
}

static gboolean
is_target_module (GumModule * module)
{
  return g_str_has_suffix (gum_module_get_path (module),
      G_DIR_SEPARATOR_S GUM_TARGET_MODULE_FILENAME);
}

#endif
