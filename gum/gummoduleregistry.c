/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry.h"

#include "gum-init.h"

struct _GumModuleRegistry
{
  GObject parent;

  GPtrArray * modules;
};

enum
{
  MODULE_ADDED,
  MODULE_REMOVED,
  LAST_SIGNAL
};

static void gum_module_registry_dispose (GObject * object);

static void gum_deinit_module_registry (void);

G_DEFINE_TYPE (GumModuleRegistry, gum_module_registry, G_TYPE_OBJECT)

static guint gum_module_registry_signals[LAST_SIGNAL] = { 0, };

static void
gum_module_registry_class_init (GumModuleRegistryClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_module_registry_dispose;

  gum_module_registry_signals[MODULE_ADDED] = g_signal_new ("module-added",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__OBJECT, G_TYPE_NONE, 1, GUM_TYPE_MODULE);
  gum_module_registry_signals[MODULE_REMOVED] = g_signal_new ("module-removed",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__OBJECT, G_TYPE_NONE, 1, GUM_TYPE_MODULE);
}

static void
gum_module_registry_init (GumModuleRegistry * self)
{
  self->modules = g_ptr_array_new_full (0, g_object_unref);
}

static void
gum_module_registry_dispose (GObject * object)
{
  GumModuleRegistry * self = GUM_MODULE_REGISTRY (object);

  g_clear_pointer (&self->modules, g_ptr_array_unref);

  G_OBJECT_CLASS (gum_module_registry_parent_class)->dispose (object);
}

GumModuleRegistry *
gum_module_registry_obtain (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    GumModuleRegistry * registry;

    registry = g_object_new (GUM_TYPE_MODULE_REGISTRY, NULL);

    _gum_register_destructor (gum_deinit_module_registry);

    g_once_init_leave (&cached_result, GPOINTER_TO_SIZE (registry));
  }

  return GSIZE_TO_POINTER (cached_result);
}

static void
gum_deinit_module_registry (void)
{
  g_object_unref (gum_module_registry_obtain ());
}
