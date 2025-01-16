/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry.h"

#include "gum-init.h"
#include "gummoduleregistry-priv.h"

#define GUM_MODULE_REGISTRY_LOCK(r) g_mutex_lock (&(r)->mutex)
#define GUM_MODULE_REGISTRY_UNLOCK(r) g_mutex_unlock (&(r)->mutex)

struct _GumModuleRegistry
{
  GObject parent;

  GMutex mutex;
  GPtrArray * modules;
};

enum
{
  MODULE_ADDED,
  MODULE_REMOVED,
  LAST_SIGNAL
};

static void gum_module_registry_dispose (GObject * object);
static void gum_module_registry_finalize (GObject * object);

static void gum_deinit_module_registry (void);

G_DEFINE_TYPE (GumModuleRegistry, gum_module_registry, G_TYPE_OBJECT)

static guint gum_module_registry_signals[LAST_SIGNAL] = { 0, };

static void
gum_module_registry_class_init (GumModuleRegistryClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_module_registry_dispose;
  object_class->finalize = gum_module_registry_finalize;

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
  g_mutex_init (&self->mutex);
  self->modules = g_ptr_array_new_full (0, g_object_unref);

  _gum_module_registry_activate (self);
}

static void
gum_module_registry_dispose (GObject * object)
{
  GumModuleRegistry * self = GUM_MODULE_REGISTRY (object);

  _gum_module_registry_deactivate (self);

  g_clear_pointer (&self->modules, g_ptr_array_unref);

  G_OBJECT_CLASS (gum_module_registry_parent_class)->dispose (object);
}

static void
gum_module_registry_finalize (GObject * object)
{
  GumModuleRegistry * self = GUM_MODULE_REGISTRY (object);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_module_registry_parent_class)->finalize (object);
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

void
_gum_module_registry_register (GumModuleRegistry * self,
                               GumModule * module)
{
  GUM_MODULE_REGISTRY_LOCK (self);

  g_ptr_array_add (self->modules, g_object_ref (module));

  GUM_MODULE_REGISTRY_UNLOCK (self);

  g_signal_emit (self, gum_module_registry_signals[MODULE_ADDED], 0, module);

  g_object_unref (module);
}

void
_gum_module_registry_unregister (GumModuleRegistry * self,
                                 GumAddress base_address)
{
  GumModule * module;
  guint i;

  GUM_MODULE_REGISTRY_LOCK (self);

  module = NULL;
  for (i = 0; i != self->modules->len; i++)
  {
    GumModule * candidate = g_ptr_array_index (self->modules, i);

    if (gum_module_get_range (candidate)->base_address == base_address)
    {
      module = g_object_ref (candidate);
      g_ptr_array_remove_index (self->modules, i);
      break;
    }
  }
  g_assert (module != NULL);

  GUM_MODULE_REGISTRY_UNLOCK (self);

  g_signal_emit (self, gum_module_registry_signals[MODULE_REMOVED], 0, module);

  g_object_unref (module);
}
