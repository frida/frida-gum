/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry.h"

#include "gum-init.h"
#include "gumcloak.h"
#include "gummoduleregistry-priv.h"

#define GUM_MODULE_REGISTRY_LOCK(r) g_rec_mutex_lock (&(r)->mutex)
#define GUM_MODULE_REGISTRY_UNLOCK(r) g_rec_mutex_unlock (&(r)->mutex)

typedef enum {
  GUM_MODULE_REGISTRY_CREATED,
  GUM_MODULE_REGISTRY_ACTIVATED,
} GumModuleRegistryState;

struct _GumModuleRegistry
{
  GObject parent;

  GRecMutex mutex;
  GumModuleRegistryState state;
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
static void gum_module_registry_activate (GumModuleRegistry * self);

static void gum_deinit_module_registry (void);

static gboolean gum_is_cloaked_module (GumModule * module);

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
  g_rec_mutex_init (&self->mutex);
  self->state = GUM_MODULE_REGISTRY_CREATED;
  self->modules = g_ptr_array_new_full (0, g_object_unref);
}

static void
gum_module_registry_dispose (GObject * object)
{
  GumModuleRegistry * self = GUM_MODULE_REGISTRY (object);

  GUM_MODULE_REGISTRY_LOCK (self);

  _gum_module_registry_deactivate (self);

  g_ptr_array_unref (self->modules);
  self->modules = g_ptr_array_new_full (0, g_object_unref);

  GUM_MODULE_REGISTRY_UNLOCK (self);

  G_OBJECT_CLASS (gum_module_registry_parent_class)->dispose (object);
}

static void
gum_module_registry_finalize (GObject * object)
{
  GumModuleRegistry * self = GUM_MODULE_REGISTRY (object);

  g_ptr_array_unref (self->modules);
  g_rec_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_module_registry_parent_class)->finalize (object);
}

GumModuleRegistry *
gum_module_registry_obtain (void)
{
  GumModuleRegistry * registry;
  static gsize cached_result = 0;
  gboolean activate = FALSE;

  if (g_once_init_enter (&cached_result))
  {
    GumModuleRegistry * registry;

    registry = g_object_new (GUM_TYPE_MODULE_REGISTRY, NULL);
    _gum_register_destructor (gum_deinit_module_registry);

    activate = TRUE;

    g_once_init_leave (&cached_result, GPOINTER_TO_SIZE (registry));
  }

  registry = GSIZE_TO_POINTER (cached_result);

  if (activate)
    gum_module_registry_activate (registry);

  return registry;
}

static void
gum_module_registry_activate (GumModuleRegistry * self)
{
  GUM_MODULE_REGISTRY_LOCK (self);

  _gum_module_registry_activate (self);
  self->state = GUM_MODULE_REGISTRY_ACTIVATED;

  GUM_MODULE_REGISTRY_UNLOCK (self);
}

static void
gum_deinit_module_registry (void)
{
  g_object_unref (gum_module_registry_obtain ());
}

GPtrArray *
_gum_module_registry_get_modules (GumModuleRegistry * self)
{
  GPtrArray * result;

  GUM_MODULE_REGISTRY_LOCK (self);

  result = g_ptr_array_ref (self->modules);

  GUM_MODULE_REGISTRY_UNLOCK (self);

  return result;
}

void
gum_module_registry_enumerate_modules (GumModuleRegistry * self,
                                       GumFoundModuleFunc func,
                                       gpointer user_data)
{
  guint n, i;

  GUM_MODULE_REGISTRY_LOCK (self);

  n = self->modules->len;
  for (i = 0; i != n; i++)
  {
    GumModule * mod = g_ptr_array_index (self->modules, i);

    if (gum_is_cloaked_module (mod))
      continue;

    if (!func (mod, user_data))
      break;
  }

  GUM_MODULE_REGISTRY_UNLOCK (self);
}

void
gum_module_registry_lock (GumModuleRegistry * self)
{
  GUM_MODULE_REGISTRY_LOCK (self);
}

void
gum_module_registry_unlock (GumModuleRegistry * self)
{
  GUM_MODULE_REGISTRY_UNLOCK (self);
}

void
_gum_module_registry_reset (GumModuleRegistry * self)
{
  GUM_MODULE_REGISTRY_LOCK (self);

  g_ptr_array_remove_range (self->modules, 0, self->modules->len);

  GUM_MODULE_REGISTRY_UNLOCK (self);
}

void
_gum_module_registry_register (GumModuleRegistry * self,
                               GumModule * mod)
{
  gboolean being_observed;
  GPtrArray * modules;

  GUM_MODULE_REGISTRY_LOCK (self);

  being_observed = self->state != GUM_MODULE_REGISTRY_CREATED;

  modules = being_observed
      ? g_ptr_array_copy (self->modules, (GCopyFunc) g_object_ref, NULL)
      : self->modules;
  g_ptr_array_add (modules, g_object_ref (mod));

  if (being_observed)
  {
    g_ptr_array_unref (self->modules);
    self->modules = modules;
  }

  GUM_MODULE_REGISTRY_UNLOCK (self);

  if (being_observed && !gum_is_cloaked_module (mod))
    g_signal_emit (self, gum_module_registry_signals[MODULE_ADDED], 0, mod);
}

void
_gum_module_registry_unregister (GumModuleRegistry * self,
                                 GumAddress base_address)
{
  gboolean being_observed;
  GPtrArray * modules;
  GumModule * mod;
  guint i;

  GUM_MODULE_REGISTRY_LOCK (self);

  being_observed = self->state != GUM_MODULE_REGISTRY_CREATED;

  modules = being_observed
      ? g_ptr_array_copy (self->modules, (GCopyFunc) g_object_ref, NULL)
      : self->modules;

  mod = NULL;
  for (i = 0; i != self->modules->len; i++)
  {
    GumModule * candidate = g_ptr_array_index (self->modules, i);

    if (gum_module_get_range (candidate)->base_address == base_address)
    {
      mod = g_object_ref (candidate);
      g_ptr_array_remove_index (modules, i);
      break;
    }
  }
  g_assert (mod != NULL);

  if (being_observed)
  {
    g_ptr_array_unref (self->modules);
    self->modules = modules;
  }

  GUM_MODULE_REGISTRY_UNLOCK (self);

  if (being_observed && !gum_is_cloaked_module (mod))
    g_signal_emit (self, gum_module_registry_signals[MODULE_REMOVED], 0, mod);

  g_object_unref (mod);
}

static gboolean
gum_is_cloaked_module (GumModule * module)
{
  const GumMemoryRange * range;

  range = gum_module_get_range (module);

  return gum_cloak_has_range_containing (range->base_address);
}
