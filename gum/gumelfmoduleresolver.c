/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumelfmoduleresolver.h"

#include "gumelfmodule-priv.h"

typedef struct _GumElfResolverModule GumElfResolverModule;

struct _GumElfModuleResolver
{
  GObject parent;

  GPtrArray * modules;
};

struct _GumElfResolverModule
{
  GumElfModule * module;
  GumAddress load_bias;
  GHashTable * symbols;
};

static void gum_elf_module_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_elf_module_resolver_finalize (GObject * object);
static GumModule * gum_elf_module_resolver_find_module_by_name (
    GumModuleResolver * resolver, const gchar * name);
static GumAddress gum_elf_module_resolver_find_dynamic_address (
    GumModuleResolver * resolver, const gchar * symbol);
static gboolean gum_elf_module_resolver_find_dynamic_symbol (
    GumModuleResolver * resolver, const gchar * symbol,
    GumDynamicSymbolDetails * details);

static GHashTable * gum_elf_resolver_module_get_symbols (
    GumElfResolverModule * self);
static gboolean gum_elf_resolver_module_collect_symbol (
    const GumElfSymbolDetails * details, gpointer user_data);
static void gum_elf_resolver_module_free (GumElfResolverModule * self);

G_DEFINE_TYPE_WITH_CODE (GumElfModuleResolver,
                         gum_elf_module_resolver,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_MODULE_RESOLVER,
                             gum_elf_module_resolver_iface_init))

static void
gum_elf_module_resolver_class_init (GumElfModuleResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_elf_module_resolver_finalize;
}

static void
gum_elf_module_resolver_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  GumModuleResolverInterface * iface = g_iface;

  iface->find_module_by_name = gum_elf_module_resolver_find_module_by_name;
  iface->find_dynamic_address = gum_elf_module_resolver_find_dynamic_address;
  iface->find_dynamic_symbol = gum_elf_module_resolver_find_dynamic_symbol;
}

static void
gum_elf_module_resolver_init (GumElfModuleResolver * self)
{
  self->modules = g_ptr_array_new_with_free_func (
      (GDestroyNotify) gum_elf_resolver_module_free);
}

static void
gum_elf_module_resolver_finalize (GObject * object)
{
  GumElfModuleResolver * self = GUM_ELF_MODULE_RESOLVER (object);

  g_ptr_array_unref (self->modules);

  G_OBJECT_CLASS (gum_elf_module_resolver_parent_class)->finalize (object);
}

GumElfModuleResolver *
gum_elf_module_resolver_new (void)
{
  return g_object_new (GUM_TYPE_ELF_MODULE_RESOLVER, NULL);
}

void
gum_elf_module_resolver_add_module (GumElfModuleResolver * self,
                                    GumElfModule * module,
                                    GumAddress base_address)
{
  GumElfResolverModule * m;

  m = g_slice_new (GumElfResolverModule);
  m->module = g_object_ref (module);
  m->load_bias = base_address - gum_elf_module_get_base_address (module);
  m->symbols = NULL;

  g_ptr_array_add (self->modules, m);
}

static GumModule *
gum_elf_module_resolver_find_module_by_name (GumModuleResolver * resolver,
                                             const gchar * name)
{
  return NULL;
}

static GumAddress
gum_elf_module_resolver_find_dynamic_address (GumModuleResolver * resolver,
                                              const gchar * symbol)
{
  GumDynamicSymbolDetails details;

  if (!gum_elf_module_resolver_find_dynamic_symbol (resolver, symbol,
      &details) || details.indirect)
  {
    return 0;
  }

  return details.address;
}

static gboolean
gum_elf_module_resolver_find_dynamic_symbol (GumModuleResolver * resolver,
                                             const gchar * symbol,
                                             GumDynamicSymbolDetails * details)
{
  GumElfModuleResolver * self = GUM_ELF_MODULE_RESOLVER (resolver);
  guint i;

  for (i = 0; i != self->modules->len; i++)
  {
    GumElfResolverModule * m = g_ptr_array_index (self->modules, i);
    const GumDynamicSymbolDetails * d;

    d = g_hash_table_lookup (gum_elf_resolver_module_get_symbols (m), symbol);
    if (d != NULL)
    {
      *details = *d;
      return TRUE;
    }
  }

  details->address = 0;
  details->indirect = FALSE;

  return FALSE;
}

static GHashTable *
gum_elf_resolver_module_get_symbols (GumElfResolverModule * self)
{
  if (self->symbols == NULL)
  {
    self->symbols =
        g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
    _gum_elf_module_enumerate_default_dynamic_symbols (self->module,
        gum_elf_resolver_module_collect_symbol, self);
  }

  return self->symbols;
}

static gboolean
gum_elf_resolver_module_collect_symbol (const GumElfSymbolDetails * details,
                                        gpointer user_data)
{
  GumElfResolverModule * self = user_data;
  GumDynamicSymbolDetails * d;

  if (details->shdr_index == GUM_ELF_SHDR_INDEX_UNDEF)
    return TRUE;

  if (details->bind != GUM_ELF_BIND_GLOBAL &&
      details->bind != GUM_ELF_BIND_WEAK)
  {
    return TRUE;
  }

  if (details->type != GUM_ELF_SYMBOL_FUNC &&
      details->type != GUM_ELF_SYMBOL_OBJECT &&
      details->type != GUM_ELF_SYMBOL_GNU_IFUNC)
  {
    return TRUE;
  }

  if (g_hash_table_contains (self->symbols, details->name))
    return TRUE;

  d = g_new (GumDynamicSymbolDetails, 1);
  d->address = details->address + self->load_bias;
  d->indirect = details->type == GUM_ELF_SYMBOL_GNU_IFUNC;
  g_hash_table_insert (self->symbols, (gpointer) details->name, d);

  return TRUE;
}

static void
gum_elf_resolver_module_free (GumElfResolverModule * self)
{
  g_clear_pointer (&self->symbols, g_hash_table_unref);
  g_object_unref (self->module);

  g_slice_free (GumElfResolverModule, self);
}
