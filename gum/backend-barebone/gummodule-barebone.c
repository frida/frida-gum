/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule.h"

#define GUM_TYPE_NATIVE_MODULE (gum_native_module_get_type ())
G_DECLARE_FINAL_TYPE (GumNativeModule, gum_native_module, GUM, NATIVE_MODULE,
                      GObject)

struct _GumNativeModule
{
  GObject parent;

  gchar * name;
  gchar * path;
  GumMemoryRange range;
};

static void gum_native_module_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_native_module_finalize (GObject * object);
static const gchar * gum_native_module_get_name (GumModule * module);
static const gchar * gum_native_module_get_path (GumModule * module);
static const GumMemoryRange * gum_native_module_get_range (GumModule * module);
static void gum_native_module_ensure_initialized (GumModule * module);
static void gum_native_module_enumerate_imports (GumModule * module,
    GumFoundImportFunc func, gpointer user_data);
static void gum_native_module_enumerate_exports (GumModule * module,
    GumFoundExportFunc func, gpointer user_data);
static void gum_native_module_enumerate_symbols (GumModule * module,
    GumFoundSymbolFunc func, gpointer user_data);
static void gum_native_module_enumerate_ranges (GumModule * module,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
static void gum_native_module_enumerate_sections (GumModule * module,
    GumFoundSectionFunc func, gpointer user_data);
static void gum_native_module_enumerate_dependencies (GumModule * module,
    GumFoundDependencyFunc func, gpointer user_data);
static GumAddress gum_native_module_find_export_by_name (GumModule * module,
    const gchar * symbol_name);

G_DEFINE_TYPE_EXTENDED (GumNativeModule,
                        gum_native_module,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_MODULE,
                            gum_native_module_iface_init))

static void
gum_native_module_class_init (GumNativeModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_native_module_finalize;
}

static void
gum_native_module_iface_init (gpointer g_iface,
                              gpointer iface_data)
{
  GumModuleInterface * iface = g_iface;

  iface->get_name = gum_native_module_get_name;
  iface->get_path = gum_native_module_get_path;
  iface->get_range = gum_native_module_get_range;
  iface->ensure_initialized = gum_native_module_ensure_initialized;
  iface->enumerate_imports = gum_native_module_enumerate_imports;
  iface->enumerate_exports = gum_native_module_enumerate_exports;
  iface->enumerate_symbols = gum_native_module_enumerate_symbols;
  iface->enumerate_ranges = gum_native_module_enumerate_ranges;
  iface->enumerate_sections = gum_native_module_enumerate_sections;
  iface->enumerate_dependencies = gum_native_module_enumerate_dependencies;
  iface->find_export_by_name = gum_native_module_find_export_by_name;
}

static void
gum_native_module_init (GumNativeModule * self)
{
}

static void
gum_native_module_finalize (GObject * object)
{
  GumNativeModule * self = GUM_NATIVE_MODULE (object);

  g_free (self->path);

  G_OBJECT_CLASS (gum_native_module_parent_class)->finalize (object);
}

GumModule *
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Not supported by the Barebone backend");
  return NULL;
}

static const gchar *
gum_native_module_get_name (GumModule * module)
{
  return GUM_NATIVE_MODULE (module)->name;
}

static const gchar *
gum_native_module_get_path (GumModule * module)
{
  return GUM_NATIVE_MODULE (module)->path;
}

static const GumMemoryRange *
gum_native_module_get_range (GumModule * module)
{
  return &GUM_NATIVE_MODULE (module)->range;
}

static void
gum_native_module_ensure_initialized (GumModule * module)
{
}

static void
gum_native_module_enumerate_imports (GumModule * module,
                                     GumFoundImportFunc func,
                                     gpointer user_data)
{
}

static void
gum_native_module_enumerate_exports (GumModule * module,
                                     GumFoundExportFunc func,
                                     gpointer user_data)
{
}

static void
gum_native_module_enumerate_symbols (GumModule * module,
                                     GumFoundSymbolFunc func,
                                     gpointer user_data)
{
}

static void
gum_native_module_enumerate_ranges (GumModule * module,
                                    GumPageProtection prot,
                                    GumFoundRangeFunc func,
                                    gpointer user_data)
{
}

static void
gum_native_module_enumerate_sections (GumModule * module,
                                      GumFoundSectionFunc func,
                                      gpointer user_data)
{
}

static void
gum_native_module_enumerate_dependencies (GumModule * module,
                                          GumFoundDependencyFunc func,
                                          gpointer user_data)
{
}

static GumAddress
gum_native_module_find_export_by_name (GumModule * module,
                                       const gchar * symbol_name)
{
  return 0;
}

GumAddress
gum_module_find_global_export_by_name (const gchar * symbol_name)
{
  return 0;
}
