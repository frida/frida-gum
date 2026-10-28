/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PE_MODULE_H__
#define __GUM_PE_MODULE_H__

#include <gum/gumdefs.h>
#include <gum/gummemory.h>
#include <gum/gummodule.h>

G_BEGIN_DECLS

#define GUM_TYPE_PE_MODULE (gum_pe_module_get_type ())
G_DECLARE_FINAL_TYPE (GumPeModule, gum_pe_module, GUM, PE_MODULE, GObject)

typedef enum {
  GUM_PE_MACHINE_UNKNOWN = 0x0000,
  GUM_PE_MACHINE_I386    = 0x014c,
  GUM_PE_MACHINE_ARMNT   = 0x01c4,
  GUM_PE_MACHINE_AMD64   = 0x8664,
  GUM_PE_MACHINE_ARM64   = 0xaa64,
} GumPeMachine;

typedef enum {
  GUM_PE_SOURCE_MODE_OFFLINE,
  GUM_PE_SOURCE_MODE_ONLINE,
} GumPeSourceMode;

typedef enum {
  GUM_PE_DIRECTORY_EXPORT       = 0,
  GUM_PE_DIRECTORY_IMPORT       = 1,
  GUM_PE_DIRECTORY_EXCEPTION    = 3,
  GUM_PE_DIRECTORY_BASERELOC    = 5,
  GUM_PE_DIRECTORY_TLS          = 9,
  GUM_PE_DIRECTORY_LOAD_CONFIG  = 10,
  GUM_PE_DIRECTORY_DELAY_IMPORT = 13,
} GumPeDirectoryIndex;

typedef enum {
  GUM_PE_RELOCATION_ABSOLUTE = 0,
  GUM_PE_RELOCATION_HIGH     = 1,
  GUM_PE_RELOCATION_LOW      = 2,
  GUM_PE_RELOCATION_HIGHLOW  = 3,
  GUM_PE_RELOCATION_HIGHADJ  = 4,
  GUM_PE_RELOCATION_DIR64    = 10,
} GumPeRelocationType;

typedef enum {
  GUM_PE_IMPORT_BY_NAME,
  GUM_PE_IMPORT_BY_ORDINAL,
} GumPeImportType;

typedef enum {
  GUM_PE_IMPORT_LOAD_MODE_REGULAR,
  GUM_PE_IMPORT_LOAD_MODE_DELAYED,
} GumPeImportLoadMode;

typedef enum {
  GUM_PE_EXPORT_REGULAR,
  GUM_PE_EXPORT_FORWARDED,
} GumPeExportType;

typedef struct _GumPeDataDirectory GumPeDataDirectory;
typedef struct _GumPeSectionDetails GumPeSectionDetails;
typedef struct _GumPeRelocationDetails GumPeRelocationDetails;
typedef struct _GumPeImportDetails GumPeImportDetails;
typedef struct _GumPeExportDetails GumPeExportDetails;
typedef struct _GumPeTlsDetails GumPeTlsDetails;

typedef gboolean (* GumFoundPeSectionFunc) (
    const GumPeSectionDetails * details, gpointer user_data);
typedef gboolean (* GumFoundPeRelocationFunc) (
    const GumPeRelocationDetails * details, gpointer user_data);
typedef gboolean (* GumFoundPeImportFunc) (
    const GumPeImportDetails * details, gpointer user_data);
typedef gboolean (* GumFoundPeExportFunc) (
    const GumPeExportDetails * details, gpointer user_data);
typedef gboolean (* GumFoundPeTlsCallbackFunc) (GumAddress rva,
    gpointer user_data);
typedef gboolean (* GumFoundPeFunctionStartFunc) (GumAddress rva,
    gpointer user_data);

struct _GumPeDataDirectory
{
  guint32 rva;
  guint32 size;
};

struct _GumPeSectionDetails
{
  const gchar * name;
  guint32 virtual_address;
  guint32 virtual_size;
  guint32 raw_data_offset;
  guint32 raw_data_size;
  guint32 characteristics;
  GumPageProtection protection;
};

struct _GumPeRelocationDetails
{
  guint32 rva;
  GumPeRelocationType type;
};

struct _GumPeImportDetails
{
  GumPeImportType type;
  GumPeImportLoadMode load_mode;
  const gchar * module_name;
  guint32 slot_rva;

  union
  {
    const gchar * name;
    guint16 ordinal;
  };
};

struct _GumPeExportDetails
{
  GumPeExportType type;
  guint16 ordinal;
  const gchar * name;

  union
  {
    guint32 rva;
    const gchar * forwarder;
  };
};

struct _GumPeTlsDetails
{
  guint32 template_rva;
  gsize template_size;
  guint32 index_rva;
};

GUM_API GumPeModule * gum_pe_module_new_from_file (const gchar * path,
    GError ** error);
GUM_API GumPeModule * gum_pe_module_new_from_blob (GBytes * blob,
    GError ** error);
GUM_API GumPeModule * gum_pe_module_new_from_memory (GumAddress base_address,
    GError ** error);

GUM_API guint gum_pe_module_get_pointer_size (GumPeModule * self);
GUM_API GumPeMachine gum_pe_module_get_machine (GumPeModule * self);
GUM_API guint64 gum_pe_module_get_image_base (GumPeModule * self);
GUM_API gsize gum_pe_module_get_size_of_image (GumPeModule * self);
GUM_API gsize gum_pe_module_get_size_of_headers (GumPeModule * self);
GUM_API guint32 gum_pe_module_get_entrypoint (GumPeModule * self);
GUM_API GBytes * gum_pe_module_get_source_blob (GumPeModule * self);
GUM_API GumPeSourceMode gum_pe_module_get_source_mode (GumPeModule * self);
GUM_API const GumPeDataDirectory * gum_pe_module_get_directory (
    GumPeModule * self, GumPeDirectoryIndex index);
GUM_API gconstpointer gum_pe_module_get_data_at_rva (GumPeModule * self,
    guint32 rva);

GUM_API void gum_pe_module_enumerate_sections (GumPeModule * self,
    GumFoundPeSectionFunc func, gpointer user_data);
GUM_API void gum_pe_module_enumerate_relocations (GumPeModule * self,
    GumFoundPeRelocationFunc func, gpointer user_data);
GUM_API void gum_pe_module_enumerate_imports (GumPeModule * self,
    GumFoundPeImportFunc func, gpointer user_data);
GUM_API gboolean gum_pe_module_find_export_by_name (GumPeModule * self,
    const gchar * name, GumPeExportDetails * details);
GUM_API void gum_pe_module_enumerate_exports (GumPeModule * self,
    GumFoundPeExportFunc func, gpointer user_data);
GUM_API gboolean gum_pe_module_get_tls_details (GumPeModule * self,
    GumPeTlsDetails * details);
GUM_API void gum_pe_module_enumerate_tls_callbacks (GumPeModule * self,
    GumFoundPeTlsCallbackFunc func, gpointer user_data);
GUM_API guint32 gum_pe_module_get_security_cookie_rva (GumPeModule * self);
GUM_API guint32 gum_pe_module_get_chpe_metadata_rva (GumPeModule * self);
GUM_API void gum_pe_module_enumerate_dependencies (GumPeModule * self,
    GumFoundDependencyFunc func, gpointer user_data);
GUM_API guint gum_pe_module_get_function_count (GumPeModule * self);
GUM_API void gum_pe_module_enumerate_function_starts (GumPeModule * self,
    GumFoundPeFunctionStartFunc func, gpointer user_data);

G_END_DECLS

#endif
