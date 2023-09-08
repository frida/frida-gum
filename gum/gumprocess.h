/*
 * Copyright (C) 2008-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_H__
#define __GUM_PROCESS_H__

#include <gum/gummemory.h>

#define GUM_THREAD_ID_INVALID ((GumThreadId) -1)

#define GUM_TYPE_MODULE_DETAILS (gum_module_details_get_type ())

G_BEGIN_DECLS

typedef guint GumProcessId;
typedef gsize GumThreadId;
typedef struct _GumThreadDetails GumThreadDetails;
typedef struct _GumModuleDetails GumModuleDetails;
typedef guint GumImportType;
typedef guint GumExportType;
typedef guint GumSymbolType;
typedef struct _GumImportDetails GumImportDetails;
typedef struct _GumExportDetails GumExportDetails;
typedef struct _GumSymbolDetails GumSymbolDetails;
typedef struct _GumSymbolSection GumSymbolSection;
typedef struct _GumRangeDetails GumRangeDetails;
typedef struct _GumFileMapping GumFileMapping;
typedef struct _GumSectionDetails GumSectionDetails;
typedef struct _GumMallocRangeDetails GumMallocRangeDetails;

typedef enum {
  GUM_CODE_SIGNING_OPTIONAL,
  GUM_CODE_SIGNING_REQUIRED
} GumCodeSigningPolicy;

typedef enum {
  GUM_MODIFY_THREAD_FLAGS_NONE         = 0,
  GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY = (1 << 0),
} GumModifyThreadFlags;

typedef enum {
  GUM_THREAD_RUNNING = 1,
  GUM_THREAD_STOPPED,
  GUM_THREAD_WAITING,
  GUM_THREAD_UNINTERRUPTIBLE,
  GUM_THREAD_HALTED
} GumThreadState;

struct _GumThreadDetails
{
  GumThreadId id;
  GumThreadState state;
  GumCpuContext cpu_context;
};

struct _GumModuleDetails
{
  const gchar * name;
  const GumMemoryRange * range;
  const gchar * path;
};

enum _GumImportType
{
  GUM_IMPORT_UNKNOWN,
  GUM_IMPORT_FUNCTION,
  GUM_IMPORT_VARIABLE
};

enum _GumExportType
{
  GUM_EXPORT_FUNCTION = 1,
  GUM_EXPORT_VARIABLE
};

enum _GumSymbolType
{
  /* Common */
  GUM_SYMBOL_UNKNOWN,
  GUM_SYMBOL_SECTION,

  /* Mach-O */
  GUM_SYMBOL_UNDEFINED,
  GUM_SYMBOL_ABSOLUTE,
  GUM_SYMBOL_PREBOUND_UNDEFINED,
  GUM_SYMBOL_INDIRECT,

  /* ELF */
  GUM_SYMBOL_OBJECT,
  GUM_SYMBOL_FUNCTION,
  GUM_SYMBOL_FILE,
  GUM_SYMBOL_COMMON,
  GUM_SYMBOL_TLS,
};

struct _GumImportDetails
{
  GumImportType type;
  const gchar * name;
  const gchar * module;
  GumAddress address;
  GumAddress slot;
};

struct _GumExportDetails
{
  GumExportType type;
  const gchar * name;
  GumAddress address;
};

struct _GumSymbolDetails
{
  gboolean is_global;
  GumSymbolType type;
  const GumSymbolSection * section;
  const gchar * name;
  GumAddress address;
  gssize size;
};

struct _GumSymbolSection
{
  const gchar * id;
  GumPageProtection protection;
};

struct _GumRangeDetails
{
  const GumMemoryRange * range;
  GumPageProtection protection;
  const GumFileMapping * file;
};

struct _GumFileMapping
{
  const gchar * path;
  guint64 offset;
  gsize size;
};

struct _GumSectionDetails
{
  const gchar * id;
  const gchar * name;
  GumAddress address;
  gsize size;
};

struct _GumMallocRangeDetails
{
  const GumMemoryRange * range;
};

typedef void (* GumModifyThreadFunc) (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
typedef gboolean (* GumFoundThreadFunc) (const GumThreadDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundModuleFunc) (const GumModuleDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundImportFunc) (const GumImportDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundExportFunc) (const GumExportDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundSymbolFunc) (const GumSymbolDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundRangeFunc) (const GumRangeDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundSectionFunc) (const GumSectionDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundMallocRangeFunc) (
    const GumMallocRangeDetails * details, gpointer user_data);
typedef GumAddress (* GumResolveExportFunc) (const char * module_name,
    const char * symbol_name, gpointer user_data);

GUM_API GumOS gum_process_get_native_os (void);
GUM_API GumCodeSigningPolicy gum_process_get_code_signing_policy (void);
GUM_API void gum_process_set_code_signing_policy (GumCodeSigningPolicy policy);
GUM_API const gchar * gum_process_query_libc_name (void);
GUM_API gboolean gum_process_is_debugger_attached (void);
GUM_API GumProcessId gum_process_get_id (void);
GUM_API GumThreadId gum_process_get_current_thread_id (void);
GUM_API gboolean gum_process_has_thread (GumThreadId thread_id);
GUM_API gboolean gum_process_modify_thread (GumThreadId thread_id,
    GumModifyThreadFunc func, gpointer user_data, GumModifyThreadFlags flags);
GUM_API void gum_process_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data);
GUM_API gboolean gum_process_resolve_module_pointer (gconstpointer ptr,
    gchar ** path, GumMemoryRange * range);
GUM_API void gum_process_enumerate_modules (GumFoundModuleFunc func,
    gpointer user_data);
GUM_API void gum_process_enumerate_ranges (GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_process_enumerate_malloc_ranges (
    GumFoundMallocRangeFunc func, gpointer user_data);
GUM_API guint gum_thread_try_get_ranges (GumMemoryRange * ranges,
    guint max_length);
GUM_API gint gum_thread_get_system_error (void);
GUM_API void gum_thread_set_system_error (gint value);
GUM_API gboolean gum_thread_suspend (GumThreadId thread_id, GError ** error);
GUM_API gboolean gum_thread_resume (GumThreadId thread_id, GError ** error);
GUM_API gboolean gum_module_load (const gchar * module_name, GError ** error);
GUM_API gboolean gum_module_ensure_initialized (const gchar * module_name);
GUM_API void gum_module_enumerate_imports (const gchar * module_name,
    GumFoundImportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_exports (const gchar * module_name,
    GumFoundExportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_symbols (const gchar * module_name,
    GumFoundSymbolFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_ranges (const gchar * module_name,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_sections (const gchar * module_name,
    GumFoundSectionFunc func, gpointer user_data);
GUM_API GumAddress gum_module_find_base_address (const gchar * module_name);
GUM_API GumAddress gum_module_find_export_by_name (const gchar * module_name,
    const gchar * symbol_name);
GUM_API GumAddress gum_module_find_symbol_by_name (const gchar * module_name,
    const gchar * symbol_name);

GUM_API const gchar * gum_code_signing_policy_to_string (
    GumCodeSigningPolicy policy);

#ifndef GUM_DIET
GUM_API GType gum_module_details_get_type (void) G_GNUC_CONST;
#endif
GUM_API GumModuleDetails * gum_module_details_copy (
    const GumModuleDetails * module);
GUM_API void gum_module_details_free (GumModuleDetails * module);

GUM_API const gchar * gum_symbol_type_to_string (GumSymbolType type);

G_END_DECLS

#endif
