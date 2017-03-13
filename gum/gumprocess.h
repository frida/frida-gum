/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_H__
#define __GUM_PROCESS_H__

#include <gum/gummemory.h>

typedef gsize GumThreadId;
typedef guint GumThreadState;
typedef struct _GumThreadDetails GumThreadDetails;
typedef struct _GumModuleDetails GumModuleDetails;
typedef guint GumImportType;
typedef guint GumExportType;
typedef struct _GumImportDetails GumImportDetails;
typedef struct _GumExportDetails GumExportDetails;
typedef struct _GumRangeDetails GumRangeDetails;
typedef struct _GumFileMapping GumFileMapping;
typedef struct _GumMallocRangeDetails GumMallocRangeDetails;

enum _GumThreadState
{
  GUM_THREAD_RUNNING = 1,
  GUM_THREAD_STOPPED,
  GUM_THREAD_WAITING,
  GUM_THREAD_UNINTERRUPTIBLE,
  GUM_THREAD_HALTED
};

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

struct _GumImportDetails
{
  GumImportType type;
  const gchar * name;
  const gchar * module;
  GumAddress address;
};

struct _GumExportDetails
{
  GumExportType type;
  const gchar * name;
  GumAddress address;
};

struct _GumRangeDetails
{
  const GumMemoryRange * range;
  GumPageProtection prot;
  const GumFileMapping * file;
};

struct _GumFileMapping
{
  const gchar * path;
  guint64 offset;
};

struct _GumMallocRangeDetails
{
  const GumMemoryRange * range;
};

G_BEGIN_DECLS

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
typedef gboolean (* GumFoundRangeFunc) (const GumRangeDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundMallocRangeFunc) (
    const GumMallocRangeDetails * details, gpointer user_data);

GUM_API GumOS gum_process_get_native_os (void);
GUM_API gboolean gum_process_is_debugger_attached (void);
GUM_API GumThreadId gum_process_get_current_thread_id (void);
GUM_API gboolean gum_process_modify_thread (GumThreadId thread_id,
    GumModifyThreadFunc func, gpointer user_data);
GUM_API void gum_process_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data);
GUM_API void gum_process_enumerate_modules (GumFoundModuleFunc func,
    gpointer user_data);
GUM_API void gum_process_enumerate_ranges (GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_process_enumerate_malloc_ranges (
    GumFoundMallocRangeFunc func, gpointer user_data);
GUM_API gboolean gum_thread_try_get_range (GumMemoryRange * range);
GUM_API gint gum_thread_get_system_error (void);
GUM_API void gum_thread_set_system_error (gint value);
GUM_API void gum_module_enumerate_imports (const gchar * module_name,
    GumFoundImportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_exports (const gchar * module_name,
    GumFoundExportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_ranges (const gchar * module_name,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
GUM_API GumAddress gum_module_find_base_address (const gchar * module_name);
GUM_API GumAddress gum_module_find_export_by_name (const gchar * module_name,
    const gchar * symbol_name);

G_END_DECLS

#endif
