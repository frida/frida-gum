/*
 * Copyright (C) 2015-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023-2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gum-init.h"
#include "gumcloak.h"
#include "gummoduleregistry.h"

#ifndef HAVE_WINDOWS
# define GUM_OS_LACKS_MODULE_LOOKUP_APIS 1
#endif

typedef struct _GumEmitThreadsContext GumEmitThreadsContext;
#ifdef GUM_OS_LACKS_MODULE_LOOKUP_APIS
typedef struct _GumFindModuleByNameContext GumFindModuleByNameContext;
typedef struct _GumFindModuleByAddressContext GumFindModuleByAddressContext;
#endif
typedef struct _GumEmitRangesContext GumEmitRangesContext;

struct _GumEmitThreadsContext
{
  GumFoundThreadFunc func;
  gpointer user_data;
};

#ifdef GUM_OS_LACKS_MODULE_LOOKUP_APIS
struct _GumFindModuleByNameContext
{
  const gchar * name;
  GumModule * module;
};

struct _GumFindModuleByAddressContext
{
  GumAddress address;
  GumModule * module;
};
#endif

struct _GumEmitRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
};

static gboolean gum_emit_thread_if_not_cloaked (
    const GumThreadDetails * details, gpointer user_data);
static void gum_deinit_main_module (void);
#ifdef GUM_OS_LACKS_MODULE_LOOKUP_APIS
static gboolean gum_try_resolve_module_by_name (GumModule * module,
    gpointer user_data);
static gboolean gum_try_resolve_module_by_path (GumModule * module,
    gpointer user_data);
static gboolean gum_try_resolve_module_by_address (GumModule * module,
    gpointer user_data);
#endif
static gboolean gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
    gpointer user_data);

static GumTeardownRequirement gum_teardown_requirement =
    GUM_TEARDOWN_REQUIREMENT_FULL;
static GumCodeSigningPolicy gum_code_signing_policy = GUM_CODE_SIGNING_OPTIONAL;

G_DEFINE_BOXED_TYPE (GumThreadDetails, gum_thread_details,
                     gum_thread_details_copy, gum_thread_details_free)

GumOS
gum_process_get_native_os (void)
{
#if defined (G_OS_NONE)
  return GUM_OS_NONE;
#elif defined (HAVE_WINDOWS)
  return GUM_OS_WINDOWS;
#elif defined (HAVE_MACOS)
  return GUM_OS_MACOS;
#elif defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  return GUM_OS_LINUX;
#elif defined (HAVE_IOS)
  return GUM_OS_IOS;
#elif defined (HAVE_WATCHOS)
  return GUM_OS_WATCHOS;
#elif defined (HAVE_TVOS)
  return GUM_OS_TVOS;
#elif defined (HAVE_ANDROID)
  return GUM_OS_ANDROID;
#elif defined (HAVE_FREEBSD)
  return GUM_OS_FREEBSD;
#elif defined (HAVE_QNX)
  return GUM_OS_QNX;
#else
# error Unknown OS
#endif
}

GumTeardownRequirement
gum_process_get_teardown_requirement (void)
{
  return gum_teardown_requirement;
}

void
gum_process_set_teardown_requirement (GumTeardownRequirement requirement)
{
  gum_teardown_requirement = requirement;
}

GumCodeSigningPolicy
gum_process_get_code_signing_policy (void)
{
  return gum_code_signing_policy;
}

void
gum_process_set_code_signing_policy (GumCodeSigningPolicy policy)
{
  gum_code_signing_policy = policy;
}

/**
 * gum_process_modify_thread:
 * @thread_id: ID of thread to modify
 * @func: (scope call): function to apply the modifications
 * @user_data: data to pass to @func
 * @flags: flags to customize behavior
 *
 * Modifies a given thread by first pausing it, reading its state, and then
 * passing that to @func, followed by writing back the new state and then
 * resuming the thread. May also be used to inspect the current state without
 * modifying it.
 *
 * Returns: whether the modifications were successfully applied
 */

/**
 * gum_process_enumerate_threads:
 * @func: (scope call): function called with #GumThreadDetails
 * @user_data: data to pass to @func
 * @flags: flags specifying the desired level of detail
 *
 * Enumerates all threads, calling @func with #GumThreadDetails about each
 * thread found.
 */
void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data,
                               GumThreadFlags flags)
{
  GumEmitThreadsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_threads (gum_emit_thread_if_not_cloaked, &ctx, flags);
}

static gboolean
gum_emit_thread_if_not_cloaked (const GumThreadDetails * details,
                                gpointer user_data)
{
  GumEmitThreadsContext * ctx = user_data;

  if (gum_cloak_has_thread (details->id))
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

/**
 * gum_process_get_main_module:
 *
 * Returns module representing the main executable of the process.
 */
GumModule *
gum_process_get_main_module (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    GumModule * result;

    gum_process_enumerate_modules (_gum_process_collect_main_module, &result);

    _gum_register_destructor (gum_deinit_main_module);

    g_once_init_leave (&cached_result, GPOINTER_TO_SIZE (result) + 1);
  }

  return GSIZE_TO_POINTER (cached_result - 1);
}

static void
gum_deinit_main_module (void)
{
  g_object_unref (gum_process_get_main_module ());
}

/**
 * gum_process_find_module_by_name:
 * @name: name of a currently loaded module
 *
 * Finds a currently loaded module by name or filesystem path.
 *
 * Returns: (transfer full) (nullable): module matching @name, or %NULL if none
 *   was found
 */
#ifdef GUM_OS_LACKS_MODULE_LOOKUP_APIS
GumModule *
gum_process_find_module_by_name (const gchar * name)
{
  GumFindModuleByNameContext ctx = {
    .name = name,
    .module = NULL
  };

  if (g_path_is_absolute (name))
    gum_process_enumerate_modules (gum_try_resolve_module_by_path, &ctx);
  else
    gum_process_enumerate_modules (gum_try_resolve_module_by_name, &ctx);

  return ctx.module;
}

static gboolean
gum_try_resolve_module_by_name (GumModule * module,
                                gpointer user_data)
{
  GumFindModuleByNameContext * ctx = user_data;

  if (strcmp (gum_module_get_name (module), ctx->name) == 0)
  {
    ctx->module = g_object_ref (module);
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_try_resolve_module_by_path (GumModule * module,
                                gpointer user_data)
{
  GumFindModuleByNameContext * ctx = user_data;

  if (strcmp (gum_module_get_path (module), ctx->name) == 0)
  {
    ctx->module = g_object_ref (module);
    return FALSE;
  }

  return TRUE;
}
#endif

/**
 * gum_process_find_module_by_address:
 * @address: memory address potentially belonging to a module
 *
 * Determines which module @address belongs to, if any. Note that #ModuleMap is
 * more efficient for repeated lookups.
 *
 * Returns: (transfer full) (nullable): module containing @address, or %NULL if
 *   none was found
 */
#ifdef GUM_OS_LACKS_MODULE_LOOKUP_APIS
GumModule *
gum_process_find_module_by_address (GumAddress address)
{
  GumFindModuleByAddressContext ctx = {
    .address = address,
    .module = NULL
  };

  gum_process_enumerate_modules (gum_try_resolve_module_by_address, &ctx);

  return ctx.module;
}

static gboolean
gum_try_resolve_module_by_address (GumModule * module,
                                   gpointer user_data)
{
  GumFindModuleByAddressContext * ctx = user_data;
  const GumMemoryRange * range;

  range = gum_module_get_range (module);

  if (GUM_MEMORY_RANGE_INCLUDES (range, ctx->address))
  {
    ctx->module = g_object_ref (module);
    return FALSE;
  }

  return TRUE;
}
#endif

/**
 * gum_process_enumerate_modules:
 * @func: (scope call): function called with #GumModule
 * @user_data: data to pass to @func
 *
 * Enumerates modules loaded right now, calling @func with each #GumModule
 * found.
 */
void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  gum_module_registry_enumerate_modules (gum_module_registry_obtain (), func,
      user_data);
}

/**
 * gum_process_enumerate_ranges:
 * @prot: bitfield specifying the minimum protection
 * @func: (scope call): function called with #GumRangeDetails
 * @user_data: data to pass to @func
 *
 * Enumerates memory ranges satisfying @prot, calling @func with
 * #GumRangeDetails about each such range found.
 */
void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  GumEmitRangesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_ranges (prot, gum_emit_range_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
                               gpointer user_data)
{
  GumEmitRangesContext * ctx = user_data;
  GArray * sub_ranges;

  sub_ranges = gum_cloak_clip_range (details->range);
  if (sub_ranges != NULL)
  {
    gboolean carry_on = TRUE;
    GumRangeDetails sub_details;
    guint i;

    sub_details.protection = details->protection;
    sub_details.file = details->file;

    for (i = 0; i != sub_ranges->len && carry_on; i++)
    {
      sub_details.range = &g_array_index (sub_ranges, GumMemoryRange, i);

      carry_on = ctx->func (&sub_details, ctx->user_data);
    }

    g_array_free (sub_ranges, TRUE);

    return carry_on;
  }

  return ctx->func (details, ctx->user_data);
}

/**
 * gum_process_enumerate_malloc_ranges:
 * @func: (scope call): function called with #GumMallocRangeDetails
 * @user_data: data to pass to @func
 *
 * Enumerates individual memory allocations known to the system heap, calling
 * @func with #GumMallocRangeDetails about each range found.
 */

/**
 * gum_module_enumerate_imports:
 * @module: module
 * @func: (scope call): function called with #GumImportDetails
 * @user_data: data to pass to @func
 *
 * Enumerates imports of the specified module, calling @func with
 * #GumImportDetails about each import found.
 */

/**
 * gum_module_enumerate_exports:
 * @module: module
 * @func: (scope call): function called with #GumExportDetails
 * @user_data: data to pass to @func
 *
 * Enumerates exports of the specified module, calling @func with
 * #GumExportDetails about each export found.
 */

/**
 * gum_module_enumerate_symbols:
 * @module: module
 * @func: (scope call): function called with #GumSymbolDetails
 * @user_data: data to pass to @func
 *
 * Enumerates symbols of the specified module, calling @func with
 * #GumSymbolDetails about each symbol found.
 */

/**
 * gum_module_enumerate_ranges:
 * @self: module
 * @prot: bitfield specifying the minimum protection
 * @func: (scope call): function called with #GumRangeDetails
 * @user_data: data to pass to @func
 *
 * Enumerates memory ranges of the specified module that satisfy @prot,
 * calling @func with #GumRangeDetails about each such range found.
 */

const gchar *
gum_code_signing_policy_to_string (GumCodeSigningPolicy policy)
{
  switch (policy)
  {
    case GUM_CODE_SIGNING_OPTIONAL: return "optional";
    case GUM_CODE_SIGNING_REQUIRED: return "required";
  }

  g_assert_not_reached ();
  return NULL;
}

GumThreadDetails *
gum_thread_details_copy (const GumThreadDetails * details)
{
  GumThreadDetails * d;

  d = g_slice_dup (GumThreadDetails, details);
  d->name = g_strdup (details->name);

  return d;
}

void
gum_thread_details_free (GumThreadDetails * details)
{
  g_free ((gpointer) details->name);
  g_slice_free (GumThreadDetails, details);
}
