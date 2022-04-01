/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gumcloak.h"

typedef struct _GumEmitThreadsContext GumEmitThreadsContext;
typedef struct _GumResolveModulePointerContext GumResolveModulePointerContext;
typedef struct _GumEmitRangesContext GumEmitRangesContext;
typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

struct _GumEmitThreadsContext
{
  GumFoundThreadFunc func;
  gpointer user_data;
};

struct _GumResolveModulePointerContext
{
  gconstpointer ptr;
  gboolean success;
  gchar ** path;
  GumMemoryRange * range;
};

struct _GumEmitRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

static gboolean gum_emit_thread_if_not_cloaked (
    const GumThreadDetails * details, gpointer user_data);
static gboolean gum_try_resolve_module_pointer_from (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
    gpointer user_data);
static gboolean gum_store_address_if_name_matches (
    const GumSymbolDetails * details, gpointer user_data);

static GumCodeSigningPolicy gum_code_signing_policy = GUM_CODE_SIGNING_OPTIONAL;

GUM_DEFINE_BOXED_TYPE (GumModuleDetails, gum_module_details,
                       gum_module_details_copy, gum_module_details_free)

GumOS
gum_process_get_native_os (void)
{
#if defined (HAVE_WINDOWS)
  return GUM_OS_WINDOWS;
#elif defined (HAVE_MACOS)
  return GUM_OS_MACOS;
#elif defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  return GUM_OS_LINUX;
#elif defined (HAVE_IOS)
  return GUM_OS_IOS;
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
 *
 * Enumerates all threads, calling @func with #GumThreadDetails about each
 * thread found.
 */
void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data)
{
  GumEmitThreadsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_threads (gum_emit_thread_if_not_cloaked, &ctx);
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
 * gum_process_resolve_module_pointer:
 * @ptr: memory location potentially belonging to a module
 * @path: (out) (optional): absolute path of module
 * @range: (out caller-allocates) (optional): memory range of module
 *
 * Determines which module @ptr belongs to, if any.
 *
 * Returns: whether the pointer resolved to a module
 */
gboolean
gum_process_resolve_module_pointer (gconstpointer ptr,
                                    gchar ** path,
                                    GumMemoryRange * range)
{
  GumResolveModulePointerContext ctx = {
    .ptr = ptr,
    .success = FALSE,
    .path = path,
    .range = range
  };

  gum_process_enumerate_modules (gum_try_resolve_module_pointer_from, &ctx);

  return ctx.success;
}

static gboolean
gum_try_resolve_module_pointer_from (const GumModuleDetails * details,
                                     gpointer user_data)
{
  GumResolveModulePointerContext * ctx = user_data;

  if (GUM_MEMORY_RANGE_INCLUDES (details->range, GUM_ADDRESS (ctx->ptr)))
  {
    ctx->success = TRUE;

    if (ctx->path != NULL)
      *ctx->path = g_strdup (details->path);

    if (ctx->range != NULL)
      *ctx->range = *details->range;

    return FALSE;
  }

  return TRUE;
}

/**
 * gum_process_enumerate_modules:
 * @func: (scope call): function called with #GumModuleDetails
 * @user_data: data to pass to @func
 *
 * Enumerates modules loaded right now, calling @func with #GumModuleDetails
 * about each module found.
 */

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
 * @module_name: name of module
 * @func: (scope call): function called with #GumImportDetails
 * @user_data: data to pass to @func
 *
 * Enumerates imports of the specified module, calling @func with
 * #GumImportDetails about each import found.
 */

/**
 * gum_module_enumerate_exports:
 * @module_name: name of module
 * @func: (scope call): function called with #GumExportDetails
 * @user_data: data to pass to @func
 *
 * Enumerates exports of the specified module, calling @func with
 * #GumExportDetails about each export found.
 */

/**
 * gum_module_enumerate_symbols:
 * @module_name: name of module
 * @func: (scope call): function called with #GumSymbolDetails
 * @user_data: data to pass to @func
 *
 * Enumerates symbols of the specified module, calling @func with
 * #GumSymbolDetails about each symbol found.
 */

/**
 * gum_module_enumerate_ranges:
 * @module_name: name of module
 * @prot: bitfield specifying the minimum protection
 * @func: (scope call): function called with #GumRangeDetails
 * @user_data: data to pass to @func
 *
 * Enumerates memory ranges of the specified module that satisfy @prot,
 * calling @func with #GumRangeDetails about each such range found.
 */

GumAddress
gum_module_find_symbol_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumResolveSymbolContext ctx;

  ctx.name = symbol_name;
  ctx.result = 0;

  gum_module_enumerate_symbols (module_name, gum_store_address_if_name_matches,
      &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}

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

GumModuleDetails *
gum_module_details_copy (const GumModuleDetails * module)
{
  GumModuleDetails * copy;

  copy = g_slice_new (GumModuleDetails);

  copy->name = g_strdup (module->name);
  copy->range = gum_memory_range_copy (module->range);
  copy->path = g_strdup (module->path);

  return copy;
}

void
gum_module_details_free (GumModuleDetails * module)
{
  if (module == NULL)
    return;

  g_free ((gpointer) module->name);
  gum_memory_range_free ((GumMemoryRange *) module->range);
  g_free ((gpointer) module->path);

  g_slice_free (GumModuleDetails, module);
}

const gchar *
gum_symbol_type_to_string (GumSymbolType type)
{
  switch (type)
  {
    /* Common */
    case GUM_SYMBOL_UNKNOWN:            return "unknown";
    case GUM_SYMBOL_SECTION:            return "section";

    /* Mach-O */
    case GUM_SYMBOL_UNDEFINED:          return "undefined";
    case GUM_SYMBOL_ABSOLUTE:           return "absolute";
    case GUM_SYMBOL_PREBOUND_UNDEFINED: return "prebound-undefined";
    case GUM_SYMBOL_INDIRECT:           return "indirect";

    /* ELF */
    case GUM_SYMBOL_OBJECT:             return "object";
    case GUM_SYMBOL_FUNCTION:           return "function";
    case GUM_SYMBOL_FILE:               return "file";
    case GUM_SYMBOL_COMMON:             return "common";
    case GUM_SYMBOL_TLS:                return "tls";
  }

  g_assert_not_reached ();
  return NULL;
}
