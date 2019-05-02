/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumandroid.h"

#include "gumlinux.h"

#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <sys/system_properties.h>

#if (defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4) || defined (HAVE_ARM)
# define GUM_ANDROID_LEGACY_SOINFO 1
#endif

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_ANDROID_LINKER_MODULE_NAME "/system/bin/linker"
#else
# define GUM_ANDROID_LINKER_MODULE_NAME "/system/bin/linker64"
#endif
#define GUM_ANDROID_VDSO_MODULE_NAME "linux-vdso.so.1"

typedef struct _GumInitLinkerBaseContext GumInitLinkerBaseContext;
typedef struct _GumGetModuleHandleContext GumGetModuleHandleContext;
typedef struct _GumEnsureModuleInitializedContext
    GumEnsureModuleInitializedContext;
typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;

typedef struct _GumSoinfoDetails GumSoinfoDetails;
typedef gboolean (* GumFoundSoinfoFunc) (const GumSoinfoDetails * details,
    gpointer user_data);

typedef enum _GumLinkerFlavor GumLinkerFlavor;
typedef struct _GumLinkerApi GumLinkerApi;
typedef struct _GumProtectedDataGuard GumProtectedDataGuard;
typedef struct _GumSoinfo GumSoinfo;

struct _GumInitLinkerBaseContext
{
  gboolean found_vdso;
  gpointer linker_base;
};

struct _GumGetModuleHandleContext
{
  const gchar * name;
  void * module;
};

struct _GumEnsureModuleInitializedContext
{
  const gchar * name;
  gboolean success;
};

struct _GumEnumerateModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;
};

struct _GumSoinfoDetails
{
  const gchar * path;
  GumSoinfo * si;
  GumLinkerApi * api;
};

enum _GumLinkerFlavor
{
  GUM_LINKER_MODERN,
  GUM_LINKER_LEGACY,
};

struct _GumLinkerApi
{
  GumLinkerFlavor flavor;

  GumAndroidDlopenImpl dlopen;
  GumAndroidDlsymImpl dlsym;
  gpointer trusted_caller;

  pthread_mutex_t * dl_mutex;

  void (* guard_init) (GumProtectedDataGuard * guard);
  void (* guard_clear) (GumProtectedDataGuard * guard);

  GumSoinfo * (* solist_get_head) (void);
  GumSoinfo * libdl_info;
  GumSoinfo * (* solist_get_somain) (void);
  GumSoinfo ** somain;

  gsize (* soinfo_ref) (GumSoinfo * si);
  const gchar * (* soinfo_get_path) (GumSoinfo * si);
  void (* soinfo_call_ctors) (GumSoinfo * si);
  void * (* soinfo_to_handle) (GumSoinfo * si);
};

struct _GumProtectedDataGuard
{
  gpointer unused[2];
};

struct _GumSoinfo
{
#ifdef GUM_ANDROID_LEGACY_SOINFO
  gchar old_name_[128];
#endif
  gpointer phdr;
  gsize phnum;
#ifdef GUM_ANDROID_LEGACY_SOINFO
  gpointer unused0;
#endif
  gpointer base;
  gsize size;

#ifdef GUM_ANDROID_LEGACY_SOINFO
  guint32 unused1;
#endif

  gpointer dynamic;

#ifdef GUM_ANDROID_LEGACY_SOINFO
  guint32 unused2;
  guint32 unused3;
#endif

  GumSoinfo * next;

  /* We don't care about the rest of the fields. */
};

static gpointer gum_get_linker_base (void);
static gpointer gum_try_init_linker_base (void);
static gboolean gum_find_linker_base (const GumModuleDetails * details,
    gpointer user_data);
static gboolean gum_is_linker_module_name (const gchar * name);
static gboolean gum_is_vdso_module_name (const gchar * name);
static gboolean gum_store_module_handle_if_name_matches (
    const GumSoinfoDetails * details, gpointer user_data);
static gboolean gum_call_module_constructors_if_name_matches (
    const GumSoinfoDetails * details, gpointer user_data);
static gboolean gum_emit_module_from_soinfo (const GumSoinfoDetails * details,
    gpointer user_data);

static void gum_enumerate_soinfo (GumFoundSoinfoFunc func, gpointer user_data);
static const gchar * gum_resolve_soinfo_path (GumSoinfo * si,
    GumLinkerApi * api, GHashTable * ranges);

static GumLinkerApi * gum_linker_api_get (void);
static GumLinkerApi * gum_linker_api_try_init (void);
static gboolean gum_store_modern_linker_symbols (
    const GumElfSymbolDetails * details, gpointer user_data);
static gboolean gum_store_legacy_linker_symbols (
    const GumElfSymbolDetails * details, gpointer user_data);
static GumSoinfo * gum_solist_get_head_fallback (void);
static GumSoinfo * gum_solist_get_somain_fallback (void);

static void * gum_call_inner_dlopen (const char * path, int mode);
static void * gum_call_inner_dlsym (void * handle, const char * symbol);

static guint gum_android_get_api_level (void);

static GumLinkerApi gum_linker;

GumElfModule *
gum_android_open_linker_module (void)
{
  return gum_elf_module_new_from_memory (GUM_ANDROID_LINKER_MODULE_NAME,
      GUM_ADDRESS (gum_get_linker_base ()));
}

static gpointer
gum_get_linker_base (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_linker_base, NULL);

  if (once.retval == NULL)
  {
    g_critical ("Unable to determine linker base address; please file a bug");
    g_abort ();
  }

  return once.retval;
}

static gpointer
gum_try_init_linker_base (void)
{
  GumInitLinkerBaseContext ctx;

  ctx.found_vdso = FALSE;
  ctx.linker_base = NULL;

  gum_linux_enumerate_modules_using_proc_maps (gum_find_linker_base, &ctx);

  return ctx.linker_base;
}

static gboolean
gum_find_linker_base (const GumModuleDetails * details,
                      gpointer user_data)
{
  GumInitLinkerBaseContext * ctx = user_data;
  const gchar * path = details->path;

  /*
   * Using /proc/self/maps means there might be false positives, as the
   * application – or even Frida itself – may have mmap()ed the module.
   *
   * Knowing that the linker is mapped right after the vdso, with no gap
   * between, we just have to find the vdso, and we can count on the the
   * next one being the actual linker.
   */
  if (!ctx->found_vdso)
  {
    ctx->found_vdso = gum_is_vdso_module_name (path);
    return TRUE;
  }

  if (!gum_is_linker_module_name (path))
    return TRUE;

  ctx->linker_base = GSIZE_TO_POINTER (details->range->base_address);

  return FALSE;
}

static gboolean
gum_is_linker_module_name (const gchar * name)
{
  return strcmp (name, GUM_ANDROID_LINKER_MODULE_NAME) == 0;
}

static gboolean
gum_is_vdso_module_name (const gchar * name)
{
  return strcmp (name, GUM_ANDROID_VDSO_MODULE_NAME) == 0;
}

void *
gum_android_get_module_handle (const gchar * name)
{
  GumGetModuleHandleContext ctx;

  ctx.name = name;
  ctx.module = NULL;

  gum_enumerate_soinfo (gum_store_module_handle_if_name_matches, &ctx);

  return ctx.module;
}

static gboolean
gum_store_module_handle_if_name_matches (const GumSoinfoDetails * details,
                                         gpointer user_data)
{
  GumGetModuleHandleContext * ctx = user_data;

  if (gum_linux_module_path_matches (details->path, ctx->name))
  {
    GumLinkerApi * api = details->api;
    GumSoinfo * si = details->si;

    if (gum_linker.flavor == GUM_LINKER_MODERN)
    {
      GumProtectedDataGuard guard;

      api->guard_init (&guard);

      api->soinfo_ref (si);
      ctx->module = api->soinfo_to_handle (si);

      api->guard_clear (&guard);
    }
    else
    {
      ctx->module = dlopen (details->path, RTLD_LAZY);
    }

    return FALSE;
  }

  return TRUE;
}

gboolean
gum_android_ensure_module_initialized (const gchar * name)
{
  GumEnsureModuleInitializedContext ctx;

  ctx.name = name;
  ctx.success = FALSE;

  gum_enumerate_soinfo (gum_call_module_constructors_if_name_matches, &ctx);

  return ctx.success;
}

static gboolean
gum_call_module_constructors_if_name_matches (const GumSoinfoDetails * details,
                                              gpointer user_data)
{
  GumEnsureModuleInitializedContext * ctx = user_data;

  if (gum_linux_module_path_matches (details->path, ctx->name))
  {
    GumLinkerApi * api = details->api;
    GumSoinfo * si = details->si;

    if (gum_linker.flavor == GUM_LINKER_MODERN)
    {
      GumProtectedDataGuard guard;

      api->guard_init (&guard);

      api->soinfo_call_ctors (si);
      ctx->success = TRUE;

      api->guard_clear (&guard);
    }
    else
    {
      void * module;

      module = dlopen (details->path, RTLD_LAZY);
      if (module != NULL)
      {
        ctx->success = TRUE;
        dlclose (module);
      }
    }

    return FALSE;
  }

  return TRUE;
}

void
gum_android_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  GumEnumerateModulesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_enumerate_soinfo (gum_emit_module_from_soinfo, &ctx);
}

static gboolean
gum_emit_module_from_soinfo (const GumSoinfoDetails * details,
                             gpointer user_data)
{
  GumEnumerateModulesContext * ctx = user_data;
  GumSoinfo * si = details->si;
  gchar * name;
  GumModuleDetails module;
  GumMemoryRange range;
  gboolean carry_on;

  name = g_path_get_basename (details->path);

  module.name = name;
  module.range = &range;
  module.path = details->path;

  range.base_address = GPOINTER_TO_SIZE (si->base);
  range.size = si->size;

  carry_on = ctx->func (&module, ctx->user_data);

  g_free (name);

  return carry_on;
}

static void
gum_enumerate_soinfo (GumFoundSoinfoFunc func,
                      gpointer user_data)
{
  GumLinkerApi * api;
  GHashTable * ranges;
  GumSoinfo * somain, * sovdso, * solinker, * si;
  GumSoinfoDetails details;
  gboolean carry_on;

  api = gum_linker_api_get ();

  pthread_mutex_lock (api->dl_mutex);

  ranges = (api->soinfo_get_path == NULL)
      ? gum_linux_collect_named_ranges ()
      : NULL;

  somain = api->solist_get_somain ();
  sovdso = NULL;
  solinker = NULL;

  details.path = gum_resolve_soinfo_path (somain, api, ranges);
  details.si = somain;
  details.api = api;
  carry_on = func (&details, user_data);

  for (si = api->solist_get_head (); carry_on && si != NULL; si = si->next)
  {
    if (si == somain)
      continue;

    details.path = gum_resolve_soinfo_path (si, api, ranges);
    if (gum_is_vdso_module_name (details.path))
    {
      sovdso = si;
      continue;
    }
    if (gum_is_linker_module_name (details.path))
    {
      solinker = si;
      continue;
    }
    details.si = si;
    carry_on = func (&details, user_data);
  }

  if (carry_on && sovdso != NULL)
  {
    details.path = gum_resolve_soinfo_path (sovdso, api, ranges);
    details.si = sovdso;
    carry_on = func (&details, user_data);
  }

  if (carry_on && solinker != NULL)
  {
    details.path = gum_resolve_soinfo_path (solinker, api, ranges);
    details.si = solinker;
    carry_on = func (&details, user_data);
  }

  pthread_mutex_unlock (api->dl_mutex);

  if (ranges != NULL)
    g_hash_table_unref (ranges);
}

static const gchar *
gum_resolve_soinfo_path (GumSoinfo * si,
                         GumLinkerApi * api,
                         GHashTable * ranges)
{
  const gchar * result;

  if (ranges == NULL)
  {
    result = api->soinfo_get_path (si);

    if (strcmp (result, "[vdso]") == 0)
      result = GUM_ANDROID_VDSO_MODULE_NAME;
  }
  else if (si->base == NULL)
  {
    result = GUM_ANDROID_LINKER_MODULE_NAME;
  }
  else
  {
    GumLinuxNamedRange * range;

    range = g_hash_table_lookup (ranges, si->base);

    result = range->name;
  }

  return result;
}

static GumLinkerApi *
gum_linker_api_get (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_linker_api_try_init, NULL);

  if (once.retval == NULL)
  {
    g_critical ("Unsupported Android linker; please file a bug");
    g_abort ();
  }

  return once.retval;
}

static GumLinkerApi *
gum_linker_api_try_init (void)
{
  GumElfModule * linker;
  guint api_level;
  GumElfFoundSymbolFunc store_linker_symbols;
  guint pending;

  linker = gum_android_open_linker_module ();

  api_level = gum_android_get_api_level ();

  gum_linker.flavor = (api_level >= 24) ? GUM_LINKER_MODERN : GUM_LINKER_LEGACY;

  if (gum_linker.flavor == GUM_LINKER_MODERN)
  {
    store_linker_symbols = gum_store_modern_linker_symbols;
    pending = 11;
  }
  else
  {
    store_linker_symbols = gum_store_legacy_linker_symbols;
    pending = 3;
  }

  gum_elf_module_enumerate_symbols (linker, store_linker_symbols, &pending);

  if (gum_linker.flavor == GUM_LINKER_MODERN)
  {
    if (api_level < 26 && gum_linker.dlopen == NULL && gum_linker.dlsym == NULL)
    {
      pending -= 2;
    }

    if (gum_linker.solist_get_head == NULL && gum_linker.libdl_info != NULL)
    {
      gum_linker.solist_get_head = gum_solist_get_head_fallback;
      pending--;
    }

    if (gum_linker.solist_get_somain == NULL && gum_linker.somain != NULL)
    {
      gum_linker.solist_get_somain = gum_solist_get_somain_fallback;
      pending--;
    }
  }
  else
  {
    gum_linker.solist_get_head = gum_solist_get_head_fallback;
    gum_linker.solist_get_somain = gum_solist_get_somain_fallback;
  }

  gum_linker.trusted_caller = dlsym (RTLD_DEFAULT, "open");

  g_object_unref (linker);

  return (pending == 0) ? &gum_linker : NULL;
}

#define GUM_TRY_ASSIGN(field_name, symbol_name) \
    _GUM_TRY_ASSIGN (field_name, symbol_name, 1)
#define GUM_TRY_ASSIGN_OPTIONAL(field_name, symbol_name) \
    _GUM_TRY_ASSIGN (field_name, symbol_name, 0)
#define _GUM_TRY_ASSIGN(field_name, symbol_name, pending_delta) \
    G_STMT_START \
    { \
      if (gum_linker.field_name == NULL && \
          strcmp (details->name, symbol_name) == 0) \
      { \
        gum_linker.field_name = GSIZE_TO_POINTER (details->address); \
        *pending -= pending_delta; \
        goto beach; \
      } \
    } \
    G_STMT_END

static gboolean
gum_store_modern_linker_symbols (const GumElfSymbolDetails * details,
                                 gpointer user_data)
{
  guint * pending = user_data;

  GUM_TRY_ASSIGN (dlopen, "__dl__Z8__dlopenPKciPKv");
  GUM_TRY_ASSIGN (dlsym, "__dl__Z8__dlvsymPvPKcS1_PKv");

  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL10g_dl_mutex");

  GUM_TRY_ASSIGN (guard_init, "__dl__ZN18ProtectedDataGuardC1Ev");
  GUM_TRY_ASSIGN (guard_clear, "__dl__ZN18ProtectedDataGuardD1Ev");

  GUM_TRY_ASSIGN (solist_get_head, "__dl__Z15solist_get_headv");  /* 8.0- */
  GUM_TRY_ASSIGN_OPTIONAL (libdl_info, "__dl_libdl_info");        /* 7.x  */
  GUM_TRY_ASSIGN_OPTIONAL (libdl_info, "__dl__ZL12__libdl_info"); /* 7.x  */

  GUM_TRY_ASSIGN (solist_get_somain, "__dl__Z17solist_get_somainv"); /* 8.0- */
  GUM_TRY_ASSIGN_OPTIONAL (somain, "__dl__ZL6somain");               /* 7.x  */

  GUM_TRY_ASSIGN (soinfo_ref, "__dl__ZN6soinfo19increment_ref_countEv");
  GUM_TRY_ASSIGN (soinfo_get_path, "__dl__ZNK6soinfo12get_realpathEv");
  GUM_TRY_ASSIGN (soinfo_call_ctors, "__dl__ZN6soinfo17call_constructorsEv");
  GUM_TRY_ASSIGN (soinfo_to_handle, "__dl__ZN6soinfo9to_handleEv");

beach:
  return *pending != 0;
}

static gboolean
gum_store_legacy_linker_symbols (const GumElfSymbolDetails * details,
                                 gpointer user_data)
{
  guint * pending = user_data;

  GUM_TRY_ASSIGN_OPTIONAL (dlopen, "__dl__Z8__dlopenPKciPKv");
  GUM_TRY_ASSIGN_OPTIONAL (dlsym, "__dl__Z8__dlvsymPvPKcS1_PKv");

  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL8gDlMutex");    /* 4.3-4.4 */
  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL10g_dl_mutex"); /* 5.0-    */

  /* guard_init, guard_clear: don't need them as we're using dlopen() */

  /* solist_get_head: emulated by knowing libdl_info is first */
  GUM_TRY_ASSIGN (libdl_info, "__dl_libdl_info");

  /* solist_get_somain: emulated by using the somain symbol */
  GUM_TRY_ASSIGN (somain, "__dl__ZL6somain");

  /* soinfo_ref: emulated by calling dlopen() */

  /* soinfo_get_path: emulated on < 6.0 */
  GUM_TRY_ASSIGN_OPTIONAL (soinfo_get_path, "__dl__ZNK6soinfo12get_realpathEv");

  /* soinfo_call_ctors: emulated by calling dlopen() */

  /* soinfo_to_handle: dlopen() returns the real thing */

beach:
  return *pending != 0;
}

#undef GUM_TRY_ASSIGN
#undef GUM_TRY_ASSIGN_OPTIONAL
#undef _GUM_TRY_ASSIGN

static GumSoinfo *
gum_solist_get_head_fallback (void)
{
  return gum_linker.libdl_info;
}

static GumSoinfo *
gum_solist_get_somain_fallback (void)
{
  return *gum_linker.somain;
}

gboolean
gum_android_find_unrestricted_dlopen (GumGenericDlopenImpl * generic_dlopen)
{
  if (!gum_android_find_unrestricted_linker_api (NULL))
    return FALSE;

  *generic_dlopen = gum_call_inner_dlopen;

  return TRUE;
}

gboolean
gum_android_find_unrestricted_dlsym (GumGenericDlsymImpl * generic_dlsym)
{
  if (!gum_android_find_unrestricted_linker_api (NULL))
    return FALSE;

  *generic_dlsym = gum_call_inner_dlsym;

  return TRUE;
}

gboolean
gum_android_find_unrestricted_linker_api (GumAndroidUnrestrictedLinkerApi * api)
{
  GumLinkerApi * private_api;

  private_api = gum_linker_api_get ();

  if (private_api->dlopen == NULL)
    return FALSE;

  if (api != NULL)
  {
    api->dlopen = private_api->dlopen;
    api->dlsym = private_api->dlsym;
  }

  return TRUE;
}

static void *
gum_call_inner_dlopen (const char * path,
                       int mode)
{
  return gum_linker.dlopen (path, mode, gum_linker.trusted_caller);
}

static void *
gum_call_inner_dlsym (void * handle,
                      const char * symbol)
{
  return gum_linker.dlsym (handle, symbol, NULL, gum_linker.trusted_caller);
}

static guint
gum_android_get_api_level (void)
{
  gchar sdk_version[PROP_VALUE_MAX];

  sdk_version[0] = '\0';
  __system_property_get ("ro.build.version.sdk", sdk_version);

  return atoi (sdk_version);
}
