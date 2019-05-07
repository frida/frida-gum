/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumandroid.h"

#include "gumlinux.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <string.h>
#include <sys/system_properties.h>

#if (defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4) || defined (HAVE_ARM)
# define GUM_ANDROID_LEGACY_SOINFO 1
#endif

#define GUM_ANDROID_VDSO_MODULE_NAME "linux-vdso.so.1"

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_LIBCXX_TINY_STRING_CAPACITY 11
#else
# define GUM_LIBCXX_TINY_STRING_CAPACITY 23
#endif

typedef struct _GumGetModuleHandleContext GumGetModuleHandleContext;
typedef struct _GumEnsureModuleInitializedContext
    GumEnsureModuleInitializedContext;
typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;

typedef struct _GumSoinfoDetails GumSoinfoDetails;
typedef gboolean (* GumFoundSoinfoFunc) (const GumSoinfoDetails * details,
    gpointer user_data);

typedef struct _GumLinkerApi GumLinkerApi;

typedef struct _GumSoinfo GumSoinfo;
typedef guint32 GumSoinfoFlags;
typedef struct _GumSoinfoList GumSoinfoList;
typedef struct _GumSoinfoListEntry GumSoinfoListEntry;

typedef union _GumLibcxxString GumLibcxxString;
typedef struct _GumLibcxxTinyString GumLibcxxTinyString;
typedef struct _GumLibcxxHugeString GumLibcxxHugeString;

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

struct _GumLinkerApi
{
  GumAndroidDlopenImpl dlopen;
  GumAndroidDlsymImpl dlsym;
  gpointer trusted_caller;

  void * (* do_dlopen) (const char * filename, int flags, const void * extinfo,
      void * caller_addr);

  pthread_mutex_t * dl_mutex;

  GumSoinfo * (* solist_get_head) (void);
  GumSoinfo ** solist;
  GumSoinfo * libdl_info;
  GumSoinfo * (* solist_get_somain) (void);
  GumSoinfo ** somain;

  const char * (* soinfo_get_path) (const GumSoinfo * si);
};

struct _GumSoinfoList
{
  GumSoinfoListEntry * head;
  GumSoinfoListEntry * tail;
};

struct _GumSoinfoListEntry
{
  GumSoinfoListEntry * next;
  GumSoinfo * element;
};

struct _GumLibcxxTinyString
{
  guint8 size;
  gchar data[GUM_LIBCXX_TINY_STRING_CAPACITY];
};

struct _GumLibcxxHugeString
{
  gsize capacity;
  gsize size;
  gchar * data;
};

union _GumLibcxxString
{
  GumLibcxxTinyString tiny;
  GumLibcxxHugeString huge;
};

struct _GumSoinfo
{
#ifdef GUM_ANDROID_LEGACY_SOINFO
  gchar old_name[128];
#endif

  const ElfW(Phdr) * phdr;
  gsize phnum;

#ifdef GUM_ANDROID_LEGACY_SOINFO
  ElfW(Addr) unused0;
#endif
  ElfW(Addr) base;
  gsize size;

#ifdef GUM_ANDROID_LEGACY_SOINFO
  guint32 unused1;
#endif

  ElfW(Dyn) * dynamic;

#ifdef GUM_ANDROID_LEGACY_SOINFO
  guint32 unused2;
  guint32 unused3;
#endif

  GumSoinfo * next;

  GumSoinfoFlags flags;

  const gchar * strtab;
  ElfW(Sym) * symtab;

  gsize nbucket;
  gsize nchain;
  guint32 * bucket;
  guint32 * chain;

#if GLIB_SIZEOF_VOID_P == 4
  ElfW(Addr) ** plt_got;
#endif

  gpointer plt_relx;
  gsize plt_relx_count;

  gpointer relx;
  gsize relx_count;

  gpointer * preinit_array;
  gsize preinit_array_count;

  gpointer * init_array;
  gsize init_array_count;
  gpointer * fini_array;
  gsize fini_array_count;

  gpointer init_func;
  gpointer fini_func;

#if defined (HAVE_ARM)
  guint32 * arm_exidx;
  gsize arm_exidx_count;
#elif defined (HAVE_MIPS)
  guint32 mips_symtabno;
  guint32 mips_local_gotno;
  guint32 mips_gotsym;
#endif

  gsize ref_count;

  struct link_map link_map_head;

  guint8 constructors_called;

  ElfW(Addr) load_bias;

#if GLIB_SIZEOF_VOID_P == 4
  guint8 has_text_relocations;
#endif
  guint8 has_dt_symbolic;

  /* Next part of structure only present when NEW_FORMAT is in flags. */
  guint32 version;

  /* version >= 0 */
  dev_t st_dev;
  ino_t st_ino;

  GumSoinfoList children;
  GumSoinfoList parents;

  /* version >= 1 */
  off64_t file_offset;
  guint32 rtld_flags;
  guint32 dt_flags_1;
  gsize strtab_size;

  /* version >= 2 */
  gsize gnu_nbucket;
  guint32 * gnu_bucket;
  guint32 * gnu_chain;
  guint32 gnu_maskwords;
  guint32 gnu_shift2;
  ElfW(Addr) * gnu_bloom_filter;

  GumSoinfo * local_group_root;

  guint8 * android_relocs;
  gsize android_relocs_size;

  const gchar * soname;
  GumLibcxxString realpath;

  const ElfW(Versym) * versym;

  ElfW(Addr) verdef_ptr;
  gsize verdef_cnt;

  ElfW(Addr) verneed_ptr;
  gsize verneed_cnt;

  gint target_sdk_version;

  /* For now we don't need anything from version >= 3. */
};

enum _GumSoinfoFlags
{
  GUM_SOINFO_NEW_FORMAT = 0x40000000,
};

static const GumModuleDetails * gum_try_init_linker_details (void);
static gboolean gum_try_parse_linker_proc_maps_line (const gchar * line,
    GumModuleDetails * module, GumMemoryRange * range);

static gboolean gum_store_module_handle_if_name_matches (
    const GumSoinfoDetails * details, gpointer user_data);
static gboolean gum_emit_module_from_soinfo (const GumSoinfoDetails * details,
    gpointer user_data);

static void gum_enumerate_soinfo (GumFoundSoinfoFunc func, gpointer user_data);
static const gchar * gum_resolve_soinfo_path (GumSoinfo * si,
    GumLinkerApi * api, GHashTable ** ranges);

static GumLinkerApi * gum_linker_api_get (void);
static GumLinkerApi * gum_linker_api_try_init (void);
static gboolean gum_store_linker_symbol_if_needed (
    const GumElfSymbolDetails * details, gpointer user_data);
static GumSoinfo * gum_solist_get_head_fallback (void);
static GumSoinfo * gum_solist_get_somain_fallback (void);
static gboolean gum_soinfo_is_linker (const GumSoinfo * self);
static const char * gum_soinfo_get_path_fallback (const GumSoinfo * self);

static void * gum_call_inner_dlopen (const char * filename, int flags);
static void * gum_call_inner_dlsym (void * handle, const char * symbol);

static const char * gum_libcxx_string_get_data (const GumLibcxxString * self);

static gboolean gum_android_is_vdso_module_name (const gchar * name);

static GumModuleDetails gum_dl_module;
static GumMemoryRange gum_dl_range;
static GumLinkerApi gum_dl_api;

static const gchar * gum_magic_linker_export_names_pre_api_level_26[] =
{
  "dlopen",
  "dlsym",
  "dlclose",
  "dlerror",
  NULL
};

static const gchar * gum_magic_linker_export_names_post_api_level_26[] =
{
  NULL
};

guint
gum_android_get_api_level (void)
{
  static guint cached_api_level = 0;

  if (cached_api_level == 0)
  {
    gchar sdk_version[PROP_VALUE_MAX];

    sdk_version[0] = '\0';
    __system_property_get ("ro.build.version.sdk", sdk_version);

    cached_api_level = atoi (sdk_version);
  }

  return cached_api_level;
}

gboolean
gum_android_is_linker_module_name (const gchar * name)
{
  const GumModuleDetails * linker;

  linker = gum_android_get_linker_module_details ();

  if (name[0] != '/')
    return strcmp (name, linker->name) == 0;

  return strcmp (name, linker->path) == 0;
}

const GumModuleDetails *
gum_android_get_linker_module_details (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_linker_details, NULL);

  if (once.retval == NULL)
  {
    g_critical ("Unable to locate the Android linker; please file a bug");
    g_abort ();
  }

  return once.retval;
}

static const GumModuleDetails *
gum_try_init_linker_details (void)
{
  const GumModuleDetails * result = NULL;
  gchar * maps, ** lines;
  gint num_lines, vdso_index, i;

  /*
   * Using /proc/self/maps means there might be false positives, as the
   * application – or even Frida itself – may have mmap()ed the module.
   *
   * Knowing that the linker is mapped right around the vdso, with no
   * empty space between, we just have to find the vdso, and we can
   * count on the the next or previous linker mapping being the actual
   * linker.
   */
  g_file_get_contents ("/proc/self/maps", &maps, NULL, NULL);
  lines = g_strsplit (maps, "\n", 0);
  num_lines = g_strv_length (lines);

  vdso_index = -1;
  for (i = 0; i != num_lines; i++)
  {
    const gchar * line = lines[i];

    if (g_str_has_suffix (line, " [vdso]"))
    {
      vdso_index = i;
      break;
    }
  }
  if (vdso_index == -1)
    goto no_vdso;

  for (i = vdso_index + 1; i != num_lines; i++)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], &gum_dl_module,
        &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  for (i = vdso_index - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], &gum_dl_module,
        &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  goto beach;

no_vdso:
  for (i = num_lines - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], &gum_dl_module,
        &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

beach:
  g_strfreev (lines);
  g_free (maps);

  return result;
}

static gboolean
gum_try_parse_linker_proc_maps_line (const gchar * line,
                                     GumModuleDetails * module,
                                     GumMemoryRange * range)
{
  GumAddress start, end;
  gchar perms[5] = { 0, };
  gchar path[PATH_MAX];
  gint n;
  const gchar * new_path, * old_path, * linker_path;
  const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };

  n = sscanf (line,
      "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
      "%4c "
      "%*x %*s %*d "
      "%s",
      &start, &end,
      perms,
      path);
  if (n != 4)
    return FALSE;

  if (sizeof (gpointer) == 4)
  {
    new_path = "/bionic/bin/linker";
    old_path = "/system/bin/linker";
  }
  else
  {
    new_path = "/bionic/bin/linker64";
    old_path = "/system/bin/linker64";
  }

  if (strcmp (path, new_path) == 0)
    linker_path = new_path;
  else if (strcmp (path, old_path) == 0)
    linker_path = old_path;
  else
    return FALSE;

  if (perms[0] != 'r')
    return FALSE;

  if (memcmp (GSIZE_TO_POINTER (start), elf_magic, sizeof (elf_magic)) != 0)
    return FALSE;

  module->name = strrchr (linker_path, '/') + 1;
  module->range = range;
  module->path = linker_path;

  range->base_address = start;
  range->size = end - start;

  return TRUE;
}

const gchar **
gum_android_get_magic_linker_export_names (void)
{
  return (gum_android_get_api_level () < 26)
      ? gum_magic_linker_export_names_pre_api_level_26
      : gum_magic_linker_export_names_post_api_level_26;
}

gboolean
gum_android_try_resolve_magic_export (const gchar * module_name,
                                      const gchar * symbol_name,
                                      GumAddress * result)
{
  const gchar ** magic_exports;
  guint i;

  magic_exports = gum_android_get_magic_linker_export_names ();
  if (magic_exports[0] == NULL)
    return FALSE;

  if (module_name == NULL || !gum_android_is_linker_module_name (module_name))
    return FALSE;

  for (i = 0; magic_exports[i] != NULL; i++)
  {
    if (strcmp (symbol_name, magic_exports[i]) == 0)
    {
      *result = GUM_ADDRESS (dlsym (RTLD_DEFAULT, symbol_name));
      return TRUE;
    }
  }

  return FALSE;
}

GumElfModule *
gum_android_open_linker_module (void)
{
  const GumModuleDetails * linker;

  linker = gum_android_get_linker_module_details ();

  return gum_elf_module_new_from_memory (linker->path,
      linker->range->base_address);
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
  GumLinkerApi * api = details->api;

  if (gum_linux_module_path_matches (details->path, ctx->name))
  {
    GumSoinfo * si = details->si;
    int flags = RTLD_LAZY;
    void * caller_addr = api->trusted_caller;

    if ((si->flags & GUM_SOINFO_NEW_FORMAT) != 0)
    {
      GumSoinfo * parent;

      parent = (si->parents.head != NULL)
          ? si->parents.head->element
          : NULL;
      if (parent != NULL)
      {
        caller_addr = GSIZE_TO_POINTER (parent->base);
      }

      if (si->version >= 1)
      {
        flags = si->rtld_flags;
      }
    }

    if (gum_android_get_api_level () >= 21)
    {
      flags |= RTLD_NOLOAD;
    }

    if (api->dlopen != NULL)
    {
      /* API level >= 26 (Android >= 8.0) */
      ctx->module = api->dlopen (details->path, flags, caller_addr);
    }
    else if (api->do_dlopen != NULL)
    {
      /* API level >= 24 (Android >= 7.0) */
      ctx->module = api->do_dlopen (details->path, flags, NULL, caller_addr);
    }
    else
    {
      ctx->module = dlopen (details->path, flags);
    }

    return FALSE;
  }

  return TRUE;
}

gboolean
gum_android_ensure_module_initialized (const gchar * name)
{
  void * module;

  module = gum_android_get_module_handle (name);
  if (module == NULL)
    return FALSE;
  dlclose (module);
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

  if (gum_soinfo_is_linker (si))
  {
    range = *gum_android_get_linker_module_details ()->range;
  }
  else
  {
    range.base_address = si->base;
    range.size = si->size;
  }

  carry_on = ctx->func (&module, ctx->user_data);

  g_free (name);

  return carry_on;
}

static void
gum_enumerate_soinfo (GumFoundSoinfoFunc func,
                      gpointer user_data)
{
  GumLinkerApi * api;
  GumSoinfo * somain, * sovdso, * solinker, * si;
  GHashTable * ranges;
  GumSoinfoDetails details;
  gboolean carry_on;

  api = gum_linker_api_get ();

  pthread_mutex_lock (api->dl_mutex);

  somain = api->solist_get_somain ();
  sovdso = NULL;
  solinker = NULL;

  ranges = NULL;

  details.path = gum_resolve_soinfo_path (somain, api, &ranges);
  details.si = somain;
  details.api = api;
  carry_on = func (&details, user_data);

  for (si = api->solist_get_head (); carry_on && si != NULL; si = si->next)
  {
    if (si == somain)
      continue;

    details.path = gum_resolve_soinfo_path (si, api, &ranges);
    if (gum_android_is_vdso_module_name (details.path))
    {
      sovdso = si;
      continue;
    }
    if (gum_android_is_linker_module_name (details.path))
    {
      solinker = si;
      continue;
    }
    details.si = si;
    carry_on = func (&details, user_data);
  }

  if (carry_on && sovdso != NULL)
  {
    details.path = gum_resolve_soinfo_path (sovdso, api, &ranges);
    details.si = sovdso;
    carry_on = func (&details, user_data);
  }

  if (carry_on && solinker != NULL)
  {
    details.path = gum_resolve_soinfo_path (solinker, api, &ranges);
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
                         GHashTable ** ranges)
{
  const gchar * result = NULL;

  if (api->soinfo_get_path != NULL)
  {
    result = api->soinfo_get_path (si);

    if (strcmp (result, "[vdso]") == 0)
      result = GUM_ANDROID_VDSO_MODULE_NAME;
    else if (strcmp (result, "libdl.so") == 0)
      result = gum_android_get_linker_module_details ()->path;
    else if (result[0] != '/')
      result = NULL;
  }
  else if (gum_soinfo_is_linker (si))
  {
    result = gum_android_get_linker_module_details ()->path;
  }

  if (result == NULL)
  {
    GumLinuxNamedRange * range;

    if (*ranges == NULL)
    {
      *ranges = gum_linux_collect_named_ranges ();
    }

    range = g_hash_table_lookup (*ranges, GSIZE_TO_POINTER (si->base));

    result = (range != NULL) ? range->name : "<unknown>";
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
  guint api_level, pending;

  linker = gum_android_open_linker_module ();

  api_level = gum_android_get_api_level ();

  pending = 6;
  gum_elf_module_enumerate_symbols (linker, gum_store_linker_symbol_if_needed,
      &pending);

  if (api_level < 26 && gum_dl_api.dlopen == NULL && gum_dl_api.dlsym == NULL)
  {
    pending -= 2;
  }

  if (gum_dl_api.solist_get_head == NULL &&
      (gum_dl_api.solist != NULL || gum_dl_api.libdl_info != NULL))
  {
    gum_dl_api.solist_get_head = gum_solist_get_head_fallback;
    pending--;
  }

  if (gum_dl_api.solist_get_somain == NULL && gum_dl_api.somain != NULL)
  {
    gum_dl_api.solist_get_somain = gum_solist_get_somain_fallback;
    pending--;
  }

  if (gum_dl_api.soinfo_get_path == NULL)
  {
    if (api_level >= 24)
    {
      gum_dl_api.soinfo_get_path = gum_soinfo_get_path_fallback;
    }

    pending--;
  }

  gum_dl_api.trusted_caller = dlsym (RTLD_DEFAULT, "open");

  g_object_unref (linker);

  return (pending == 0) ? &gum_dl_api : NULL;
}

#define GUM_TRY_ASSIGN(field_name, symbol_name) \
    _GUM_TRY_ASSIGN (field_name, symbol_name, 1)
#define GUM_TRY_ASSIGN_OPTIONAL(field_name, symbol_name) \
    _GUM_TRY_ASSIGN (field_name, symbol_name, 0)
#define _GUM_TRY_ASSIGN(field_name, symbol_name, pending_delta) \
    G_STMT_START \
    { \
      if (gum_dl_api.field_name == NULL && \
          strcmp (details->name, symbol_name) == 0) \
      { \
        gum_dl_api.field_name = GSIZE_TO_POINTER (details->address); \
        *pending -= pending_delta; \
        goto beach; \
      } \
    } \
    G_STMT_END

static gboolean
gum_store_linker_symbol_if_needed (const GumElfSymbolDetails * details,
                                   gpointer user_data)
{
  guint * pending = user_data;

  /* Restricted dlopen() implemented in API level >= 26 (Android >= 8.0). */
  GUM_TRY_ASSIGN (dlopen, "__dl___loader_dlopen");       /* >= 28 */
  GUM_TRY_ASSIGN (dlsym, "__dl___loader_dlvsym");        /* >= 28 */
  GUM_TRY_ASSIGN (dlopen, "__dl__Z8__dlopenPKciPKv");    /* >= 26 */
  GUM_TRY_ASSIGN (dlsym, "__dl__Z8__dlvsymPvPKcS1_PKv"); /* >= 26 */
  /* Namespaces implemented in API level >= 24 (Android >= 7.0). */
  GUM_TRY_ASSIGN_OPTIONAL (do_dlopen,
      "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv");

  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL10g_dl_mutex"); /* >= 21 */
  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL8gDlMutex");    /*  < 21 */

  GUM_TRY_ASSIGN (solist_get_head, "__dl__Z15solist_get_headv"); /* >= 26 */
  GUM_TRY_ASSIGN_OPTIONAL (solist, "__dl__ZL6solist");           /* >= 21 */
  GUM_TRY_ASSIGN_OPTIONAL (libdl_info, "__dl_libdl_info");       /*  < 21 */

  GUM_TRY_ASSIGN (solist_get_somain, "__dl__Z17solist_get_somainv"); /* >= 26 */
  GUM_TRY_ASSIGN_OPTIONAL (somain, "__dl__ZL6somain");               /* "any" */

  /*
   * Realpath getter implemented in API level >= 23+ (6.0+), but may have
   * been inlined.
   */
  GUM_TRY_ASSIGN (soinfo_get_path, "__dl__ZNK6soinfo12get_realpathEv");

beach:
  return *pending != 0;
}

#undef GUM_TRY_ASSIGN
#undef GUM_TRY_ASSIGN_OPTIONAL
#undef _GUM_TRY_ASSIGN

static GumSoinfo *
gum_solist_get_head_fallback (void)
{
  return (gum_dl_api.solist != NULL)
      ? *gum_dl_api.solist
      : gum_dl_api.libdl_info;
}

static GumSoinfo *
gum_solist_get_somain_fallback (void)
{
  return *gum_dl_api.somain;
}

static gboolean
gum_soinfo_is_linker (const GumSoinfo * self)
{
  return self->base == 0;
}

static const char *
gum_soinfo_get_path_fallback (const GumSoinfo * self)
{
#ifdef GUM_ANDROID_LEGACY_SOINFO
  if ((self->flags & GUM_SOINFO_NEW_FORMAT) != 0 && self->version >= 2)
    return gum_libcxx_string_get_data (&self->realpath);
  else
    return self->old_name;
#else
  return gum_libcxx_string_get_data (&self->realpath);
#endif
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
gum_call_inner_dlopen (const char * filename,
                       int flags)
{
  return gum_dl_api.dlopen (filename, flags, gum_dl_api.trusted_caller);
}

static void *
gum_call_inner_dlsym (void * handle,
                      const char * symbol)
{
  return gum_dl_api.dlsym (handle, symbol, NULL, gum_dl_api.trusted_caller);
}

static const char *
gum_libcxx_string_get_data (const GumLibcxxString * self)
{
  gboolean is_tiny;

  is_tiny = (self->tiny.size & 1) == 0;

  return is_tiny ? self->tiny.data : self->huge.data;
}

static gboolean
gum_android_is_vdso_module_name (const gchar * name)
{
  return strcmp (name, GUM_ANDROID_VDSO_MODULE_NAME) == 0;
}
