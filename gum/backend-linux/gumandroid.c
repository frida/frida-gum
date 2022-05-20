/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumandroid.h"

#include "gum-init.h"
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
typedef struct _GumSoinfoHead GumSoinfoHead;
typedef struct _GumSoinfoBody GumSoinfoBody;
typedef struct _GumSoinfoModern GumSoinfoModern;
typedef struct _GumSoinfoLegacy23 GumSoinfoLegacy23;
typedef struct _GumSoinfoLegacy GumSoinfoLegacy;
typedef guint32 GumSoinfoFlags;
typedef struct _GumSoinfoList GumSoinfoList;
typedef struct _GumSoinfoListEntry GumSoinfoListEntry;

typedef struct _GumFindDlopenApiContext GumFindDlopenApiContext;
typedef struct _GumFindDlMutexContext GumFindDlMutexContext;
typedef struct _GumFindFunctionSignatureContext GumFindFunctionSignatureContext;
typedef struct _GumFunctionSignature GumFunctionSignature;

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
  GumSoinfoBody * body;
  GumLinkerApi * api;
};

struct _GumLinkerApi
{
  GumAndroidDlopenImpl dlopen;
  GumAndroidDlsymImpl dlsym;
  gpointer trusted_caller;

  void * (* do_dlopen) (const char * filename, int flags, const void * extinfo,
      void * caller_addr);
  guint8 (* do_dlsym) (void * handle, const char * sym_name,
      const char * sym_ver, void * caller_addr, void ** symbol);

  pthread_mutex_t * dl_mutex;

  GumSoinfo * (* solist_get_head) (void);
  GumSoinfo ** solist;
  GumSoinfo * libdl_info;
  GumSoinfo * (* solist_get_somain) (void);
  GumSoinfo ** somain;
  GumSoinfo * somain_node;

  const char * (* soinfo_get_path) (GumSoinfo * si);
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

struct _GumSoinfoHead
{
#ifdef GUM_ANDROID_LEGACY_SOINFO
  gchar old_name[128];
#endif

  const ElfW(Phdr) * phdr;
  gsize phnum;
};

struct _GumSoinfoBody
{
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

struct _GumSoinfoModern
{
  GumSoinfoHead head;
  GumSoinfoBody body;
};

struct _GumSoinfoLegacy23
{
  GumSoinfoHead head;

#ifndef GUM_ANDROID_LEGACY_SOINFO
  ElfW(Addr) entry;
#endif
  GumSoinfoBody body;
};

struct _GumSoinfoLegacy
{
#ifndef GUM_ANDROID_LEGACY_SOINFO
  gchar name[128];
#endif

  GumSoinfoLegacy23 legacy23;
};

struct _GumSoinfo
{
  union
  {
    GumSoinfoModern modern;
    GumSoinfoLegacy23 legacy23;
    GumSoinfoLegacy legacy;
  };
};

enum _GumSoinfoFlags
{
  GUM_SOINFO_LINKED     = 0x00000001,
  GUM_SOINFO_EXE        = 0x00000004,
  GUM_SOINFO_GNU_HASH   = 0x00000040,
  GUM_SOINFO_NEW_FORMAT = 0x40000000,
};

struct _GumFindDlopenApiContext
{
  GumElfModule * linker;

  const GumFunctionSignature * dlopen_signatures;
  gpointer dlopen;

  const GumFunctionSignature * dlsym_signatures;
  gpointer dlsym;
};

struct _GumFindDlMutexContext
{
  GumElfModule * linker;
  pthread_mutex_t * dl_mutex;
};

struct _GumFindFunctionSignatureContext
{
  GumAddress match;
  guint num_matches;
};

struct _GumFunctionSignature
{
  const gchar * signature;
  gint displacement;
};

static const GumModuleDetails * gum_try_init_linker_details (void);
static void gum_deinit_linker_details (void);
static gchar * gum_find_linker_path (void);
static GRegex * gum_find_linker_path_pattern (void);
static gboolean gum_try_parse_linker_proc_maps_line (const gchar * line,
    const gchar * linker_path, const GRegex * linker_path_pattern,
    GumModuleDetails * module, GumMemoryRange * range);

static gboolean gum_store_module_handle_if_name_matches (
    const GumSoinfoDetails * details, GumGetModuleHandleContext * ctx);
static gboolean gum_emit_module_from_soinfo (const GumSoinfoDetails * details,
    GumEnumerateModulesContext * ctx);

static void gum_enumerate_soinfo (GumFoundSoinfoFunc func, gpointer user_data);
static void gum_init_soinfo_details (GumSoinfoDetails * details, GumSoinfo * si,
    GumLinkerApi * api, GHashTable ** ranges);
static const gchar * gum_resolve_soinfo_path (GumSoinfo * si,
    GumLinkerApi * api, GHashTable ** ranges);

static GumLinkerApi * gum_linker_api_get (void);
static GumLinkerApi * gum_linker_api_try_init (void);
static gboolean gum_store_linker_symbol_if_needed (
    const GumElfSymbolDetails * details, guint * pending);
static gboolean gum_try_find_dlopen_api245_forensically (GumElfModule * linker,
    GumLinkerApi * api);
static gboolean gum_try_find_dlopen_api26p_forensically (GumElfModule * linker,
    GumLinkerApi * api);
static gboolean gum_store_dlopen_api_if_found_in_section (
    const GumElfSectionDetails * details, GumFindDlopenApiContext * ctx);
static gboolean gum_try_find_dl_mutex_forensically (GumElfModule * linker,
    pthread_mutex_t ** dl_mutex);
static gboolean gum_store_dl_mutex_pointer_if_found_in_section (
    const GumElfSectionDetails * details, GumFindDlMutexContext * ctx);
static gboolean gum_try_find_libdl_info_forensically (GumElfModule * linker,
    GumSoinfo ** libdl_info);
static gboolean gum_store_libdl_info_pointer_if_found_in_section (
    const GumElfSectionDetails * details, GumSoinfo ** libdl_info);
static gboolean gum_try_find_somain_forensically (GumLinkerApi * api);
static gpointer gum_find_function_by_signature (GumAddress address, gsize size,
    const GumFunctionSignature * signatures);
static gboolean gum_store_function_signature_match (GumAddress address,
    gsize size, GumFindFunctionSignatureContext * ctx);
static gboolean gum_store_first_scan_match (GumAddress address, gsize size,
    gpointer user_data);
static GumSoinfo * gum_solist_get_head_fallback (void);
static GumSoinfo * gum_solist_get_somain_fallback (void);
#ifdef GUM_ANDROID_LEGACY_SOINFO
static GumSoinfoHead * gum_soinfo_get_head (GumSoinfo * self);
#endif
static GumSoinfoBody * gum_soinfo_get_body (GumSoinfo * self);
static gboolean gum_soinfo_is_linker (GumSoinfo * self);
static const char * gum_soinfo_get_path_fallback (GumSoinfo * self);

static void * gum_call_inner_dlopen (const char * filename, int flags);
static void * gum_call_inner_dlsym (void * handle, const char * symbol);

static const char * gum_libcxx_string_get_data (const GumLibcxxString * self);

static gboolean gum_android_is_vdso_module_name (const gchar * name);

static gchar * gum_dl_path;
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

/*
 * The following signatures have been tested on:
 *
 * - Xiaomi iRedmi Note 3 running LineageOS 14.1 (Android 7.1.2)
 */

static const GumFunctionSignature gum_dlopen_signatures_api245[] =
{
#ifdef HAVE_ARM
  {
    "93 46 "        /* mov r11, r2                             */
    "0c 46 "        /* mov r4, r1                              */
    "78 44 "        /* add r0, pc                              */
    "05 68",        /* ldr r5, [r0]                            */
    -12 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "f4 4f 04 a9 "  /* stp x20, x19, [sp, #0x40]               */
    "fd 7b 05 a9 "  /* stp x29, x30, [sp, #0x50]               */
    "fd 43 01 91 "  /* add x29, sp, #0x50                      */
    "ff c3 04 d1 "  /* sub sp, sp, #0x130                      */
    "?? ?? ?? ?? "  /* adrp x8, #0xb1000                       */
    "?? ?? ?? ?? "  /* ldr x21, [x8, #0x688]                   */
    "f4 03 02 aa",  /* mov x20, x2                             */
    -16
  },
#endif
  { NULL, 0 }
};

static const GumFunctionSignature gum_dlsym_signatures_api245[] =
{
#ifdef HAVE_ARM
  {
    "14 46 "        /* mov r4, r2                              */
    "88 46 "        /* mov r8, r1                              */
    "?? ?? "        /* cbz r6, loc_52a6                        */
    "b8 f1 00 0f",  /* cmp.w r8, #0                            */
    -8 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "ff c3 01 d1 "  /* sub sp, sp, #0x70                       */
    "f3 03 04 aa "  /* mov x19, x4                             */
    "f4 03 02 aa "  /* mov x20, x2                             */
    "f5 03 01 aa "  /* mov x21, x1                             */
    "e8 03 00 aa",  /* mov x8, x0                              */
    -16
  },
#endif
  { NULL, 0 }
};

/*
 * The following signatures have been tested on:
 *
 * - Pixel 3 running Android 9.0
 */

static const GumFunctionSignature gum_dlopen_signatures_api26p[] =
{
#ifdef HAVE_ARM
  {
    "0d 46 "        /* mov r5, r1                              */
    "78 44 "        /* add r0, pc                              */
    "?? ?? ?? ?? "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? "        /* ldr r0, =0xbd62a                        */
    "78 44",        /* add r0, pc                              */
    -8 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "f3 03 02 aa "  /* mov x19, x2                             */
    "f4 03 01 2a "  /* mov w20, w1                             */
    "f5 03 00 aa "  /* mov x21, x0                             */
    "?? ?? ?? ?? "  /* adrp x0, #0x150000                      */
    "?? ?? ?? ?? "  /* add x0, x0, #0                          */
    "?? ?? ?? ?4 "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? ?? ?? "  /* adrp x0, #0x14f000                      */
    "?? ?? ?? ?? "  /* ldr x0, [x0, #0x840]                    */
    "?? ?? ?? ?4 "  /* bl __dl__ZN12LinkerLogger10ResetStateEv */
    "e0 03 15 aa ", /* mov x0, x21                             */
    -16
  },
#endif
  { NULL, 0 }
};

static const GumFunctionSignature gum_dlsym_signatures_api26p[] =
{
#ifdef HAVE_ARM
  {
    "1c 46 "        /* mov r4, r3                              */
    "15 46 "        /* mov r5, r2                              */
    "0e 46 "        /* mov r6, r1                              */
    "78 44 "        /* add r0, pc                              */
    "?? ?? ?? ?? "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? "        /* ldr r0, =0xbd5ce                        */
    "78 44 "        /* add r0, pc                              */
    "00 68 "        /* ldr r0, [r0]                            */
    "?? ?? ?? ?? "  /* bl __dl__ZN12LinkerLogger10ResetStateEv */
    "02 a8",        /* add r0, sp, #8                          */
    -8 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "fd c3 00 91 "  /* add x29, sp, #0x30                      */
    "f3 03 03 aa "  /* mov x19, x3                             */
    "f4 03 02 aa "  /* mov x20, x2                             */
    "f5 03 01 aa "  /* mov x21, x1                             */
    "f6 03 00 aa "  /* mov x22, x0                             */
    "?? ?? ?? ?? "  /* adrp x0, #0x150000                      */
    "?? ?? ?? ?? "  /* add x0, x0, #0                          */
    "?? ?? ?? ?4 "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? ?? ?? "  /* adrp x0, #0x14f000                      */
    "?? ?? ?? ?? "  /* ldr x0, [x0, #0x840]                    */
    "?? ?? ?? ?4 "  /* bl __dl__ZN12LinkerLogger10ResetStateEv */
    "e4 23 00 91",  /* add x4, sp, #8                          */
    -16
  },
#endif
  { NULL, 0 }
};

GumAndroidLinkerFlavor
gum_android_get_linker_flavor (void)
{
#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  static GumAndroidLinkerFlavor cached_flavor = -1;

  if (cached_flavor == -1)
  {
    gchar * info = NULL;

    g_file_get_contents ("/sys/devices/system/cpu/modalias", &info, NULL, NULL);

    cached_flavor = (info != NULL && strstr (info, "x86") != NULL)
        ? GUM_ANDROID_LINKER_EMULATED
        : GUM_ANDROID_LINKER_NATIVE;

    g_free (info);
  }

  return cached_flavor;
#else
  return GUM_ANDROID_LINKER_NATIVE;
#endif
}

guint
gum_android_get_api_level (void)
{
  static guint cached_api_level = G_MAXUINT;

  if (cached_api_level == G_MAXUINT)
  {
    gchar sdk_version[PROP_VALUE_MAX];

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
    gum_panic ("Unable to locate the Android linker; please file a bug");

  return once.retval;
}

static const GumModuleDetails *
gum_try_init_linker_details (void)
{
  const GumModuleDetails * result = NULL;
  gchar * linker_path;
  GRegex * linker_path_pattern;
  gchar * maps, ** lines;
  gint num_lines, vdso_index, i;

  linker_path = gum_find_linker_path ();
  linker_path_pattern = gum_find_linker_path_pattern ();

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
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  for (i = vdso_index - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  goto beach;

no_vdso:
  for (i = num_lines - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

beach:
  if (result != NULL)
  {
    gum_dl_path = linker_path;
    _gum_register_destructor (gum_deinit_linker_details);
  }
  else
  {
    g_free (linker_path);
  }

  g_strfreev (lines);
  g_free (maps);
  g_regex_unref (linker_path_pattern);

  return result;
}

static void
gum_deinit_linker_details (void)
{
  g_free (gum_dl_path);
}

static gchar *
gum_find_linker_path (void)
{
  const gchar * traditional_path, * modern_path, * path;

  traditional_path = (sizeof (gpointer) == 4)
      ? "/system/bin/linker"
      : "/system/bin/linker64";

  modern_path = (sizeof (gpointer) == 4)
      ? "/apex/com.android.runtime/bin/linker"
      : "/apex/com.android.runtime/bin/linker64";

  path = (gum_android_get_api_level () >= 29)
      ? modern_path
      : traditional_path;

  return g_strdup (path);
}

static GRegex *
gum_find_linker_path_pattern (void)
{
  const gchar * pattern;

  if (gum_android_get_api_level () >= 29)
  {
    pattern = (sizeof (gpointer) == 4)
        ? "/apex/com.android.runtime[^/]*/bin/linker$"
        : "/apex/com.android.runtime[^/]*/bin/linker64$";
  }
  else
  {
    pattern = (sizeof (gpointer) == 4)
        ? "/system/bin/linker$"
        : "/system/bin/linker64$";
  }

  return g_regex_new (pattern, 0, 0, NULL);
}

static gboolean
gum_try_parse_linker_proc_maps_line (const gchar * line,
                                     const gchar * linker_path,
                                     const GRegex * linker_path_pattern,
                                     GumModuleDetails * module,
                                     GumMemoryRange * range)
{
  GumAddress start, end;
  gchar perms[5] = { 0, };
  gchar path[PATH_MAX];
  gint n;
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

  if (!g_regex_match (linker_path_pattern, path, 0, NULL))
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
      linker->range->base_address, NULL);
}

void *
gum_android_get_module_handle (const gchar * name)
{
  GumGetModuleHandleContext ctx;

  ctx.name = name;
  ctx.module = NULL;

  gum_enumerate_soinfo (
      (GumFoundSoinfoFunc) gum_store_module_handle_if_name_matches, &ctx);

  return ctx.module;
}

static gboolean
gum_store_module_handle_if_name_matches (const GumSoinfoDetails * details,
                                         GumGetModuleHandleContext * ctx)
{
  GumLinkerApi * api = details->api;

  if (gum_linux_module_path_matches (details->path, ctx->name))
  {
    GumSoinfoBody * sb = details->body;
    int flags = RTLD_LAZY;
    void * caller_addr = GSIZE_TO_POINTER (sb->base);

    if (gum_android_is_vdso_module_name (details->path))
      return FALSE;

    if ((sb->flags & GUM_SOINFO_NEW_FORMAT) != 0)
    {
      GumSoinfo * parent;

      parent = (sb->parents.head != NULL)
          ? sb->parents.head->element
          : NULL;
      if (parent != NULL)
      {
        caller_addr = GSIZE_TO_POINTER (gum_soinfo_get_body (parent)->base);
      }

      if (sb->version >= 1)
      {
        flags = sb->rtld_flags;
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

  gum_enumerate_soinfo ((GumFoundSoinfoFunc) gum_emit_module_from_soinfo, &ctx);
}

static gboolean
gum_emit_module_from_soinfo (const GumSoinfoDetails * details,
                             GumEnumerateModulesContext * ctx)
{
  gchar * name;
  GumModuleDetails module;
  GumMemoryRange range;
  gboolean carry_on;

  name = g_path_get_basename (details->path);

  module.name = name;
  module.range = &range;
  module.path = details->path;

  if (gum_soinfo_is_linker (details->si))
  {
    range = *gum_android_get_linker_module_details ()->range;
  }
  else
  {
    GumSoinfoBody * sb = details->body;

    range.base_address = sb->base;
    range.size = sb->size;
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
  GumSoinfo * somain, * sovdso, * solinker, * si, * next;
  GHashTable * ranges;
  GumSoinfoDetails details;
  gboolean carry_on;

  api = gum_linker_api_get ();

  pthread_mutex_lock (api->dl_mutex);

  somain = api->solist_get_somain ();
  sovdso = NULL;
  solinker = NULL;

  ranges = NULL;

  gum_init_soinfo_details (&details, somain, api, &ranges);
  carry_on = func (&details, user_data);

  next = NULL;
  for (si = api->solist_get_head (); carry_on && si != NULL; si = next)
  {
    gum_init_soinfo_details (&details, si, api, &ranges);

    if (si == somain)
      goto skip;

    if (gum_android_is_vdso_module_name (details.path))
    {
      sovdso = si;
      goto skip;
    }

    if (gum_android_is_linker_module_name (details.path))
    {
      solinker = si;
      goto skip;
    }

    carry_on = func (&details, user_data);

skip:
    next = details.body->next;
  }

  if (carry_on && sovdso != NULL)
  {
    gum_init_soinfo_details (&details, sovdso, api, &ranges);
    carry_on = func (&details, user_data);
  }

  if (carry_on && solinker != NULL)
  {
    gum_init_soinfo_details (&details, solinker, api, &ranges);
    carry_on = func (&details, user_data);
  }

  pthread_mutex_unlock (api->dl_mutex);

  if (ranges != NULL)
    g_hash_table_unref (ranges);
}

static void
gum_init_soinfo_details (GumSoinfoDetails * details,
                         GumSoinfo * si,
                         GumLinkerApi * api,
                         GHashTable ** ranges)
{
  details->path = gum_resolve_soinfo_path (si, api, ranges);
  details->si = si;
  details->body = gum_soinfo_get_body (si);
  details->api = api;
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

    range = g_hash_table_lookup (*ranges,
        GSIZE_TO_POINTER (gum_soinfo_get_body (si)->base));

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
    gum_panic ("Unsupported Android linker; please file a bug");

  return once.retval;
}

static GumLinkerApi *
gum_linker_api_try_init (void)
{
  GumElfModule * linker;
  guint api_level, pending;
  gboolean got_dlopen_api245, got_dlopen_api26p;

  linker = gum_android_open_linker_module ();

  api_level = gum_android_get_api_level ();

  pending = 6;
  gum_elf_module_enumerate_symbols (linker,
      (GumFoundElfSymbolFunc) gum_store_linker_symbol_if_needed, &pending);

  got_dlopen_api245 =
      (gum_dl_api.do_dlopen != NULL) && (gum_dl_api.do_dlsym != NULL);
  got_dlopen_api26p =
      (gum_dl_api.dlopen != NULL) && (gum_dl_api.dlsym != NULL);

  if (api_level >= 24)
  {
    if (api_level < 26 && (got_dlopen_api245 ||
        gum_try_find_dlopen_api245_forensically (linker, &gum_dl_api)))
    {
      pending -= 2;
    }
    else if (api_level >= 26 && !got_dlopen_api26p &&
        gum_try_find_dlopen_api26p_forensically (linker, &gum_dl_api))
    {
      pending -= 2;
    }
  }
  else if (!got_dlopen_api245 && !got_dlopen_api26p)
  {
    pending -= 2;
  }

  if (gum_dl_api.dl_mutex == NULL &&
      gum_try_find_dl_mutex_forensically (linker, &gum_dl_api.dl_mutex))
  {
    pending--;
  }

  if (gum_dl_api.solist_get_head == NULL &&
      (gum_dl_api.solist != NULL || gum_dl_api.libdl_info != NULL ||
       gum_try_find_libdl_info_forensically (linker, &gum_dl_api.libdl_info)))
  {
    gum_dl_api.solist_get_head = gum_solist_get_head_fallback;
    pending--;
  }

  if (gum_dl_api.solist_get_somain == NULL &&
      (gum_dl_api.somain != NULL ||
       gum_try_find_somain_forensically (&gum_dl_api)))
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

  gum_object_unref (linker);

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
                                   guint * pending)
{
  /* Restricted dlopen() implemented in API level >= 26 (Android >= 8.0). */
  GUM_TRY_ASSIGN (dlopen, "__dl___loader_dlopen");       /* >= 28 */
  GUM_TRY_ASSIGN (dlsym, "__dl___loader_dlvsym");        /* >= 28 */
  GUM_TRY_ASSIGN (dlopen, "__dl__Z8__dlopenPKciPKv");    /* >= 26 */
  GUM_TRY_ASSIGN (dlsym, "__dl__Z8__dlvsymPvPKcS1_PKv"); /* >= 26 */
  /* Namespaces implemented in API level >= 24 (Android >= 7.0). */
  GUM_TRY_ASSIGN_OPTIONAL (do_dlopen,
      "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv");
  GUM_TRY_ASSIGN_OPTIONAL (do_dlsym, "__dl__Z8do_dlsymPvPKcS1_S_PS_");

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

static gboolean
gum_try_find_dlopen_api245_forensically (GumElfModule * linker,
                                         GumLinkerApi * api)
{
  GumFindDlopenApiContext ctx;

  ctx.linker = linker;

  ctx.dlopen_signatures = gum_dlopen_signatures_api245;
  ctx.dlopen = NULL;

  ctx.dlsym_signatures = gum_dlsym_signatures_api245;
  ctx.dlsym = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_dlopen_api_if_found_in_section,
      &ctx);

  if (ctx.dlopen == NULL || ctx.dlsym == NULL)
    return FALSE;

  api->do_dlopen = ctx.dlopen;
  api->do_dlsym = ctx.dlsym;

  return TRUE;
}

static gboolean
gum_try_find_dlopen_api26p_forensically (GumElfModule * linker,
                                         GumLinkerApi * api)
{
  GumFindDlopenApiContext ctx;

  ctx.linker = linker;

  ctx.dlopen_signatures = gum_dlopen_signatures_api26p;
  ctx.dlopen = NULL;

  ctx.dlsym_signatures = gum_dlsym_signatures_api26p;
  ctx.dlsym = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_dlopen_api_if_found_in_section,
      &ctx);

  if (ctx.dlopen == NULL || ctx.dlsym == NULL)
    return FALSE;

  api->dlopen = ctx.dlopen;
  api->dlsym = ctx.dlsym;

  return TRUE;
}

static gboolean
gum_store_dlopen_api_if_found_in_section (const GumElfSectionDetails * details,
                                          GumFindDlopenApiContext * ctx)
{
  if (strcmp (details->name, ".text") != 0)
    return TRUE;

  ctx->dlopen = gum_find_function_by_signature (details->address, details->size,
      ctx->dlopen_signatures);

  ctx->dlsym = gum_find_function_by_signature (details->address, details->size,
      ctx->dlsym_signatures);

  return FALSE;
}

static gboolean
gum_try_find_dl_mutex_forensically (GumElfModule * linker,
                                    pthread_mutex_t ** dl_mutex)
{
  GumFindDlMutexContext ctx;

  ctx.linker = linker;
  ctx.dl_mutex = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_dl_mutex_pointer_if_found_in_section,
      &ctx);

  *dl_mutex = ctx.dl_mutex;

  return *dl_mutex != NULL;
}

static gboolean
gum_store_dl_mutex_pointer_if_found_in_section (
    const GumElfSectionDetails * details,
    GumFindDlMutexContext * ctx)
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  gpointer mutex_in_file;

  if (strcmp (details->name, ".data") != 0)
    return TRUE;

  range.base_address = GUM_ADDRESS (
      gum_elf_module_get_file_data (ctx->linker)) + details->offset;
  range.size = details->size;

  pattern = gum_match_pattern_new_from_string ("00 40 00 00");

  mutex_in_file = NULL;
  gum_memory_scan (&range, pattern, gum_store_first_scan_match, &mutex_in_file);

  if (mutex_in_file != NULL)
  {
    ctx->dl_mutex = GSIZE_TO_POINTER (
        details->address + (GUM_ADDRESS (mutex_in_file) - range.base_address));
  }

  gum_match_pattern_unref (pattern);

  return FALSE;
}

static gboolean
gum_try_find_libdl_info_forensically (GumElfModule * linker,
                                      GumSoinfo ** libdl_info)
{
  *libdl_info = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_libdl_info_pointer_if_found_in_section,
      libdl_info);

  return *libdl_info != NULL;
}

static gboolean
gum_store_libdl_info_pointer_if_found_in_section (
    const GumElfSectionDetails * details,
    GumSoinfo ** libdl_info)
{
  GumMemoryRange range;
  GumMatchPattern * pattern;

  range.base_address = details->address;
  range.size = details->size;

  if (strcmp (details->name, ".data") == 0)
  {
    pattern = gum_match_pattern_new_from_string ("6c 69 62 64 6c 2e 73 6f 00");
    gum_memory_scan (&range, pattern, gum_store_first_scan_match, libdl_info);
    gum_match_pattern_unref (pattern);
  }
  else if (strcmp (details->name, ".bss") == 0)
  {
    guint offset;

    for (offset = 0;
        offset <= details->size - sizeof (GumSoinfo);
        offset += sizeof (gpointer))
    {
      GumSoinfo * si = GSIZE_TO_POINTER (details->address + offset);
      GumSoinfoBody * sb;

      sb = gum_soinfo_get_body (si);

      if ((sb->flags & ~GUM_SOINFO_GNU_HASH) ==
          (GUM_SOINFO_NEW_FORMAT | GUM_SOINFO_LINKED))
      {
        *libdl_info = si;
        break;
      }
    }
  }

  return *libdl_info == NULL;
}

static gboolean
gum_try_find_somain_forensically (GumLinkerApi * api)
{
  GumSoinfo * si, * next;

  if (api->dl_mutex == NULL || api->solist_get_head == NULL)
    return FALSE;

  pthread_mutex_lock (api->dl_mutex);

  next = NULL;
  for (si = api->solist_get_head (); si != NULL; si = next)
  {
    GumSoinfoBody * sb = gum_soinfo_get_body (si);

    if ((sb->flags & GUM_SOINFO_EXE) != 0)
    {
      api->somain_node = si;
      break;
    }

    next = sb->next;
  }

  pthread_mutex_unlock (api->dl_mutex);

  return api->somain_node != NULL;
}

static gpointer
gum_find_function_by_signature (GumAddress address,
                                gsize size,
                                const GumFunctionSignature * signatures)
{
  GumFindFunctionSignatureContext ctx;
  GumMemoryRange range;
  const GumFunctionSignature * s;

  range.base_address = address;
  range.size = size;

  for (s = signatures; s->signature != NULL; s++)
  {
    GumMatchPattern * pattern;

    ctx.match = 0;
    ctx.num_matches = 0;

    pattern = gum_match_pattern_new_from_string (s->signature);

    gum_memory_scan (&range, pattern,
        (GumMemoryScanMatchFunc) gum_store_function_signature_match, &ctx);

    gum_match_pattern_unref (pattern);

    if (ctx.num_matches == 1)
      return GSIZE_TO_POINTER (ctx.match + s->displacement);
  }

  return NULL;
}

static gboolean
gum_store_function_signature_match (GumAddress address,
                                    gsize size,
                                    GumFindFunctionSignatureContext * ctx)
{
  ctx->match = address;
  ctx->num_matches++;

  return TRUE;
}

static gboolean
gum_store_first_scan_match (GumAddress address,
                            gsize size,
                            gpointer user_data)
{
  gpointer * match = user_data;

  *match = GSIZE_TO_POINTER (address);

  return FALSE;
}

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
  return (gum_dl_api.somain != NULL)
      ? *gum_dl_api.somain
      : gum_dl_api.somain_node;
}

#ifdef GUM_ANDROID_LEGACY_SOINFO

static GumSoinfoHead *
gum_soinfo_get_head (GumSoinfo * self)
{
  guint api_level = gum_android_get_api_level ();
  if (api_level >= 26)
    return &self->modern.head;
  else if (api_level >= 23)
    return &self->legacy23.head;
  else
    return &self->legacy.legacy23.head;
}

#endif

static GumSoinfoBody *
gum_soinfo_get_body (GumSoinfo * self)
{
  guint api_level = gum_android_get_api_level ();
  if (api_level >= 26)
    return &self->modern.body;
  else if (api_level >= 23)
    return &self->legacy23.body;
  else
    return &self->legacy.legacy23.body;
}

static gboolean
gum_soinfo_is_linker (GumSoinfo * self)
{
  return gum_soinfo_get_body (self)->base == 0;
}

static const char *
gum_soinfo_get_path_fallback (GumSoinfo * self)
{
  GumSoinfoBody * sb = gum_soinfo_get_body (self);

#ifdef GUM_ANDROID_LEGACY_SOINFO
  if ((sb->flags & GUM_SOINFO_NEW_FORMAT) != 0 && sb->version >= 2)
    return gum_libcxx_string_get_data (&sb->realpath);
  else
    return gum_soinfo_get_head (self)->old_name;
#else
  return gum_libcxx_string_get_data (&sb->realpath);
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
