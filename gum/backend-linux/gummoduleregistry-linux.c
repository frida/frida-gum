/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-elf.h"

#include "gum-init.h"
#include "gumlinux-priv.h"
#include "gummodule-elf.h"
#include "valgrind.h"
#include "gum/gumandroid.h"
#include "gum/gumlinux.h"

#ifdef HAVE_LINK_H
# include <link.h>
#endif

#define GUM_PAGE_START(value, page_size) \
    (GUM_ADDRESS (value) & ~GUM_ADDRESS (page_size - 1))

typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;

typedef gint (* GumFoundDlPhdrFunc) (struct dl_phdr_info * info,
    gsize size, gpointer data);
typedef void (* GumDlIteratePhdrImpl) (GumFoundDlPhdrFunc func, gpointer data);

typedef struct _GumProgramModules GumProgramModules;
typedef guint GumProgramRuntimeLinker;
typedef struct _GumProgramRanges GumProgramRanges;
typedef ElfW(auxv_t) * (* GumReadAuxvFunc) (void);

struct _GumEnumerateModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;

  GHashTable * named_ranges;
};

struct _GumProgramModules
{
  GumModule * program;
  GumModule * interpreter;
  GumModule * vdso;
  GumProgramRuntimeLinker rtld;
};

enum _GumProgramRuntimeLinker
{
  GUM_PROGRAM_RTLD_NONE,
  GUM_PROGRAM_RTLD_SHARED,
};

struct _GumProgramRanges
{
  GumMemoryRange program;
  GumMemoryRange interpreter;
  GumMemoryRange vdso;
};

static void gum_enumerate_modules_using_libc (GumDlIteratePhdrImpl iterate_phdr,
    GumFoundModuleFunc func, gpointer user_data);
static gint gum_emit_module_from_phdr (struct dl_phdr_info * info, gsize size,
    gpointer user_data);
static void gum_enumerate_modules_using_proc_maps (GumFoundModuleFunc func,
    gpointer user_data);
static gpointer gum_create_module_handle (GumNativeModule * module,
    gpointer user_data);
static gboolean gum_find_r_debug (GumModule * module, gpointer user_data);
static gboolean gum_find_debug_entry (const GumElfDynamicEntryDetails * details,
    gpointer user_data);

static const GumProgramModules * gum_query_program_modules (void);
static void gum_deinit_program_modules (void);
static gboolean gum_query_program_ranges (GumReadAuxvFunc read_auxv,
    GumProgramRanges * ranges);
static ElfW(auxv_t) * gum_read_auxv_from_proc (void);
static ElfW(auxv_t) * gum_read_auxv_from_stack (void);
static gboolean gum_query_main_thread_stack_range (GumMemoryRange * range);
static void gum_compute_elf_range_from_ehdr (const ElfW(Ehdr) * ehdr,
    GumMemoryRange * range);
static void gum_compute_elf_range_from_phdrs (const ElfW(Phdr) * phdrs,
    ElfW(Half) phdr_size, ElfW(Half) phdr_count, GumAddress base_address,
    GumMemoryRange * range);

static struct r_debug * gum_r_debug;
static GumProgramModules gum_program_modules;

void
_gum_module_registry_enumerate_loaded_modules (GumFoundModuleFunc func,
                                               gpointer user_data)
{
  const GumProgramModules * pm;
  static gsize iterate_phdr_value = 0;
  GumDlIteratePhdrImpl iterate_phdr;

  pm = gum_query_program_modules ();

  if (pm->rtld == GUM_PROGRAM_RTLD_NONE)
  {
    if (!func (pm->program, user_data))
      return;

    if (pm->vdso != NULL)
      func (pm->vdso, user_data);

    return;
  }

#ifdef HAVE_ANDROID
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
  {
    gum_android_enumerate_modules (func, user_data);
    return;
  }
#endif

  if (g_once_init_enter (&iterate_phdr_value))
  {
    gpointer libc, impl;

    libc = dlopen (_gum_process_get_libc_info ()->dli_fname,
        RTLD_LAZY | RTLD_GLOBAL);
    g_assert (libc != NULL);

    impl = dlsym (libc, "dl_iterate_phdr");

    dlclose (libc);

    g_once_init_leave (&iterate_phdr_value, GPOINTER_TO_SIZE (impl) + 1);
  }

  iterate_phdr = GSIZE_TO_POINTER (iterate_phdr_value - 1);
  if (iterate_phdr != NULL)
    gum_enumerate_modules_using_libc (iterate_phdr, func, user_data);
  else
    gum_enumerate_modules_using_proc_maps (func, user_data);
}

static void
gum_enumerate_modules_using_libc (GumDlIteratePhdrImpl iterate_phdr,
                                  GumFoundModuleFunc func,
                                  gpointer user_data)
{
  GumEnumerateModulesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.named_ranges = gum_linux_collect_named_ranges ();

  iterate_phdr (gum_emit_module_from_phdr, &ctx);

  g_hash_table_unref (ctx.named_ranges);
}

static gint
gum_emit_module_from_phdr (struct dl_phdr_info * info,
                           gsize size,
                           gpointer user_data)
{
  GumEnumerateModulesContext * ctx = user_data;
  GumMemoryRange range;
  GumLinuxNamedRange * named_range;
  const gchar * path;
  GumNativeModule * module;
  gboolean carry_on;

  gum_compute_elf_range_from_phdrs (info->dlpi_phdr, sizeof (ElfW(Phdr)),
      info->dlpi_phnum, 0, &range);

  named_range = g_hash_table_lookup (ctx->named_ranges,
      GSIZE_TO_POINTER (range.base_address));

  path = (named_range != NULL) ? named_range->name : info->dlpi_name;

  module = _gum_native_module_make (path, &range, gum_create_module_handle,
      NULL, NULL, (GDestroyNotify) dlclose);

  carry_on = ctx->func (GUM_MODULE (module), ctx->user_data);

  g_object_unref (module);

  return carry_on ? 0 : 1;
}

static void
gum_enumerate_modules_using_proc_maps (GumFoundModuleFunc func,
                                       gpointer user_data)
{
  GumProcMapsIter iter;
  gchar * path, * next_path;
  const gchar * line;
  gboolean carry_on = TRUE;
  gboolean got_line = FALSE;

  gum_proc_maps_iter_init_for_self (&iter);

  path = g_malloc (PATH_MAX);
  next_path = g_malloc (PATH_MAX);

  do
  {
    const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };
    GumMemoryRange range;
    GumAddress end;
    gchar perms[5] = { 0, };
    gint n;
    gboolean is_vdso, readable, shared;
    GumNativeModule * module;

    if (!got_line)
    {
      if (!gum_proc_maps_iter_next (&iter, &line))
        break;
    }
    else
    {
      got_line = FALSE;
    }

    n = sscanf (line,
        "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
        "%4c "
        "%*x %*s %*d "
        "%[^\n]",
        &range.base_address, &end,
        perms,
        path);
    if (n == 3)
      continue;
    g_assert (n == 4);

    is_vdso = _gum_try_translate_vdso_name (path);

    readable = perms[0] == 'r';
    shared = perms[3] == 's';
    if (!readable || shared)
      continue;
    else if ((path[0] != '/' && !is_vdso) || g_str_has_prefix (path, "/dev/"))
      continue;
    else if (RUNNING_ON_VALGRIND && strstr (path, "/valgrind/") != NULL)
      continue;
    else if (memcmp (GSIZE_TO_POINTER (range.base_address), elf_magic,
        sizeof (elf_magic)) != 0)
      continue;

    range.size = end - range.base_address;

    while (gum_proc_maps_iter_next (&iter, &line))
    {
      n = sscanf (line,
          "%*x-%" G_GINT64_MODIFIER "x %*c%*c%*c%*c %*x %*s %*d %[^\n]",
          &end,
          next_path);
      if (n == 1)
      {
        continue;
      }
      else if (n == 2 && next_path[0] == '[')
      {
        if (!_gum_try_translate_vdso_name (next_path))
          continue;
      }

      if (n == 2 && strcmp (next_path, path) == 0)
      {
        range.size = end - range.base_address;
      }
      else
      {
        got_line = TRUE;
        break;
      }
    }

    module = _gum_native_module_make (path, &range, gum_create_module_handle,
        NULL, NULL, (GDestroyNotify) dlclose);

    carry_on = func (GUM_MODULE (module), user_data);

    g_object_unref (module);
  }
  while (carry_on);

  g_free (path);
  g_free (next_path);

  gum_proc_maps_iter_destroy (&iter);
}

static gpointer
gum_create_module_handle (GumNativeModule * module,
                          gpointer user_data)
{
#if defined (HAVE_MUSL)
  struct link_map * cur;

  for (cur = dlopen (NULL, 0); cur != NULL; cur = cur->l_next)
  {
    if (gum_linux_module_path_matches (cur->l_name, module->path))
      return cur;
  }

  for (cur = dlopen (NULL, 0); cur != NULL; cur = cur->l_next)
  {
    gchar * target, * parent_dir, * canonical_path;
    gboolean is_match;

    target = g_file_read_link (cur->l_name, NULL);
    if (target == NULL)
      continue;
    parent_dir = g_path_get_dirname (cur->l_name);
    canonical_path = g_canonicalize_filename (target, parent_dir);

    is_match = gum_linux_module_path_matches (canonical_path, module->path);

    g_free (canonical_path);
    g_free (parent_dir);
    g_free (target);

    if (is_match)
      return cur;
  }

  return NULL;
#else
  return dlopen (module->path, RTLD_LAZY | RTLD_NOLOAD);
#endif
}

void
_gum_module_registry_enumerate_rtld_notifiers (GumFoundRtldNotifierFunc func,
                                               gpointer user_data)
{
  struct r_debug * dbg = NULL;
  GumRtldNotifierDetails notifier;

  _gum_module_registry_enumerate_loaded_modules (gum_find_r_debug, &dbg);
  if (dbg == NULL)
    return;

  gum_r_debug = dbg;

  notifier.location = GSIZE_TO_POINTER (dbg->r_brk);
  notifier.point_cut = GUM_POINT_ENTER;
  func (&notifier, user_data);
}

static gboolean
gum_find_r_debug (GumModule * module,
                  gpointer user_data)
{
  struct r_debug ** dbg = user_data;

  gum_elf_module_enumerate_dynamic_entries (
      _gum_native_module_get_elf_module (GUM_NATIVE_MODULE (module)),
      gum_find_debug_entry, dbg);

  return *dbg == NULL;
}

static gboolean
gum_find_debug_entry (const GumElfDynamicEntryDetails * details,
                      gpointer user_data)
{
  struct r_debug ** dbg = user_data;

  if (details->tag == GUM_ELF_DYNAMIC_DEBUG)
  {
    *dbg = GSIZE_TO_POINTER (details->val);
    return FALSE;
  }

  return TRUE;
}

void
_gum_module_registry_handle_rtld_notification (GumSynchronizeModulesFunc sync,
                                               GumInvocationContext * ic)
{
  if (gum_r_debug->r_state == RT_CONSISTENT)
    sync ();
}

static const GumProgramModules *
gum_query_program_modules (void)
{
  static gsize modules_value = 0;

  if (g_once_init_enter (&modules_value))
  {
    static GumProgramRanges ranges;
    gboolean got_kern, got_user;
    GumProgramRanges kern, user;
    GumProcMapsIter iter;
    gchar * path;
    const gchar * line;

    got_kern = gum_query_program_ranges (gum_read_auxv_from_proc, &kern);
    got_user = gum_query_program_ranges (gum_read_auxv_from_stack, &user);
    if (got_kern && got_user &&
        user.program.base_address != kern.program.base_address)
    {
      ranges = user;
      ranges.interpreter = kern.program;
    }
    else if (got_kern)
      ranges = kern;
    else
      ranges = user;

    gum_program_modules.rtld = (ranges.interpreter.base_address == 0)
        ? GUM_PROGRAM_RTLD_NONE
        : GUM_PROGRAM_RTLD_SHARED;

    gum_proc_maps_iter_init_for_self (&iter);
    path = g_malloc (PATH_MAX);

    while (gum_proc_maps_iter_next (&iter, &line))
    {
      GumAddress start;
      GumModule ** m;
      const GumMemoryRange * r;

      sscanf (line, "%" G_GINT64_MODIFIER "x-", &start);

      if (start == ranges.program.base_address)
      {
        m = &gum_program_modules.program;
        r = &ranges.program;
      }
      else if (start == ranges.interpreter.base_address)
      {
        m = &gum_program_modules.interpreter;
        r = &ranges.interpreter;
      }
      else
        continue;

      sscanf (line, "%*x-%*x %*c%*c%*c%*c %*x %*s %*d %[^\n]", path);

      *m = GUM_MODULE (_gum_native_module_make_handleless (path, r));
    }

    g_free (path);
    gum_proc_maps_iter_destroy (&iter);

    if (ranges.vdso.base_address != 0)
    {
      /* FIXME: Parse soname instead of hardcoding: */
      gum_program_modules.vdso = GUM_MODULE (
          _gum_native_module_make_handleless ("linux-vdso.so.1", &ranges.vdso));
    }

    _gum_register_destructor (gum_deinit_program_modules);

    g_once_init_leave (&modules_value, GPOINTER_TO_SIZE (&gum_program_modules));
  }

  return GSIZE_TO_POINTER (modules_value);
}

static void
gum_deinit_program_modules (void)
{
  GumProgramModules * m = &gum_program_modules;

  g_object_unref (m->program);
  if (m->interpreter != NULL)
    g_object_unref (m->interpreter);
  if (m->vdso != NULL)
    g_object_unref (m->vdso);
}

static gboolean
gum_query_program_ranges (GumReadAuxvFunc read_auxv,
                          GumProgramRanges * ranges)
{
  gboolean success = FALSE;
  ElfW(auxv_t) * auxv;
  const ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_size, phdr_count;
  const ElfW(Ehdr) * interpreter, * vdso;
  ElfW(auxv_t) * entry;

  bzero (ranges, sizeof (GumProgramRanges));

  auxv = read_auxv ();
  if (auxv == NULL)
    goto beach;

  phdrs = NULL;
  phdr_size = 0;
  phdr_count = 0;
  interpreter = NULL;
  vdso = NULL;
  for (entry = auxv; entry->a_type != AT_NULL; entry++)
  {
    switch (entry->a_type)
    {
      case AT_PHDR:
        phdrs = (ElfW(Phdr) *) entry->a_un.a_val;
        break;
      case AT_PHENT:
        phdr_size = entry->a_un.a_val;
        break;
      case AT_PHNUM:
        phdr_count = entry->a_un.a_val;
        break;
      case AT_BASE:
        interpreter = (const ElfW(Ehdr) *) entry->a_un.a_val;
        break;
      case AT_SYSINFO_EHDR:
        vdso = (const ElfW(Ehdr) *) entry->a_un.a_val;
        break;
    }
  }
  if (phdrs == NULL || phdr_size == 0 || phdr_count == 0)
    goto beach;

  gum_compute_elf_range_from_phdrs (phdrs, phdr_size, phdr_count, 0,
      &ranges->program);
  gum_compute_elf_range_from_ehdr (interpreter, &ranges->interpreter);
  gum_compute_elf_range_from_ehdr (vdso, &ranges->vdso);

  success = TRUE;

beach:
  g_free (auxv);

  return success;
}

static ElfW(auxv_t) *
gum_read_auxv_from_proc (void)
{
  ElfW(auxv_t) * auxv = NULL;

  _gum_acquire_dumpability ();

  g_file_get_contents ("/proc/self/auxv", (gchar **) &auxv, NULL, NULL);

  _gum_release_dumpability ();

  return auxv;
}

static ElfW(auxv_t) *
gum_read_auxv_from_stack (void)
{
  GumMemoryRange stack;
  gpointer stack_start, stack_end;
  ElfW(auxv_t) needle;
  const ElfW(auxv_t) * match, * last_match;
  gsize offset;
  const ElfW(auxv_t) * cursor, * auxv_start, * auxv_end;
  gsize page_size;

  if (!gum_query_main_thread_stack_range (&stack))
    return NULL;
  stack_start = GSIZE_TO_POINTER (stack.base_address);
  stack_end = stack_start + stack.size;

  needle.a_type = AT_PHENT;
  needle.a_un.a_val = sizeof (ElfW(Phdr));

  match = NULL;
  last_match = NULL;
  offset = 0;
  while (offset != stack.size)
  {
    match = memmem (GSIZE_TO_POINTER (stack.base_address) + offset,
        stack.size - offset, &needle, sizeof (needle));
    if (match == NULL)
      break;

    last_match = match;
    offset = (GUM_ADDRESS (match) - stack.base_address) + 1;
  }
  if (last_match == NULL)
    return NULL;

  auxv_start = NULL;
  page_size = gum_query_page_size ();
  for (cursor = last_match - 1;
      (gpointer) cursor >= stack_start;
      cursor--)
  {
    gboolean probably_an_invalid_type = cursor->a_type >= page_size;
    if (probably_an_invalid_type)
    {
      auxv_start = cursor + 1;
      break;
    }
  }

  auxv_end = NULL;
  for (cursor = last_match + 1;
      (gpointer) cursor <= stack_end - sizeof (ElfW(auxv_t));
      cursor++)
  {
    if (cursor->a_type == AT_NULL)
    {
      auxv_end = cursor + 1;
      break;
    }
  }
  if (auxv_end == NULL)
    return NULL;

  return g_memdup (auxv_start, (guint8 *) auxv_end - (guint8 *) auxv_start);
}

static gboolean
gum_query_main_thread_stack_range (GumMemoryRange * range)
{
  GumProcMapsIter iter;
  GumAddress stack_bottom, stack_top;
  const gchar * line;

  gum_proc_maps_iter_init_for_self (&iter);

  stack_bottom = 0;
  stack_top = 0;

  while (gum_proc_maps_iter_next (&iter, &line))
  {
    if (g_str_has_suffix (line, " [stack]"))
    {
      sscanf (line,
          "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x ",
          &stack_bottom,
          &stack_top);
      break;
    }
  }

  range->base_address = stack_bottom;
  range->size = stack_top - stack_bottom;

  gum_proc_maps_iter_destroy (&iter);

  return range->size != 0;
}

static void
gum_compute_elf_range_from_ehdr (const ElfW(Ehdr) * ehdr,
                                 GumMemoryRange * range)
{
  if (ehdr == NULL)
  {
    range->base_address = 0;
    range->size = 0;
    return;
  }

  gum_compute_elf_range_from_phdrs ((gconstpointer) ehdr + ehdr->e_phoff,
      ehdr->e_phentsize, ehdr->e_phnum, GUM_ADDRESS (ehdr), range);
}

static void
gum_compute_elf_range_from_phdrs (const ElfW(Phdr) * phdrs,
                                  ElfW(Half) phdr_size,
                                  ElfW(Half) phdr_count,
                                  GumAddress base_address,
                                  GumMemoryRange * range)
{
  GumAddress lowest, highest;
  gsize page_size;
  ElfW(Half) i;
  const ElfW(Phdr) * phdr;

  range->base_address = 0;

  lowest = ~0;
  highest = 0;
  page_size = gum_query_page_size ();

  for (i = 0, phdr = phdrs;
      i != phdr_count;
      i++, phdr = (gconstpointer) phdr + phdr_size)
  {
    if (phdr->p_type == PT_PHDR)
      range->base_address = GPOINTER_TO_SIZE (phdrs) - phdr->p_offset;

    if (phdr->p_type == PT_LOAD && phdr->p_offset == 0)
    {
      if (range->base_address == 0)
        range->base_address = phdr->p_vaddr;
    }

    if (phdr->p_type == PT_LOAD)
    {
      lowest = MIN (GUM_PAGE_START (phdr->p_vaddr, page_size), lowest);
      highest = MAX (phdr->p_vaddr + phdr->p_memsz, highest);
    }
  }

  if (range->base_address == 0)
  {
    range->base_address = (base_address != 0)
        ? base_address
        : GUM_PAGE_START (phdrs, page_size);
  }

  range->size = highest - lowest;
}
