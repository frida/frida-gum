/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess.h"

#include "gumdarwin.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <malloc/malloc.h>
#include <sys/sysctl.h>

#define MAX_MACH_HEADER_SIZE (64 * 1024)
#define DYLD_INFO_COUNT 5
#define DYLD_INFO_LEGACY_COUNT 1
#define DYLD_INFO_32_COUNT 3
#define DYLD_INFO_64_COUNT 5
#define DYLD_IMAGE_INFO_32_SIZE 12
#define DYLD_IMAGE_INFO_64_SIZE 24

#define SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL(S) \
      (S->n_value == 0 || \
       S->n_type >= N_PEXT || \
       (S->n_type & N_EXT) == 0)

typedef struct _GumFindEntrypointContext GumFindEntrypointContext;
typedef struct _GumEnumerateModulesSlowContext GumEnumerateModulesSlowContext;
typedef struct _GumFindExportContext GumFindExportContext;
typedef struct _GumEnumerateExportsContext GumEnumerateExportsContext;
typedef struct _GumEnumerateMallocRangesContext GumEnumerateMallocRangesContext;

typedef union _DyldInfo DyldInfo;
typedef struct _DyldInfoLegacy DyldInfoLegacy;
typedef struct _DyldInfo32 DyldInfo32;
typedef struct _DyldInfo64 DyldInfo64;
typedef struct _DyldAllImageInfos32 DyldAllImageInfos32;
typedef struct _DyldAllImageInfos64 DyldAllImageInfos64;
typedef struct _DyldImageInfo32 DyldImageInfo32;
typedef struct _DyldImageInfo64 DyldImageInfo64;

struct _GumFindEntrypointContext
{
  GumAddress result;
  mach_port_t task;
  guint alignment;
};

struct _GumEnumerateModulesSlowContext
{
  mach_port_t task;
  GumFoundModuleFunc func;
  gpointer user_data;

  GArray * ranges;
  guint alignment;
};

struct _GumFindExportContext
{
  GumAddress result;
  const gchar * symbol_name;
};

struct _GumEnumerateExportsContext
{
  mach_port_t task;
  GHashTable * modules;
  GHashTable * strings;
  const gchar * module_name;
  GumFoundExportFunc func;
  gpointer user_data;
};

struct _GumEnumerateMallocRangesContext
{
  GumFoundMallocRangeFunc func;
  gpointer user_data;
  gboolean carry_on;
};

struct _DyldInfoLegacy
{
  guint32 all_image_info_addr;
};

struct _DyldInfo32
{
  guint32 all_image_info_addr;
  guint32 all_image_info_size;
  gint32 all_image_info_format;
};

struct _DyldInfo64
{
  guint64 all_image_info_addr;
  guint64 all_image_info_size;
  gint32 all_image_info_format;
};

union _DyldInfo
{
  DyldInfoLegacy info_legacy;
  DyldInfo32 info_32;
  DyldInfo64 info_64;
};

struct _DyldAllImageInfos32
{
  guint32 version;
  guint32 info_array_count;
  guint32 info_array;
};

struct _DyldAllImageInfos64
{
  guint32 version;
  guint32 info_array_count;
  guint64 info_array;
};

struct _DyldImageInfo32
{
  guint32 image_load_address;
  guint32 image_file_path;
  guint32 image_file_mod_date;
};

struct _DyldImageInfo64
{
  guint64 image_load_address;
  guint64 image_file_path;
  guint64 image_file_mod_date;
};

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
typedef arm_unified_thread_state_t gum_thread_state_t;
# define GUM_THREAD_STATE_COUNT ARM_UNIFIED_THREAD_STATE_COUNT
# define GUM_THREAD_STATE_FLAVOR ARM_UNIFIED_THREAD_STATE
#else
typedef x86_thread_state_t gum_thread_state_t;
# define GUM_THREAD_STATE_COUNT x86_THREAD_STATE_COUNT
# define GUM_THREAD_STATE_FLAVOR x86_THREAD_STATE
#endif

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_LC_SEGMENT LC_SEGMENT
typedef struct mach_header gum_mach_header_t;
typedef struct segment_command gum_segment_command_t;
typedef struct nlist gum_nlist_t;
#else
# define GUM_LC_SEGMENT LC_SEGMENT_64
typedef struct mach_header_64 gum_mach_header_t;
typedef struct segment_command_64 gum_segment_command_t;
typedef struct nlist_64 gum_nlist_t;
#endif

#ifndef PROC_SETPC_NONE
extern int proc_regionfilename (int pid, uint64_t address, void * buffer,
    uint32_t buffersize);
#endif

typedef const struct dyld_all_image_infos * (* DyldGetAllImageInfosFunc) (
    void);

static void gum_emit_malloc_ranges (task_t task,
    void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t gum_read_malloc_memory (task_t remote_task,
    vm_address_t remote_address, vm_size_t size, void ** local_memory);

static gboolean gum_module_do_enumerate_exports (const gchar * module_name,
    GumFoundExportFunc func, gpointer user_data);
static gboolean gum_store_address_if_export_name_matches (
    const GumExportDetails * details, gpointer user_data);
static gboolean gum_probe_range_for_entrypoint (const GumRangeDetails * details,
    gpointer user_data);
static void gum_darwin_enumerate_modules_slow (mach_port_t task,
    GumFoundModuleFunc func, gpointer user_data);
static gboolean gum_store_range_of_potential_modules (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_emit_modules_in_range (const GumMemoryRange * range,
    GumEnumerateModulesSlowContext * ctx);

static gboolean gum_store_module_address (const GumModuleDetails * details,
    gpointer user_data);
static gboolean gum_do_enumerate_exports (GumEnumerateExportsContext * ctx,
    const gchar * module_name);
static GSList * gum_darwin_find_text_section_ids (guint8 * module,
    gsize module_size);

static gboolean find_image_address_and_slide (const gchar * image_name,
    gpointer * address, gpointer * slide);
static gboolean find_image_vmaddr_and_fileoff (gconstpointer address,
    gsize * vmaddr, gsize * fileoff);
static gsize find_image_size (const gchar * image_name);
static GSList * find_image_text_section_ids (gconstpointer address);
static gboolean find_image_symtab_command (gconstpointer address,
    const struct symtab_command ** sc);

static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);

static GumThreadState gum_thread_state_from_darwin (integer_t run_state);
static void gum_cpu_context_from_darwin (const gum_thread_state_t * state,
    GumCpuContext * ctx);
static void gum_cpu_context_to_darwin (const GumCpuContext * ctx,
    gum_thread_state_t * state);
static const char * gum_symbol_name_from_darwin (const char * s);

static DyldGetAllImageInfosFunc get_all_image_infos_impl = NULL;

gboolean
gum_process_is_debugger_attached (void)
{
  int mib[4];
  struct kinfo_proc info;
  size_t size;
  int result;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = getpid ();

  size = sizeof (info);
  result = sysctl (mib, G_N_ELEMENTS (mib), &info, &size, NULL, 0);
  g_assert_cmpint (result, ==, 0);

  return (info.kp_proc.p_flag & P_TRACED) != 0;
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  mach_port_t port;

  port = mach_thread_self ();
  mach_port_deallocate (mach_task_self (), port);
  return (GumThreadId) port;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  gboolean success = FALSE;
  mach_port_t task;
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  kern_return_t kr;

  task = mach_task_self ();

  kr = task_threads (task, &threads, &count);
  if (kr == KERN_SUCCESS)
  {
    guint i;

    for (i = 0; i != count; i++)
    {
      thread_t thread = threads[i];

      if (thread == thread_id)
      {
        gum_thread_state_t state;
        mach_msg_type_number_t state_count = GUM_THREAD_STATE_COUNT;
        thread_state_flavor_t state_flavor = GUM_THREAD_STATE_FLAVOR;
        GumCpuContext cpu_context;

        kr = thread_suspend (thread);
        if (kr != KERN_SUCCESS)
          break;

        kr = thread_get_state (thread, state_flavor, (thread_state_t) &state,
            &state_count);
        if (kr != KERN_SUCCESS)
        {
          thread_resume (thread);
          break;
        }

        gum_cpu_context_from_darwin (&state, &cpu_context);
        func (thread_id, &cpu_context, user_data);
        gum_cpu_context_to_darwin (&cpu_context, &state);

        kr = thread_set_state (thread, state_flavor, (thread_state_t) &state,
            state_count);

        success =
            (thread_resume (thread) == KERN_SUCCESS && kr == KERN_SUCCESS);
      }
    }

    for (i = 0; i != count; i++)
      mach_port_deallocate (task, threads[i]);
    vm_deallocate (task, (vm_address_t) threads, count * sizeof (thread_t));
  }

  return success;
}

void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data)
{
  gum_darwin_enumerate_threads (mach_task_self (), func, user_data);
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  const struct dyld_all_image_infos * all_info;
  guint count, i;

  if (get_all_image_infos_impl == NULL)
  {
    void * syslib;

    syslib = dlopen ("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_GLOBAL);
    get_all_image_infos_impl = dlsym (syslib, "_dyld_get_all_image_infos");
    g_assert (get_all_image_infos_impl != NULL);
    dlclose (syslib);
  }

  all_info = get_all_image_infos_impl ();

  count = all_info->infoArrayCount;
  for (i = 0; i != count; i++)
  {
    const struct dyld_image_info * info = &all_info->infoArray[i];
    gchar * name;
    GumMemoryRange range;
    GumModuleDetails details;
    gboolean carry_on;

    name = g_path_get_basename (info->imageFilePath);

    range.base_address = GUM_ADDRESS (info->imageLoadAddress);
    range.size = find_image_size (info->imageFilePath);

    details.name = name;
    details.range = &range;
    details.path = info->imageFilePath;

    carry_on = func (&details, user_data);

    g_free (name);

    if (!carry_on)
      break;
  }
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  gum_darwin_enumerate_ranges (mach_task_self (), prot, func, user_data);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  task_t task;
  kern_return_t ret;
  unsigned i;
  vm_address_t * malloc_zone_addresses;
  unsigned malloc_zone_count;

  task = mach_task_self ();

  ret = malloc_get_all_zones (task,
      gum_read_malloc_memory, &malloc_zone_addresses,
      &malloc_zone_count);
  if (ret != KERN_SUCCESS)
    return;

  for (i = 0; i != malloc_zone_count; i++)
  {
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t * zone = (malloc_zone_t *) zone_address;

    if (zone != NULL && zone->introspect != NULL &&
        zone->introspect->enumerator != NULL)
    {
      GumEnumerateMallocRangesContext ctx = { func, user_data, TRUE };

      zone->introspect->enumerator (task, &ctx,
          MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address,
          gum_read_malloc_memory,
          gum_emit_malloc_ranges);

      if (!ctx.carry_on)
        return;
    }
  }
}

static void
gum_emit_malloc_ranges (task_t task,
                        void * user_data,
                        unsigned type,
                        vm_range_t * ranges,
                        unsigned count)
{
  GumEnumerateMallocRangesContext * ctx =
      (GumEnumerateMallocRangesContext *) user_data;
  GumMemoryRange gum_range;
  GumMallocRangeDetails details;
  unsigned i;

  if (!ctx->carry_on)
    return;

  details.range = &gum_range;

  for (i = 0; i != count; i++)
  {
    vm_range_t range = ranges[i];

    gum_range.base_address = range.address;
    gum_range.size = range.size;

    ctx->carry_on = ctx->func (&details, ctx->user_data);
    if (!ctx->carry_on)
      return;
  }
}

static kern_return_t
gum_read_malloc_memory (task_t remote_task,
                        vm_address_t remote_address,
                        vm_size_t size,
                        void ** local_memory)
{
  *local_memory = (void *) remote_address;

  return KERN_SUCCESS;
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  gum_module_do_enumerate_exports (module_name, func, user_data);
}

static gboolean
gum_module_do_enumerate_exports (const gchar * module_name,
                                 GumFoundExportFunc func,
                                 gpointer user_data)
{
  gboolean carry_on = TRUE;
  gpointer address, slide;
  gsize vmaddr, fileoff;
  GSList * text_section_ids = NULL;
  const struct symtab_command * sc;
  guint8 * table_base;
  gum_nlist_t * symbase, * sym;
  gchar * strbase;
  guint symbol_index;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    goto beach;

  if (!find_image_vmaddr_and_fileoff (address, &vmaddr, &fileoff))
    goto beach;

  text_section_ids = find_image_text_section_ids (address);

  if (!find_image_symtab_command (address, &sc))
    goto beach;

  table_base = GSIZE_TO_POINTER (vmaddr - fileoff + GPOINTER_TO_SIZE (slide));
  symbase = (gum_nlist_t *) (table_base + sc->symoff);
  strbase = (gchar *) (table_base + sc->stroff);

  for (symbol_index = 0, sym = symbase;
      symbol_index != sc->nsyms;
      symbol_index++, sym++)
  {
    GumExportDetails details;

    if (SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL (sym))
      continue;

    details.type =
        g_slist_find (text_section_ids, GSIZE_TO_POINTER (sym->n_sect)) != NULL
        ? GUM_EXPORT_FUNCTION : GUM_EXPORT_VARIABLE;
    details.name = gum_symbol_name_from_darwin (strbase + sym->n_un.n_strx);
    details.address = GUM_ADDRESS (
        GSIZE_TO_POINTER (sym->n_value) + GPOINTER_TO_SIZE (slide));
    if ((sym->n_desc & N_ARM_THUMB_DEF) != 0)
      details.address++;

    carry_on = func (&details, user_data);

    if (!carry_on)
      goto beach;
  }

  {
    gum_mach_header_t * header = address;
    guint8 * p;
    guint cmd_index;

    p = (guint8 *) (header + 1);
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == LC_REEXPORT_DYLIB)
      {
        struct dylib_command * dc = (struct dylib_command *) lc;
        const char * name = (const char *)
            (((guint8 *) dc) + dc->dylib.name.offset);
        if (!gum_module_do_enumerate_exports (name, func, user_data))
          return FALSE;
      }

      p += lc->cmdsize;
    }
  }

beach:
  g_slist_free (text_section_ids);

  return carry_on;
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  gpointer address, slide;
  gum_mach_header_t * header;
  guint8 * p;
  guint cmd_index;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return;

  header = address;
  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == GUM_LC_SEGMENT)
    {
      gum_segment_command_t * segcmd = (gum_segment_command_t *) lc;
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_mach (segcmd->initprot);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;

        range.base_address = GUM_ADDRESS (
            GSIZE_TO_POINTER (segcmd->vmaddr) + GPOINTER_TO_SIZE (slide));
        range.size = segcmd->vmsize;

        details.range = &range;
        details.prot = cur_prot;
        details.file = NULL; /* TODO */

        if (!func (&details, user_data))
          return;
      }
    }

    p += lc->cmdsize;
  }
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  gpointer address, slide;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return 0;

  return GUM_ADDRESS (address);
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumFindExportContext ctx;

  ctx.result = 0;
  ctx.symbol_name = symbol_name;

  gum_module_enumerate_exports (module_name,
      gum_store_address_if_export_name_matches, &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_export_name_matches (const GumExportDetails * details,
                                          gpointer user_data)
{
  GumFindExportContext * ctx = (GumFindExportContext *) user_data;

  if (strcmp (details->name, ctx->symbol_name) == 0)
  {
    ctx->result = details->address;
    return FALSE;
  }

  return TRUE;
}

gboolean
gum_darwin_cpu_type_from_pid (pid_t pid,
                              GumCpuType * cpu_type)
{
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  struct kinfo_proc kp;
  size_t bufsize = sizeof (kp);
  int err;

  memset (&kp, 0, sizeof (kp));
  err = sysctl (mib, G_N_ELEMENTS (mib), &kp, &bufsize, NULL, 0);
  if (err != 0)
    return FALSE;

#ifdef HAVE_I386
  *cpu_type = (kp.kp_proc.p_flag & P_LP64) ? GUM_CPU_AMD64 : GUM_CPU_IA32;
#else
  *cpu_type = (kp.kp_proc.p_flag & P_LP64) ? GUM_CPU_ARM64 : GUM_CPU_ARM;
#endif
  return TRUE;
}

GumAddress
gum_darwin_find_entrypoint (mach_port_t task)
{
  GumFindEntrypointContext ctx;

  ctx.result = 0;
  ctx.task = task;
  ctx.alignment = 4096;

  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX,
      gum_probe_range_for_entrypoint, &ctx);

  return ctx.result;
}

static gboolean
gum_probe_range_for_entrypoint (const GumRangeDetails * details,
                                gpointer user_data)
{
  const GumMemoryRange * range = details->range;
  GumFindEntrypointContext * ctx = user_data;
  gboolean carry_on = TRUE;
  guint8 * chunk, * page, * p;
  gsize chunk_size;

  chunk = gum_darwin_read (ctx->task, range->base_address, range->size,
      &chunk_size);
  if (chunk == NULL)
    return TRUE;

  g_assert (chunk_size % ctx->alignment == 0);

  for (page = chunk; page != chunk + chunk_size; page += ctx->alignment)
  {
    struct mach_header * header;
    gint64 slide;
    guint cmd_index;
    GumAddress text_base = 0, text_offset = 0;

    header = (struct mach_header *) page;
    if (header->magic != MH_MAGIC && header->magic != MH_MAGIC_64)
      continue;

    if (header->filetype != MH_EXECUTE)
      continue;

    if (!gum_darwin_find_slide (range->base_address + (page - chunk), page,
          chunk_size - (page - chunk), &slide))
    {
      continue;
    }

    carry_on = FALSE;

    if (header->magic == MH_MAGIC)
      p = page + sizeof (struct mach_header);
    else
      p = page + sizeof (struct mach_header_64);
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      switch (lc->cmd)
      {
        case LC_SEGMENT:
        {
          struct segment_command * sc = (struct segment_command *) lc;
          if (strcmp (sc->segname, "__TEXT") == 0)
            text_base = sc->vmaddr + slide;
          break;
        }
        case LC_SEGMENT_64:
        {
          struct segment_command_64 * sc = (struct segment_command_64 *) lc;
          if (strcmp (sc->segname, "__TEXT") == 0)
            text_base = sc->vmaddr + slide;
          break;
        }
#ifdef HAVE_I386
        case LC_UNIXTHREAD:
        {
          guint8 * thread = p + sizeof (struct thread_command);
          while (thread != p + lc->cmdsize)
          {
            thread_state_flavor_t * flavor = (thread_state_flavor_t *) thread;
            mach_msg_type_number_t * count = (mach_msg_type_number_t *)
                (flavor + 1);
            if (header->magic == MH_MAGIC && *flavor == x86_THREAD_STATE32)
            {
              x86_thread_state32_t * ts = (x86_thread_state32_t *) (count + 1);
              ctx->result = ts->__eip + slide;
            }
            else if (header->magic == MH_MAGIC_64 &&
                *flavor == x86_THREAD_STATE64)
            {
              x86_thread_state64_t * ts = (x86_thread_state64_t *) (count + 1);
              ctx->result = ts->__rip + slide;
            }
            thread = ((guint8 *) (count + 1)) + (*count * sizeof (int));
          }
          break;
        }
#endif
        case LC_MAIN:
        {
          struct entry_point_command * ec = (struct entry_point_command *) p;
          text_offset = ec->entryoff;
          break;
        }
      }
      p += lc->cmdsize;
    }

    if (ctx->result == 0)
      ctx->result = text_base + text_offset;

    if (!carry_on)
      break;
  }

  g_free (chunk);
  return carry_on;
}

void
gum_darwin_enumerate_threads (mach_port_t task,
                              GumFoundThreadFunc func,
                              gpointer user_data)
{
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  kern_return_t kr;

  kr = task_threads (task, &threads, &count);
  if (kr == KERN_SUCCESS)
  {
    guint i;

    for (i = 0; i != count; i++)
    {
      thread_t thread = threads[i];
      GumThreadDetails details;
      thread_basic_info_data_t info;
      mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
      gum_thread_state_t state;
      mach_msg_type_number_t state_count = GUM_THREAD_STATE_COUNT;
      thread_state_flavor_t state_flavor = GUM_THREAD_STATE_FLAVOR;

      kr = thread_info (thread, THREAD_BASIC_INFO, (thread_info_t) &info,
          &info_count);
      if (kr != KERN_SUCCESS)
        continue;

      kr = thread_get_state (thread, state_flavor, (thread_state_t) &state,
          &state_count);
      if (kr != KERN_SUCCESS)
        continue;

      details.id = (GumThreadId) thread;
      details.state = gum_thread_state_from_darwin (info.run_state);
      gum_cpu_context_from_darwin (&state, &details.cpu_context);

      if (!func (&details, user_data))
        break;
    }

    for (i = 0; i != count; i++)
      mach_port_deallocate (task, threads[i]);
    vm_deallocate (task, (vm_address_t) threads, count * sizeof (thread_t));
  }
}

void
gum_darwin_enumerate_modules (mach_port_t task,
                              GumFoundModuleFunc func,
                              gpointer user_data)
{
  struct task_dyld_info info;
  mach_msg_type_number_t count;
  kern_return_t kr;
  gsize info_array_count, info_array_size, i;
  GumAddress info_array_address;
  gpointer info_array = NULL;
  gpointer header_data = NULL;
  gchar * file_path = NULL;
  gboolean carry_on = TRUE;

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  DyldInfo info_raw;
  count = DYLD_INFO_COUNT;
  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info_raw, &count);
  if (kr != KERN_SUCCESS)
    goto beach;
  switch (count)
  {
    case DYLD_INFO_LEGACY_COUNT:
      info.all_image_info_addr = info_raw.info_legacy.all_image_info_addr;
      info.all_image_info_size = 0;
      info.all_image_info_format = TASK_DYLD_ALL_IMAGE_INFO_32;
      break;
    case DYLD_INFO_32_COUNT:
      info.all_image_info_addr = info_raw.info_32.all_image_info_addr;
      info.all_image_info_size = info_raw.info_32.all_image_info_size;
      info.all_image_info_format = info_raw.info_32.all_image_info_format;
      break;
    case DYLD_INFO_64_COUNT:
      info.all_image_info_addr = info_raw.info_64.all_image_info_addr;
      info.all_image_info_size = info_raw.info_64.all_image_info_size;
      info.all_image_info_format = info_raw.info_64.all_image_info_format;
      break;
    default:
      g_assert_not_reached ();
  }
#else
  count = TASK_DYLD_INFO_COUNT;
  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info, &count);
  if (kr != KERN_SUCCESS)
    goto beach;
#endif

  if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64)
  {
    DyldAllImageInfos64 * all_info;

    all_info = (DyldAllImageInfos64 *) gum_darwin_read (task,
        info.all_image_info_addr,
        sizeof (DyldAllImageInfos64),
        NULL);
    if (all_info == NULL)
      goto beach;
    info_array_count = all_info->info_array_count;
    info_array_size = info_array_count * DYLD_IMAGE_INFO_64_SIZE;
    info_array_address = all_info->info_array;
    g_free (all_info);
  }
  else
  {
    DyldAllImageInfos32 * all_info;

    all_info = (DyldAllImageInfos32 *) gum_darwin_read (task,
        info.all_image_info_addr,
        sizeof (DyldAllImageInfos32),
        NULL);
    if (all_info == NULL)
      goto beach;
    info_array_count = all_info->info_array_count;
    info_array_size = info_array_count * DYLD_IMAGE_INFO_32_SIZE;
    info_array_address = all_info->info_array;
    g_free (all_info);
  }

  if (info_array_address == 0)
    goto fallback;

  info_array =
      gum_darwin_read (task, info_array_address, info_array_size, NULL);

  for (i = 0; i != info_array_count && carry_on; i++)
  {
    GumAddress load_address, file_path_address;
    struct mach_header * header;
    guint8 * first_command, * p;
    guint cmd_index;
    GumMemoryRange dylib_range;
    gchar * name;
    GumModuleDetails details;

    if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64)
    {
      DyldImageInfo64 * info = info_array + (i * DYLD_IMAGE_INFO_64_SIZE);
      load_address = info->image_load_address;
      file_path_address = info->image_file_path;
    }
    else
    {
      DyldImageInfo32 * info = info_array + (i * DYLD_IMAGE_INFO_32_SIZE);
      load_address = info->image_load_address;
      file_path_address = info->image_file_path;
    }

    header_data = gum_darwin_read (task,
        load_address,
        MAX_MACH_HEADER_SIZE,
        NULL);
    file_path = (gchar *) gum_darwin_read (task,
        file_path_address,
        2 * MAXPATHLEN,
        NULL);
    if (header_data == NULL || file_path == NULL)
      goto beach;

    header = (struct mach_header *) header_data;
    if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64)
      first_command = header_data + sizeof (struct mach_header_64);
    else
      first_command = header_data + sizeof (struct mach_header);

    dylib_range.base_address = load_address;
    dylib_range.size = 4096;

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == GUM_LC_SEGMENT)
      {
        gum_segment_command_t * sc = (gum_segment_command_t *) lc;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }

      p += lc->cmdsize;
    }

    name = g_path_get_basename (file_path);

    details.name = name;
    details.range = &dylib_range;
    details.path = file_path;

    carry_on = func (&details, user_data);

    g_free (name);

    g_free (file_path);
    file_path = NULL;
    g_free (header_data);
    header_data = NULL;
  }

  goto beach;

fallback:
  gum_darwin_enumerate_modules_slow (task, func, user_data);

beach:
  g_free (file_path);
  g_free (header_data);
  g_free (info_array);

  return;
}

static void
gum_darwin_enumerate_modules_slow (mach_port_t task,
                                   GumFoundModuleFunc func,
                                   gpointer user_data)
{
  GumEnumerateModulesSlowContext ctx;
  guint i;

  ctx.task = task;
  ctx.func = func;
  ctx.user_data = user_data;

  ctx.ranges = g_array_sized_new (FALSE, FALSE, sizeof (GumMemoryRange), 64);
  ctx.alignment = 4096;

  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX,
      gum_store_range_of_potential_modules, &ctx);

  for (i = 0; i != ctx.ranges->len; i++)
  {
    GumMemoryRange * r = &g_array_index (ctx.ranges, GumMemoryRange, i);
    if (!gum_emit_modules_in_range (r, &ctx))
      break;
  }

  g_array_unref (ctx.ranges);
}

static gboolean
gum_store_range_of_potential_modules (const GumRangeDetails * details,
                                      gpointer user_data)
{
  GumEnumerateModulesSlowContext * ctx = user_data;

  g_array_append_val (ctx->ranges, *(details->range));

  return TRUE;
}

static gboolean
gum_emit_modules_in_range (const GumMemoryRange * range,
                           GumEnumerateModulesSlowContext * ctx)
{
  GumAddress address = range->base_address;
  gsize remaining = range->size;
  gboolean carry_on = TRUE;

  do
  {
    struct mach_header * header;
    gboolean is_dylib;
    guint8 * chunk;
    gsize chunk_size;
    guint8 * first_command, * p;
    guint cmd_index;
    GumMemoryRange dylib_range;

    header = (struct mach_header *) gum_darwin_read (ctx->task,
        address, sizeof (struct mach_header), NULL);
    if (header == NULL)
      return TRUE;
    is_dylib = (header->magic == MH_MAGIC || header->magic == MH_MAGIC_64) &&
        header->filetype == MH_DYLIB;
    g_free (header);

    if (!is_dylib)
    {
      address += ctx->alignment;
      remaining -= ctx->alignment;
      continue;
    }

    chunk = gum_darwin_read (ctx->task,
        address, MIN (MAX_MACH_HEADER_SIZE, remaining), &chunk_size);
    if (chunk == NULL)
      return TRUE;

    header = (struct mach_header *) chunk;
    if (header->magic == MH_MAGIC)
      first_command = chunk + sizeof (struct mach_header);
    else
      first_command = chunk + sizeof (struct mach_header_64);

    dylib_range.base_address = address;
    dylib_range.size = ctx->alignment;

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == GUM_LC_SEGMENT)
      {
        gum_segment_command_t * sc = (gum_segment_command_t *) lc;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }

      p += lc->cmdsize;
    }

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == LC_ID_DYLIB)
      {
        const struct dylib * dl = &((struct dylib_command *) lc)->dylib;
        const gchar * raw_path;
        guint raw_path_len;
        gchar * path, * name;
        GumModuleDetails details;

        raw_path = (gchar *) p + dl->name.offset;
        raw_path_len = lc->cmdsize - sizeof (struct dylib_command);
        path = g_malloc (raw_path_len + 1);
        memcpy (path, raw_path, raw_path_len);
        path[raw_path_len] = '\0';
        name = g_path_get_basename (path);

        details.name = name;
        details.range = &dylib_range;
        details.path = path;

        carry_on = ctx->func (&details, ctx->user_data);

        g_free (name);
        g_free (path);

        break;
      }

      p += lc->cmdsize;
    }

    g_free (chunk);

    address += dylib_range.size;
    remaining -= dylib_range.size;

    if (!carry_on)
      break;
  }
  while (remaining != 0);

  return carry_on;
}

void
gum_darwin_enumerate_ranges (mach_port_t task,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  int pid;
  kern_return_t kr;
  mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
  mach_vm_size_t size = (mach_vm_size_t) 0;
  natural_t depth = 0;

  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return;

  while (TRUE)
  {
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count;
    GumPageProtection cur_prot;

    while (TRUE)
    {
      info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
      kr = mach_vm_region_recurse (task, &address, &size, &depth,
          (vm_region_recurse_info_t) &info, &info_count);
      if (kr != KERN_SUCCESS)
        break;

      if (info.is_submap)
      {
        depth++;
        continue;
      }
      else
      {
        break;
      }
    }

    if (kr != KERN_SUCCESS)
      break;

    cur_prot = gum_page_protection_from_mach (info.protection);

    if ((cur_prot & prot) == prot)
    {
      GumMemoryRange range;
      GumRangeDetails details;
      GumFileMapping file;
      gchar file_path[MAXPATHLEN];
      gint len;

      range.base_address = address;
      range.size = size;

      details.range = &range;
      details.prot = cur_prot;
      details.file = NULL;

      len = proc_regionfilename (pid, address, file_path, sizeof (file_path));
      file_path[len] = '\0';
      if (len != 0)
      {
        file.path = file_path;
        file.offset = 0; /* TODO */

        details.file = &file;
      }

      if (!func (&details, user_data))
        return;
    }

    address += size;
    size = 0;
  }
}

void
gum_darwin_enumerate_exports (mach_port_t task,
                              const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumEnumerateExportsContext ctx;

  ctx.task = task;
  ctx.modules = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) g_variant_unref);
  ctx.strings = g_hash_table_new_full (NULL, NULL,
      NULL, (GDestroyNotify) g_free);
  ctx.module_name = module_name;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_darwin_enumerate_modules (task, gum_store_module_address, &ctx);

  gum_do_enumerate_exports (&ctx, module_name);

  g_hash_table_unref (ctx.strings);
  g_hash_table_unref (ctx.modules);
}

static gboolean
gum_store_module_address (const GumModuleDetails * details,
                          gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  GVariant * value;

  value = g_variant_new_uint64 (details->range->base_address);
  g_hash_table_insert (ctx->modules, g_strdup (details->name),
      g_variant_ref (value));
  g_hash_table_insert (ctx->modules, g_strdup (details->path),
      g_variant_ref (value));
  g_variant_unref (value);

  return TRUE;
}

static gboolean
gum_do_enumerate_exports (GumEnumerateExportsContext * ctx,
                          const gchar * module_name)
{
  gboolean carry_on = TRUE;
  GVariant * address_value;
  GumAddress address;
  guint8 * chunk = NULL;
  gsize chunk_size;
  struct mach_header * header;
  gint64 slide;
  GumAddress linkedit;
  GSList * text_section_ids = NULL;
  struct symtab_command * sc;
  gsize symbol_size;
  guint8 * symbols = NULL;
  GumAddress strings_address;
  gchar * strings;
  guint8 * cur_sym;
  guint symbol_index;

  address_value = g_hash_table_lookup (ctx->modules, module_name);
  if (address_value == NULL)
    goto beach;

  address = g_variant_get_uint64 (address_value);
  if (address == 0)
    goto beach;

  chunk = gum_darwin_read (ctx->task, address, MAX_MACH_HEADER_SIZE,
      &chunk_size);
  if (chunk == NULL)
    goto beach;
  header = (struct mach_header *) chunk;

  if (!gum_darwin_find_slide (address, chunk, chunk_size, &slide))
    goto beach;

  if (!gum_darwin_find_linkedit (chunk, chunk_size, &linkedit))
    goto beach;
  linkedit += slide;

  text_section_ids = gum_darwin_find_text_section_ids (chunk, chunk_size);

  if (!gum_darwin_find_command (LC_SYMTAB, chunk, chunk_size, (gpointer *) &sc))
    goto beach;

  if (header->magic == MH_MAGIC)
    symbol_size = sizeof (struct nlist);
  else
    symbol_size = sizeof (struct nlist_64);
  symbols = gum_darwin_read (ctx->task, linkedit + sc->symoff,
      sc->nsyms * symbol_size, NULL);
  if (symbols == NULL)
    goto beach;

  strings_address = linkedit + sc->stroff;
  strings = g_hash_table_lookup (ctx->strings,
      GSIZE_TO_POINTER (strings_address));
  if (strings == NULL)
  {
    strings = (gchar *) gum_darwin_read (ctx->task,
        strings_address, sc->strsize, NULL);
    if (strings == NULL)
      goto beach;
    g_hash_table_insert (ctx->strings, GSIZE_TO_POINTER (strings_address),
        strings);
  }

  cur_sym = symbols;
  for (symbol_index = 0; symbol_index != sc->nsyms; symbol_index++)
  {
    GumExportDetails details;

    details.name = NULL;

    if (header->magic == MH_MAGIC)
    {
      struct nlist * sym = (struct nlist *) cur_sym;
      if (!SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL (sym))
      {
        details.type = g_slist_find (text_section_ids,
            GSIZE_TO_POINTER (sym->n_sect)) != NULL
            ? GUM_EXPORT_FUNCTION : GUM_EXPORT_VARIABLE;
        details.name = gum_symbol_name_from_darwin (strings + sym->n_un.n_strx);
        details.address = sym->n_value + slide;
        if ((sym->n_desc & N_ARM_THUMB_DEF) != 0)
          details.address++;
      }
    }
    else
    {
      struct nlist_64 * sym = (struct nlist_64 *) cur_sym;
      if (!SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL (sym))
      {
        details.type = g_slist_find (text_section_ids,
            GSIZE_TO_POINTER (sym->n_sect)) != NULL
            ? GUM_EXPORT_FUNCTION : GUM_EXPORT_VARIABLE;
        details.name = gum_symbol_name_from_darwin (strings + sym->n_un.n_strx);
        details.address = sym->n_value + slide;
        if ((sym->n_desc & N_ARM_THUMB_DEF) != 0)
          details.address++;
      }
    }

    if (details.name != NULL)
    {
      if (!ctx->func (&details, ctx->user_data))
      {
        carry_on = FALSE;
        break;
      }
    }

    cur_sym += symbol_size;
  }

  if (carry_on)
  {
    guint8 * cur_cmd;
    guint cmd_index;

    if (header->magic == MH_MAGIC)
      cur_cmd = chunk + sizeof (struct mach_header);
    else
      cur_cmd = chunk + sizeof (struct mach_header_64);
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      struct load_command * lc = (struct load_command *) cur_cmd;

      if (lc->cmd == LC_REEXPORT_DYLIB)
      {
        struct dylib_command * dc = (struct dylib_command *) lc;
        const char * name = (const char *)
            (((guint8 *) dc) + dc->dylib.name.offset);
        if (!gum_do_enumerate_exports (ctx, name))
        {
          carry_on = FALSE;
          break;
        }
      }

      cur_cmd += lc->cmdsize;
    }
  }

beach:
  g_free (symbols);
  g_slist_free (text_section_ids);
  g_free (chunk);

  return carry_on;
}

gboolean
gum_darwin_find_slide (GumAddress module_address,
                       const guint8 * module,
                       gsize module_size,
                       gint64 * slide)
{
  struct mach_header * header;
  const guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      struct segment_command * sc = (struct segment_command *) lc;
      struct segment_command_64 * sc64 = (struct segment_command_64 *) lc;
      if (strcmp (sc->segname, "__TEXT") == 0)
      {
        if (header->magic == MH_MAGIC)
          *slide = module_address - sc->vmaddr;
        else
          *slide = module_address - sc64->vmaddr;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

gboolean
gum_darwin_find_linkedit (const guint8 * module,
                          gsize module_size,
                          GumAddress * linkedit)
{
  struct mach_header * header;
  const guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      struct segment_command * sc = (struct segment_command *) lc;
      struct segment_command_64 * sc64 = (struct segment_command_64 *) lc;
      if (strcmp (sc->segname, "__LINKEDIT") == 0)
      {
        if (header->magic == MH_MAGIC)
          *linkedit = sc->vmaddr - sc->fileoff;
        else
          *linkedit = sc64->vmaddr - sc64->fileoff;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static GSList *
gum_darwin_find_text_section_ids (guint8 * module,
                                  gsize module_size)
{
  GSList * ids = NULL;
  gsize section_count = 0;
  struct mach_header * header;
  guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      vm_prot_t initprot;
      gsize nsects, section_index;

      if (header->magic == MH_MAGIC)
      {
        struct segment_command * sc = (struct segment_command *) lc;
        initprot = sc->initprot;
        nsects = sc->nsects;
      }
      else
      {
        struct segment_command_64 * sc = (struct segment_command_64 *) lc;
        initprot = sc->initprot;
        nsects = sc->nsects;
      }

      if ((initprot & VM_PROT_EXECUTE) != 0)
      {
        for (section_index = 0; section_index != nsects; section_index++)
        {
          ids = g_slist_prepend (ids,
              GSIZE_TO_POINTER (section_count + section_index + 1));
        }
      }

      section_count += nsects;
    }

    p += lc->cmdsize;
  }

  return g_slist_reverse (ids);
}

gboolean
gum_darwin_find_command (guint id,
                         const guint8 * module,
                         gsize module_size,
                         gpointer * command)
{
  struct mach_header * header;
  const guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == id)
    {
      *command = lc;
      return TRUE;
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
find_image_address_and_slide (const gchar * image_name,
                              gpointer * address,
                              gpointer * slide)
{
  guint count, i;

  count = _dyld_image_count ();

  for (i = 0; i != count; i++)
  {
    if (gum_module_path_equals (_dyld_get_image_name (i), image_name))
    {
      *address = (gpointer) _dyld_get_image_header (i);
      *slide = (gpointer) _dyld_get_image_vmaddr_slide (i);
      return TRUE;
    }
  }

  return FALSE;
}

static gboolean
find_image_vmaddr_and_fileoff (gconstpointer address,
                               gsize * vmaddr,
                               gsize * fileoff)
{
  const gum_mach_header_t * header = address;
  guint8 * p;
  guint cmd_index;

  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == GUM_LC_SEGMENT)
    {
      gum_segment_command_t * segcmd = (gum_segment_command_t *) lc;

      if (strcmp (segcmd->segname, "__LINKEDIT") == 0)
      {
        *vmaddr = segcmd->vmaddr;
        *fileoff = segcmd->fileoff;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gsize
find_image_size (const gchar * image_name)
{
  gpointer image_address, image_slide;
  const gum_mach_header_t * header;
  guint8 * p;
  guint cmd_index;

  if (!find_image_address_and_slide (image_name, &image_address, &image_slide))
    return 0;

  header = (const gum_mach_header_t *) image_address;
  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    gum_segment_command_t * sc = (gum_segment_command_t *) p;

    if (sc->cmd == GUM_LC_SEGMENT)
    {
      gpointer segment_address = sc->vmaddr + image_slide;
      if (segment_address == image_address)
        return sc->vmsize;
    }

    p += sc->cmdsize;
  }

  return 0;
}

static GSList *
find_image_text_section_ids (gconstpointer address)
{
  GSList * ids = NULL;
  gsize section_count = 0;
  const gum_mach_header_t * header = address;
  guint8 * p;
  guint cmd_index, section_index;

  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == GUM_LC_SEGMENT)
    {
      gum_segment_command_t * segcmd = (gum_segment_command_t *) lc;

      if ((segcmd->initprot & VM_PROT_EXECUTE) != 0)
      {
        for (section_index = 0; section_index != segcmd->nsects; section_index++)
        {
          ids = g_slist_prepend (ids,
              GSIZE_TO_POINTER (section_count + section_index + 1));
        }
      }

      section_count += segcmd->nsects;
    }

    p += lc->cmdsize;
  }

  return g_slist_reverse (ids);
}

static gboolean
find_image_symtab_command (gconstpointer address,
                           const struct symtab_command ** sc)
{
  const gum_mach_header_t * header = address;
  guint8 * p;
  guint cmd_index;

  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SYMTAB)
    {
      *sc = (struct symtab_command *) lc;
      return TRUE;
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
gum_module_path_equals (const gchar * path,
                        const gchar * name_or_path)
{
  gchar * s;

  if (name_or_path[0] == '/')
    return strcmp (name_or_path, path) == 0;

  if ((s = strrchr (path, '/')) != NULL)
    return strcmp (name_or_path, s + 1) == 0;

  return strcmp (name_or_path, path) == 0;
}

static GumThreadState
gum_thread_state_from_darwin (integer_t run_state)
{
  switch (run_state)
  {
    case TH_STATE_RUNNING: return GUM_THREAD_RUNNING;
    case TH_STATE_STOPPED: return GUM_THREAD_STOPPED;
    case TH_STATE_WAITING: return GUM_THREAD_WAITING;
    case TH_STATE_UNINTERRUPTIBLE: return GUM_THREAD_UNINTERRUPTIBLE;
    case TH_STATE_HALTED: return GUM_THREAD_HALTED;
    default:
      g_assert_not_reached ();
      break;
  }
}

static void
gum_cpu_context_from_darwin (const gum_thread_state_t * state,
                             GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  const x86_thread_state32_t * ts = &state->uts.ts32;

  ctx->eip = ts->__eip;

  ctx->edi = ts->__edi;
  ctx->esi = ts->__esi;
  ctx->ebp = ts->__ebp;
  ctx->esp = ts->__esp;
  ctx->ebx = ts->__ebx;
  ctx->edx = ts->__edx;
  ctx->ecx = ts->__ecx;
  ctx->eax = ts->__eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  const x86_thread_state64_t * ts = &state->uts.ts64;

  ctx->rip = ts->__rip;

  ctx->r15 = ts->__r15;
  ctx->r14 = ts->__r14;
  ctx->r13 = ts->__r13;
  ctx->r12 = ts->__r12;
  ctx->r11 = ts->__r11;
  ctx->r10 = ts->__r10;
  ctx->r9 = ts->__r9;
  ctx->r8 = ts->__r8;

  ctx->rdi = ts->__rdi;
  ctx->rsi = ts->__rsi;
  ctx->rbp = ts->__rbp;
  ctx->rsp = ts->__rsp;
  ctx->rbx = ts->__rbx;
  ctx->rdx = ts->__rdx;
  ctx->rcx = ts->__rcx;
  ctx->rax = ts->__rax;
#elif defined (HAVE_ARM)
  const arm_thread_state32_t * ts = &state->ts_32;
  guint n;

  ctx->pc = ts->__pc;
  ctx->sp = ts->__sp;

  for (n = 0; n != G_N_ELEMENTS (ctx->r); n++)
    ctx->r[n] = ts->__r[n];
  ctx->lr = ts->__lr;
#elif defined (HAVE_ARM64)
  const arm_thread_state64_t * ts = &state->ts_64;
  guint n;

  ctx->pc = ts->__pc;
  ctx->sp = ts->__sp;

  for (n = 0; n != G_N_ELEMENTS (ctx->x); n++)
    ctx->x[n] = ts->__x[n];
  ctx->fp = ts->__fp;
  ctx->lr = ts->__lr;
#endif
}

static void
gum_cpu_context_to_darwin (const GumCpuContext * ctx,
                           gum_thread_state_t * state)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  x86_thread_state32_t * ts = &state->uts.ts32;

  ts->__eip = ctx->eip;

  ts->__edi = ctx->edi;
  ts->__esi = ctx->esi;
  ts->__ebp = ctx->ebp;
  ts->__esp = ctx->esp;
  ts->__ebx = ctx->ebx;
  ts->__edx = ctx->edx;
  ts->__ecx = ctx->ecx;
  ts->__eax = ctx->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  x86_thread_state64_t * ts = &state->uts.ts64;

  ts->__rip = ctx->rip;

  ts->__r15 = ctx->r15;
  ts->__r14 = ctx->r14;
  ts->__r13 = ctx->r13;
  ts->__r12 = ctx->r12;
  ts->__r11 = ctx->r11;
  ts->__r10 = ctx->r10;
  ts->__r9 = ctx->r9;
  ts->__r8 = ctx->r8;

  ts->__rdi = ctx->rdi;
  ts->__rsi = ctx->rsi;
  ts->__rbp = ctx->rbp;
  ts->__rsp = ctx->rsp;
  ts->__rbx = ctx->rbx;
  ts->__rdx = ctx->rdx;
  ts->__rcx = ctx->rcx;
  ts->__rax = ctx->rax;
#elif defined (HAVE_ARM)
  arm_thread_state32_t * ts = &state->ts_32;
  guint n;

  ts->__pc = ctx->pc;
  ts->__sp = ctx->sp;

  for (n = 0; n != G_N_ELEMENTS (ctx->r); n++)
    ts->__r[n] = ctx->r[n];
  ts->__lr = ctx->lr;
#elif defined (HAVE_ARM64)
  arm_thread_state64_t * ts = &state->ts_64;
  guint n;

  ts->__pc = ctx->pc;
  ts->__sp = ctx->sp;

  for (n = 0; n != G_N_ELEMENTS (ctx->x); n++)
    ts->__x[n] = ctx->x[n];
  ts->__fp = ctx->fp;
  ts->__lr = ctx->lr;
#endif
}

static const char *
gum_symbol_name_from_darwin (const char * s)
{
  return (s[0] == '_') ? s + 1 : s;
}
