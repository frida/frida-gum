/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2022 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2022 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2023 Alex Soler <asoler@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gum-init.h"
#include "gumdarwin.h"
#include "gumdarwinmodule.h"
#include "gumleb.h"
#include "gumprocess-darwin-priv.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define GUM_PSR_THUMB 0x20
#define MAX_MACH_HEADER_SIZE (64 * 1024)
#define DYLD_IMAGE_INFO_32_SIZE 12
#define DYLD_IMAGE_INFO_64_SIZE 24
#define GUM_THREAD_POLL_STEP 1000
#define GUM_MAX_THREAD_POLL (20000000 / GUM_THREAD_POLL_STEP)
#define GUM_PTHREAD_FIELD_STACKADDR ((GLIB_SIZEOF_VOID_P == 8) ? 0xb0 : 0x88)
#define GUM_PTHREAD_FIELD_FREEADDR ((GLIB_SIZEOF_VOID_P == 8) ? 0xc0 : 0x90)
#define GUM_PTHREAD_FIELD_FREESIZE ((GLIB_SIZEOF_VOID_P == 8) ? 0xc8 : 0x94)
#define GUM_PTHREAD_FIELD_GUARDSIZE ((GLIB_SIZEOF_VOID_P == 8) ? 0xd0 : 0x98)
#define GUM_PTHREAD_FIELD_THREADID ((GLIB_SIZEOF_VOID_P == 8) ? 0xd8 : 0xa0)
#define GUM_PTHREAD_GET_FIELD(thread, field, type) \
    (*((type *) ((guint8 *) thread + field)))

#if defined (HAVE_ARM64) && !defined (__DARWIN_OPAQUE_ARM_THREAD_STATE64)
# define __darwin_arm_thread_state64_get_pc_fptr(ts) \
    ((void *) (uintptr_t) ((ts).__pc))
# define __darwin_arm_thread_state64_set_pc_fptr(ts, fptr) \
    ((ts).__pc = (uintptr_t) (fptr))
# define __darwin_arm_thread_state64_get_lr_fptr(ts) \
    ((void *) (uintptr_t) ((ts).__lr))
# define __darwin_arm_thread_state64_set_lr_fptr(ts, fptr) \
    ((ts).__lr = (uintptr_t) (fptr))
# define __darwin_arm_thread_state64_get_sp(ts) \
    ((ts).__sp)
# define __darwin_arm_thread_state64_set_sp(ts, ptr) \
    ((ts).__sp = (uintptr_t) (ptr))
# define __darwin_arm_thread_state64_get_fp(ts) \
    ((ts).__fp)
# define __darwin_arm_thread_state64_set_fp(ts, ptr) \
    ((ts).__fp = (uintptr_t) (ptr))
#endif

typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumEnumerateExportsContext GumEnumerateExportsContext;
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumFindEntrypointContext GumFindEntrypointContext;
typedef struct _GumEnumerateModulesSlowContext GumEnumerateModulesSlowContext;
typedef struct _GumEnumerateMallocRangesContext GumEnumerateMallocRangesContext;
typedef struct _GumCanonicalizeNameContext GumCanonicalizeNameContext;

typedef struct _DyldAllImageInfos32 DyldAllImageInfos32;
typedef struct _DyldAllImageInfos64 DyldAllImageInfos64;
typedef struct _DyldImageInfo32 DyldImageInfo32;
typedef struct _DyldImageInfo64 DyldImageInfo64;

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GumDarwinModuleResolver * resolver;
  GumModuleMap * module_map;
};

struct _GumEnumerateExportsContext
{
  GumFoundExportFunc func;
  gpointer user_data;

  GumDarwinModuleResolver * resolver;
  GumDarwinModule * module;
  gboolean carry_on;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundSymbolFunc func;
  gpointer user_data;

  GArray * sections;
};

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

struct _GumEnumerateMallocRangesContext
{
  GumFoundMallocRangeFunc func;
  gpointer user_data;
  gboolean carry_on;
};

struct _GumCanonicalizeNameContext
{
  const gchar * module_name;
  gchar * module_path;
};

struct _DyldAllImageInfos32
{
  guint32 version;
  guint32 info_array_count;
  guint32 info_array;
  guint32 notification;
  guint8 process_detached_from_shared_region;
  guint8 libsystem_initialized;
  guint32 dyld_image_load_address;
  guint32 jit_info;
  guint32 dyld_version;
  guint32 error_message;
  guint32 termination_flags;
  guint32 core_symbolication_shm_page;
  guint32 system_order_flag;
  guint32 uuid_array_count;
  guint32 uuid_array;
  guint32 dyld_all_image_infos_address;
  guint32 initial_image_count;
  guint32 error_kind;
  guint32 error_client_of_dylib_path;
  guint32 error_target_dylib_path;
  guint32 error_symbol;
  guint32 shared_cache_slide;
  guint8 shared_cache_uuid[16];
  guint32 shared_cache_base_address;
  volatile guint64 info_array_change_timestamp;
  guint32 dyld_path;
  guint32 notify_mach_ports[8];
  guint32 reserved[5];
  guint32 compact_dyld_image_info_addr;
  guint32 compact_dyld_image_info_size;
  guint32 platform;
};

struct _DyldAllImageInfos64
{
  guint32 version;
  guint32 info_array_count;
  guint64 info_array;
  guint64 notification;
  guint8 process_detached_from_shared_region;
  guint8 libsystem_initialized;
  guint32 padding;
  guint64 dyld_image_load_address;
  guint64 jit_info;
  guint64 dyld_version;
  guint64 error_message;
  guint64 termination_flags;
  guint64 core_symbolication_shm_page;
  guint64 system_order_flag;
  guint64 uuid_array_count;
  guint64 uuid_array;
  guint64 dyld_all_image_infos_address;
  guint64 initial_image_count;
  guint64 error_kind;
  guint64 error_client_of_dylib_path;
  guint64 error_target_dylib_path;
  guint64 error_symbol;
  guint64 shared_cache_slide;
  guint8 shared_cache_uuid[16];
  guint64 shared_cache_base_address;
  volatile guint64 info_array_change_timestamp;
  guint64 dyld_path;
  guint32 notify_mach_ports[8];
  guint64 reserved[9];
  guint64 compact_dyld_image_info_addr;
  guint64 compact_dyld_image_info_size;
  guint32 platform;
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

#ifndef PROC_PIDREGIONPATHINFO2
# define PROC_PIDREGIONPATHINFO2 22
#endif

#ifndef PROC_INFO_CALL_PIDINFO

# define PROC_INFO_CALL_PIDINFO 0x2
# define PROC_PIDREGIONINFO     7
# define PROC_PIDREGIONPATHINFO 8

struct vinfo_stat
{
  uint32_t vst_dev;
  uint16_t vst_mode;
  uint16_t vst_nlink;
  uint64_t vst_ino;
  uid_t vst_uid;
  gid_t vst_gid;
  int64_t vst_atime;
  int64_t vst_atimensec;
  int64_t vst_mtime;
  int64_t vst_mtimensec;
  int64_t vst_ctime;
  int64_t vst_ctimensec;
  int64_t vst_birthtime;
  int64_t vst_birthtimensec;
  off_t vst_size;
  int64_t vst_blocks;
  int32_t vst_blksize;
  uint32_t vst_flags;
  uint32_t vst_gen;
  uint32_t vst_rdev;
  int64_t vst_qspare[2];
};

struct vnode_info
{
  struct vinfo_stat vi_stat;
  int vi_type;
  int vi_pad;
  fsid_t vi_fsid;
};

struct vnode_info_path
{
  struct vnode_info vip_vi;
  char vip_path[MAXPATHLEN];
};

struct proc_regioninfo
{
  uint32_t pri_protection;
  uint32_t pri_max_protection;
  uint32_t pri_inheritance;
  uint32_t pri_flags;
  uint64_t pri_offset;
  uint32_t pri_behavior;
  uint32_t pri_user_wired_count;
  uint32_t pri_user_tag;
  uint32_t pri_pages_resident;
  uint32_t pri_pages_shared_now_private;
  uint32_t pri_pages_swapped_out;
  uint32_t pri_pages_dirtied;
  uint32_t pri_ref_count;
  uint32_t pri_shadow_depth;
  uint32_t pri_share_mode;
  uint32_t pri_private_pages_resident;
  uint32_t pri_shared_pages_resident;
  uint32_t pri_obj_id;
  uint32_t pri_depth;
  uint64_t pri_address;
  uint64_t pri_size;
};

struct proc_regionwithpathinfo
{
  struct proc_regioninfo prp_prinfo;
  struct vnode_info_path prp_vip;
};

#endif

extern int __proc_info (int callnum, int pid, int flavor, uint64_t arg,
    void * buffer, int buffersize);

static void gum_emit_malloc_ranges (task_t task,
    void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t gum_read_malloc_memory (task_t remote_task,
    vm_address_t remote_address, vm_size_t size, void ** local_memory);
#ifdef HAVE_I386
static void gum_deinit_sysroot (void);
#endif
static gboolean gum_probe_range_for_entrypoint (const GumRangeDetails * details,
    gpointer user_data);
static gboolean gum_store_range_of_potential_modules (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_emit_modules_in_range (const GumMemoryRange * range,
    GumEnumerateModulesSlowContext * ctx);
static gboolean gum_emit_import (const GumImportDetails * details,
    gpointer user_data);
static GumAddress gum_resolve_export (const char * module_name,
    const char * symbol_name, gpointer user_data);
static gboolean gum_emit_export (const GumDarwinExportDetails * details,
    gpointer user_data);
static gboolean gum_emit_symbol (const GumDarwinSymbolDetails * details,
    gpointer user_data);
static gboolean gum_append_symbol_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
static void gum_symbol_section_destroy (GumSymbolSection * self);

static gboolean find_image_address_and_slide (const gchar * image_name,
    gpointer * address, gpointer * slide);

static gchar * gum_canonicalize_module_name (const gchar * name);
static gboolean gum_store_module_path_if_module_name_matches (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);

static GumThreadState gum_thread_state_from_darwin (integer_t run_state);

static gboolean gum_darwin_fill_file_mapping (gint pid,
    mach_vm_address_t address, GumFileMapping * file,
    struct proc_regionwithpathinfo * region);
static void gum_darwin_clamp_range_size (GumMemoryRange * range,
    const GumFileMapping * file);

const gchar *
gum_process_query_libc_name (void)
{
  return "/usr/lib/libSystem.B.dylib";
}

gboolean
gum_process_is_debugger_attached (void)
{
  int mib[4];
  struct kinfo_proc info;
  size_t size;
  G_GNUC_UNUSED int result;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = getpid ();

  size = sizeof (info);
  result = sysctl (mib, G_N_ELEMENTS (mib), &info, &size, NULL, 0);
  g_assert (result == 0);

  return (info.kp_proc.p_flag & P_TRACED) != 0;
}

GumProcessId
gum_process_get_id (void)
{
  return getpid ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return pthread_mach_thread_np (pthread_self ());
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  gboolean found = FALSE;
  mach_port_t task;
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  kern_return_t kr;
  guint i;

  /*
   * We won't see the same Mach port name as the one that libpthread has,
   * so we need to special-case it. This also doubles as an optimization.
   */
  if (thread_id == gum_process_get_current_thread_id ())
    return TRUE;

  task = mach_task_self ();

  kr = task_threads (task, &threads, &count);
  if (kr != KERN_SUCCESS)
    goto beach;

  for (i = 0; i != count; i++)
  {
    if (threads[i] == thread_id)
    {
      found = TRUE;
      break;
    }
  }

  for (i = 0; i != count; i++)
    mach_port_deallocate (task, threads[i]);
  vm_deallocate (task, (vm_address_t) threads, count * sizeof (thread_t));

beach:
  return found;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  return gum_darwin_modify_thread (thread_id, func, user_data);
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  gum_darwin_enumerate_threads (mach_task_self (), func, user_data);
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  gum_darwin_enumerate_modules (mach_task_self (), func, user_data);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
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

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  pthread_t thread;
  uint64_t thread_id, real_thread_id;
  guint skew;
  GumMemoryRange * range;
  GumAddress stack_addr;
  size_t guard_size, stack_size;
  GumAddress stack_base;

  range = &ranges[0];

  thread = pthread_self ();

  thread_id = GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_THREADID, uint64_t);
  pthread_threadid_np (thread, &real_thread_id);

  skew = (thread_id == real_thread_id) ? 0 : 8;

  range->base_address = GUM_ADDRESS (GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_FREEADDR + skew, void *));
  range->size = GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_FREESIZE + skew, size_t);

  if (max_length == 1)
    return 1;

  stack_addr = GUM_ADDRESS (GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_STACKADDR + skew, void *));
  stack_size = pthread_get_stacksize_np (thread);
  guard_size = GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_GUARDSIZE + skew, size_t);

  stack_base = stack_addr - stack_size - guard_size;

  if (stack_base == range->base_address)
    return 1;

  range = &ranges[1];

  range->base_address = stack_base;
  range->size = stack_addr - stack_base;

  return 2;
}

gint
gum_thread_get_system_error (void)
{
  return errno;
}

void
gum_thread_set_system_error (gint value)
{
  errno = value;
}

gboolean
gum_thread_suspend (GumThreadId thread_id,
                    GError ** error)
{
#ifdef HAVE_WATCHOS
  g_set_error (error,
      GUM_ERROR,
      GUM_ERROR_NOT_SUPPORTED,
      "Not supported");
  return FALSE;
#else
  kern_return_t kr;

  kr = thread_suspend (thread_id);
  if (kr != KERN_SUCCESS)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_NOT_FOUND,
        "%s",
        mach_error_string (kr));
    return FALSE;
  }
#endif
}

gboolean
gum_thread_resume (GumThreadId thread_id,
                   GError ** error)
{
#ifdef HAVE_WATCHOS
  g_set_error (error,
      GUM_ERROR,
      GUM_ERROR_NOT_SUPPORTED,
      "Not supported");
  return FALSE;
#else
  kern_return_t kr;

  kr = thread_resume (thread_id);
  if (kr != KERN_SUCCESS)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_NOT_FOUND,
        "%s",
        mach_error_string (kr));
    return FALSE;
  }
#endif
}

gboolean
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  if (dlopen (module_name, RTLD_LAZY) == NULL)
    goto not_found;

  return TRUE;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  gboolean success;
  gchar * name;
  void * module;

  success = FALSE;

  name = gum_canonicalize_module_name (module_name);
  if (name == NULL)
    goto beach;

  module = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);
  if (module == NULL)
    goto beach;
  dlclose (module);

  module = dlopen (name, RTLD_LAZY);
  if (module == NULL)
    goto beach;
  dlclose (module);

  success = TRUE;

beach:
  g_free (name);

  return success;
}

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  return gum_darwin_enumerate_imports (mach_task_self (), module_name, func,
      user_data);
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  return gum_darwin_enumerate_exports (mach_task_self (), module_name, func,
      user_data);
}

void
gum_module_enumerate_symbols (const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  return gum_darwin_enumerate_symbols (mach_task_self (), module_name, func,
      user_data);
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  gpointer address, slide;
  gint pid;
  gum_mach_header_t * header;
  guint8 * p;
  guint cmd_index;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return;

  pid = getpid ();

  header = address;
  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == GUM_LC_SEGMENT)
    {
      gum_segment_command_t * segcmd = (gum_segment_command_t *) lc;
      gboolean is_page_zero;
      GumPageProtection cur_prot;

      is_page_zero = segcmd->vmaddr == 0 &&
          segcmd->filesize == 0 &&
          segcmd->vmsize != 0 &&
          (segcmd->initprot & VM_PROT_ALL) == VM_PROT_NONE &&
          (segcmd->maxprot & VM_PROT_ALL) == VM_PROT_NONE;
      if (is_page_zero)
      {
        p += lc->cmdsize;
        continue;
      }

      cur_prot = gum_page_protection_from_mach (segcmd->initprot);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;
        GumFileMapping file;
        struct proc_regionwithpathinfo region;

        range.base_address = GUM_ADDRESS (
            GSIZE_TO_POINTER (segcmd->vmaddr) + GPOINTER_TO_SIZE (slide));
        range.size = segcmd->vmsize;

        details.range = &range;
        details.protection = cur_prot;
        details.file = NULL;

        if (pid != 0 && gum_darwin_fill_file_mapping (pid, range.base_address,
            &file, &region))
        {
          details.file = &file;
          gum_darwin_clamp_range_size (&range, &file);
        }

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
  GumAddress result;
  void * module;

  if (module_name != NULL)
  {
    gchar * name;

    name = gum_canonicalize_module_name (module_name);
    if (name == NULL)
      return 0;

#ifndef GUM_DIET
    if (g_str_has_prefix (name, "/usr/lib/dyld"))
    {
      GumDarwinModuleResolver * resolver;
      GumDarwinModule * dm;

      resolver = gum_darwin_module_resolver_new (mach_task_self (), NULL);
      g_assert (resolver != NULL);

      dm = gum_darwin_module_resolver_find_module (resolver, name);
      if (dm != NULL)
      {
        result = gum_darwin_module_resolver_find_export_address (resolver, dm,
            symbol_name);
      }
      else
      {
        result = 0;
      }

      g_object_unref (resolver);

      g_free (name);

      return result;
    }
#endif

    module = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);

    g_free (name);
  }
  else
  {
    module = RTLD_DEFAULT;
  }

  result = GUM_ADDRESS (dlsym (module, symbol_name));

  if (module != RTLD_DEFAULT)
    dlclose (module);

  return result;
}

gboolean
gum_darwin_check_xnu_version (guint major,
                              guint minor,
                              guint micro)
{
  static gboolean initialized = FALSE;
  static guint xnu_major = G_MAXUINT;
  static guint xnu_minor = G_MAXUINT;
  static guint xnu_micro = G_MAXUINT;

  if (!initialized)
  {
    char buf[256] = { 0, };
    size_t size;
    G_GNUC_UNUSED int res;
    const char * version_str;

    size = sizeof (buf);
    res = sysctlbyname ("kern.version", buf, &size, NULL, 0);
    g_assert (res == 0);

    version_str = strstr (buf, "xnu-");
    if (version_str != NULL)
    {
      version_str += 4;
      sscanf (version_str, "%u.%u.%u", &xnu_major, &xnu_minor, &xnu_micro);
    }

    initialized = TRUE;
  }

  if (xnu_major > major)
    return TRUE;

  if (xnu_major == major && xnu_minor > minor)
    return TRUE;

  return xnu_major == major && xnu_minor == minor && xnu_micro >= micro;
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

#ifdef HAVE_I386

const gchar *
gum_darwin_query_sysroot (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    gchar * result = NULL;
    const gchar * program_path;

    program_path = _dyld_get_image_name (0);

    if (g_str_has_suffix (program_path, "/usr/lib/dyld_sim"))
    {
      result = g_strndup (program_path, strlen (program_path) - 17);
      _gum_register_destructor (gum_deinit_sysroot);
    }

    g_once_init_leave (&cached_result, GPOINTER_TO_SIZE (result) + 1);
  }

  return GSIZE_TO_POINTER (cached_result - 1);
}

static void
gum_deinit_sysroot (void)
{
  g_free ((gchar *) gum_darwin_query_sysroot ());
}

#else

const gchar *
gum_darwin_query_sysroot (void)
{
  return NULL;
}

#endif

gboolean
gum_darwin_query_hardened (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    const gchar * program_path;
    guint i;
    gboolean is_hardened;

    for (program_path = NULL, i = 0; program_path == NULL; i++)
    {
      if (_dyld_get_image_header (i)->filetype == MH_EXECUTE)
        program_path = _dyld_get_image_name (i);
    }

    is_hardened = strcmp (program_path, "/sbin/launchd") == 0 ||
        g_str_has_prefix (program_path, "/usr/libexec/") ||
        g_str_has_prefix (program_path, "/System/") ||
        g_str_has_prefix (program_path, "/Developer/");

    g_once_init_leave (&cached_result, is_hardened + 1);
  }

  return cached_result - 1;
}

gboolean
gum_darwin_query_all_image_infos (mach_port_t task,
                                  GumDarwinAllImageInfos * infos)
{
  struct task_dyld_info info;
  mach_msg_type_number_t count;
  kern_return_t kr;
  gboolean inprocess;

  bzero (infos, sizeof (GumDarwinAllImageInfos));

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  DyldInfo info_raw;
  count = DYLD_INFO_COUNT;
  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info_raw, &count);
  if (kr != KERN_SUCCESS)
    return FALSE;
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
    return FALSE;
#endif

  infos->format = info.all_image_info_format;

  inprocess = task == mach_task_self ();

  if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64)
  {
    DyldAllImageInfos64 * all_info;
    gpointer all_info_malloc_data = NULL;

    if (inprocess)
    {
      all_info = (DyldAllImageInfos64 *) info.all_image_info_addr;
    }
    else
    {
      all_info = (DyldAllImageInfos64 *) gum_darwin_read (task,
          info.all_image_info_addr,
          sizeof (DyldAllImageInfos64),
          NULL);
      all_info_malloc_data = all_info;
    }
    if (all_info == NULL)
      return FALSE;

    infos->info_array_address = all_info->info_array;
    infos->info_array_count = all_info->info_array_count;
    infos->info_array_size =
        all_info->info_array_count * DYLD_IMAGE_INFO_64_SIZE;

    infos->notification_address = all_info->notification;

    infos->libsystem_initialized = all_info->libsystem_initialized;

    infos->dyld_image_load_address = all_info->dyld_image_load_address;

    if (all_info->version >= 15)
      infos->shared_cache_base_address = all_info->shared_cache_base_address;

    g_free (all_info_malloc_data);
  }
  else
  {
    DyldAllImageInfos32 * all_info;
    gpointer all_info_malloc_data = NULL;

    if (inprocess)
    {
      all_info = (DyldAllImageInfos32 *) info.all_image_info_addr;
    }
    else
    {
      all_info = (DyldAllImageInfos32 *) gum_darwin_read (task,
          info.all_image_info_addr,
          sizeof (DyldAllImageInfos32),
          NULL);
      all_info_malloc_data = all_info;
    }
    if (all_info == NULL)
      return FALSE;

    infos->info_array_address = all_info->info_array;
    infos->info_array_count = all_info->info_array_count;
    infos->info_array_size =
        all_info->info_array_count * DYLD_IMAGE_INFO_32_SIZE;

    infos->notification_address = all_info->notification;

    infos->libsystem_initialized = all_info->libsystem_initialized;

    infos->dyld_image_load_address = all_info->dyld_image_load_address;

    if (all_info->version >= 15)
      infos->shared_cache_base_address = all_info->shared_cache_base_address;

    g_free (all_info_malloc_data);
  }

  return TRUE;
}

gboolean
gum_darwin_query_mapped_address (mach_port_t task,
                                 GumAddress address,
                                 GumDarwinMappingDetails * details)
{
  int pid;
  kern_return_t kr;
  GumFileMapping file;
  struct proc_regionwithpathinfo region;
  guint64 mapping_offset;

  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return FALSE;

  if (!gum_darwin_fill_file_mapping (pid, address, &file, &region))
    return FALSE;

  g_strlcpy (details->path, file.path, sizeof (details->path));

  mapping_offset = address - region.prp_prinfo.pri_address;
  details->offset = mapping_offset;
  details->size = region.prp_prinfo.pri_size - mapping_offset;

  return TRUE;
}

gboolean
gum_darwin_query_protection (mach_port_t task,
                             GumAddress address,
                             GumPageProtection * prot)
{
  kern_return_t kr;
  gint pid, retval;
  struct proc_regioninfo region;

  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return FALSE;

  retval = __proc_info (PROC_INFO_CALL_PIDINFO, pid, PROC_PIDREGIONINFO,
      address, &region, sizeof (struct proc_regioninfo));
  if (retval == -1)
    return FALSE;

  *prot = gum_page_protection_from_mach (region.pri_protection);

  return TRUE;
}

gboolean
gum_darwin_query_shared_cache_range (mach_port_t task,
                                     GumMemoryRange * range)
{
  GumDarwinAllImageInfos infos;
  GumAddress start, end;
  mach_vm_address_t address;
  mach_vm_size_t size;
  natural_t depth;
  struct vm_region_submap_info_64 info;
  mach_msg_type_number_t info_count;
  kern_return_t kr;

  if (!gum_darwin_query_all_image_infos (task, &infos))
    return FALSE;

  start = infos.shared_cache_base_address;
  if (start == 0)
    return FALSE;

  address = start;
  depth = 0;
  info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

  kr = mach_vm_region_recurse (task, &address, &size, &depth,
      (vm_region_recurse_info_t) &info, &info_count);
  if (kr != KERN_SUCCESS)
    return FALSE;

  start = address;
  end = address + size;

  do
  {
    gboolean is_contiguous, is_dsc_tag;

    address += size;
    depth = 0;
    info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kr = mach_vm_region_recurse (task, &address, &size, &depth,
        (vm_region_recurse_info_t) &info, &info_count);
    if (kr != KERN_SUCCESS)
      break;

    is_contiguous = address == end;
    if (!is_contiguous)
      break;

    is_dsc_tag = info.user_tag == 0x20 || info.user_tag == 0x23;
    if (!is_dsc_tag)
      break;

    end = address + size;
  }
  while (TRUE);

  range->base_address = start;
  range->size = end - start;

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

gboolean
gum_darwin_modify_thread (mach_port_t thread,
                          GumModifyThreadFunc func,
                          gpointer user_data)
{
#ifdef HAVE_WATCHOS
  return FALSE;
#else
  kern_return_t kr;
  gboolean is_suspended = FALSE;
  GumDarwinUnifiedThreadState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  GumCpuContext cpu_context, original_cpu_context;

  kr = thread_suspend (thread);
  if (kr != KERN_SUCCESS)
    goto beach;

  is_suspended = TRUE;

  kr = thread_abort_safely (thread);
  if (kr != KERN_SUCCESS)
    goto beach;

  kr = thread_get_state (thread, state_flavor, (thread_state_t) &state,
      &state_count);
  if (kr != KERN_SUCCESS)
    goto beach;

  gum_darwin_parse_unified_thread_state (&state, &cpu_context);
  memcpy (&original_cpu_context, &cpu_context, sizeof (cpu_context));

  func (thread, &cpu_context, user_data);

  if (memcmp (&cpu_context, &original_cpu_context, sizeof (cpu_context)) != 0)
  {
    gum_darwin_unparse_unified_thread_state (&cpu_context, &state);

    kr = thread_set_state (thread, state_flavor, (thread_state_t) &state,
        state_count);
  }

beach:
  if (is_suspended)
  {
    kern_return_t resume_res;

    resume_res = thread_resume (thread);
    if (kr == KERN_SUCCESS)
      kr = resume_res;
  }

  return kr == KERN_SUCCESS;
#endif
}

void
gum_darwin_enumerate_threads (mach_port_t task,
                              GumFoundThreadFunc func,
                              gpointer user_data)
{
  mach_port_t self;
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  kern_return_t kr;

  self = mach_task_self ();

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
      GumDarwinUnifiedThreadState state;

      kr = thread_info (thread, THREAD_BASIC_INFO, (thread_info_t) &info,
          &info_count);
      if (kr != KERN_SUCCESS)
        continue;

#ifdef HAVE_WATCHOS
      bzero (&state, sizeof (state));
#else
      {
        mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
        thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;

        kr = thread_get_state (thread, state_flavor, (thread_state_t) &state,
            &state_count);
        if (kr != KERN_SUCCESS)
          continue;
      }
#endif

      details.id = (GumThreadId) thread;
      details.state = gum_thread_state_from_darwin (info.run_state);
      gum_darwin_parse_unified_thread_state (&state, &details.cpu_context);

      if (!func (&details, user_data))
        break;
    }

    for (i = 0; i != count; i++)
      mach_port_deallocate (self, threads[i]);
    vm_deallocate (self, (vm_address_t) threads, count * sizeof (thread_t));
  }
}

void
gum_darwin_enumerate_modules (mach_port_t task,
                              GumFoundModuleFunc func,
                              gpointer user_data)
{
  GumDarwinAllImageInfos infos;
  gboolean inprocess;
  const gchar * sysroot;
  guint sysroot_size;
  gsize i;
  gpointer info_array, info_array_malloc_data = NULL;
  gpointer header_data, header_data_end, header_malloc_data = NULL;
  const guint header_data_initial_size = 4096;
  gchar * file_path, * file_path_malloc_data = NULL;
  gboolean carry_on = TRUE;

  if (!gum_darwin_query_all_image_infos (task, &infos))
    goto beach;

  if (infos.info_array_address == 0)
    goto fallback;

  inprocess = task == mach_task_self ();

  sysroot = inprocess ? gum_darwin_query_sysroot () : NULL;
  sysroot_size = (sysroot != NULL) ? strlen (sysroot) : 0;

  if (inprocess)
  {
    info_array = GSIZE_TO_POINTER (infos.info_array_address);
  }
  else
  {
    info_array = gum_darwin_read (task, infos.info_array_address,
        infos.info_array_size, NULL);
    info_array_malloc_data = info_array;
  }

  for (i = 0; i != infos.info_array_count + 1 && carry_on; i++)
  {
    GumAddress load_address;
    struct mach_header * header;
    gpointer first_command, p;
    guint cmd_index;
    GumMemoryRange dylib_range;
    gchar * name;
    GumModuleDetails details;

    if (i != infos.info_array_count)
    {
      GumAddress file_path_address;

      if (infos.format == TASK_DYLD_ALL_IMAGE_INFO_64)
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

      if (inprocess)
      {
        header_data = GSIZE_TO_POINTER (load_address);

        file_path = GSIZE_TO_POINTER (file_path_address);
      }
      else
      {
        header_data = gum_darwin_read (task, load_address,
            header_data_initial_size, NULL);
        header_malloc_data = header_data;

        if (((file_path_address + MAXPATHLEN + 1) & ~((GumAddress) 4095))
            == load_address)
        {
          file_path = header_data + (file_path_address - load_address);
        }
        else
        {
          file_path = (gchar *) gum_darwin_read (task, file_path_address,
              MAXPATHLEN + 1, NULL);
          file_path_malloc_data = file_path;
        }
      }
      if (header_data == NULL || file_path == NULL)
        goto beach;
    }
    else
    {
      load_address = infos.dyld_image_load_address;

      if (inprocess)
      {
        header_data = GSIZE_TO_POINTER (load_address);
      }
      else
      {
        header_data = gum_darwin_read (task, load_address,
            header_data_initial_size, NULL);
        header_malloc_data = header_data;
      }
      if (header_data == NULL)
        goto beach;

      file_path = "/usr/lib/dyld";
    }

    header_data_end = header_data + header_data_initial_size;

    header = (struct mach_header *) header_data;
    if (infos.format == TASK_DYLD_ALL_IMAGE_INFO_64)
      first_command = header_data + sizeof (struct mach_header_64);
    else
      first_command = header_data + sizeof (struct mach_header);

    dylib_range.base_address = load_address;
    dylib_range.size = 4096;

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = p;

      if (!inprocess)
      {
        while (p + sizeof (struct load_command) > header_data_end ||
            p + lc->cmdsize > header_data_end)
        {
          gsize current_offset, new_size;

          if (file_path_malloc_data == NULL)
          {
            file_path_malloc_data = g_strdup (file_path);
            file_path = file_path_malloc_data;
          }

          current_offset = p - header_data;
          new_size = (header_data_end - header_data) + 4096;

          g_free (header_malloc_data);
          header_data = gum_darwin_read (task, load_address, new_size, NULL);
          header_malloc_data = header_data;
          if (header_data == NULL)
            goto beach;
          header_data_end = header_data + new_size;

          header = (struct mach_header *) header_data;

          p = header_data + current_offset;
          lc = (struct load_command *) p;

          first_command = NULL;
        }
      }

      if (lc->cmd == LC_SEGMENT)
      {
        struct segment_command * sc = p;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }
      else if (lc->cmd == LC_SEGMENT_64)
      {
        struct segment_command_64 * sc = p;
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
    if (sysroot != NULL && g_str_has_prefix (file_path, sysroot))
      details.path += sysroot_size;

    carry_on = func (&details, user_data);

    g_free (name);

    g_free (file_path_malloc_data);
    file_path_malloc_data = NULL;
    g_free (header_malloc_data);
    header_malloc_data = NULL;
  }

  goto beach;

fallback:
  gum_darwin_enumerate_modules_forensically (task, func, user_data);

beach:
  g_free (file_path_malloc_data);
  g_free (header_malloc_data);
  g_free (info_array_malloc_data);

  return;
}

void
gum_darwin_enumerate_modules_forensically (mach_port_t task,
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
        path = g_strndup (raw_path, raw_path_len);
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
  mach_vm_size_t size = 0;
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
      struct proc_regionwithpathinfo region;

      range.base_address = address;
      range.size = size;

      details.range = &range;
      details.protection = cur_prot;
      details.file = NULL;

      if (pid != 0 && gum_darwin_fill_file_mapping (pid, address, &file,
          &region))
      {
        details.file = &file;
        gum_darwin_clamp_range_size (&range, &file);
      }

      if (!func (&details, user_data))
        return;
    }

    address += size;
    size = 0;
  }
}

static gboolean
gum_darwin_fill_file_mapping (gint pid,
                              mach_vm_address_t address,
                              GumFileMapping * file,
                              struct proc_regionwithpathinfo * region)
{
  gint flavor, retval, len;

  if (gum_darwin_check_xnu_version (2782, 1, 97))
    flavor = PROC_PIDREGIONPATHINFO2;
  else
    flavor = PROC_PIDREGIONPATHINFO;

  retval = __proc_info (PROC_INFO_CALL_PIDINFO, pid, flavor, (uint64_t) address,
      region, sizeof (struct proc_regionwithpathinfo));

  if (retval == -1)
    return FALSE;

  len = strnlen (region->prp_vip.vip_path, MAXPATHLEN - 1);
  region->prp_vip.vip_path[len] = '\0';

  if (len == 0)
    return FALSE;

  file->path = region->prp_vip.vip_path;
  file->offset = region->prp_prinfo.pri_offset;
  file->size = region->prp_vip.vip_vi.vi_stat.vst_size;

  return TRUE;
}

static void
gum_darwin_clamp_range_size (GumMemoryRange * range,
                             const GumFileMapping * file)
{
  const gsize end_of_map = file->offset + range->size;

  if (end_of_map > file->size)
  {
    const gsize delta = end_of_map - file->size;

    range->size = MIN (
        range->size,
        (range->size - delta + (vm_kernel_page_size - 1)) &
            ~(vm_kernel_page_size - 1));
  }
}

void
gum_darwin_enumerate_imports (mach_port_t task,
                              const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  GumEnumerateImportsContext ctx;
  GumDarwinModule * module;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.resolver = gum_darwin_module_resolver_new (task, NULL);
  if (ctx.resolver == NULL)
    return;
  ctx.module_map = NULL;

  module = gum_darwin_module_resolver_find_module (ctx.resolver, module_name);
  if (module != NULL)
  {
    gum_darwin_module_enumerate_imports (module, gum_emit_import,
        gum_resolve_export, &ctx);
  }

  gum_clear_object (&ctx.module_map);
  gum_object_unref (ctx.resolver);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumImportDetails d;

  d.type = GUM_IMPORT_UNKNOWN;
  d.name = gum_symbol_name_from_darwin (details->name);
  d.module = details->module;
  d.address = 0;
  d.slot = details->slot;

  if (d.module == NULL)
  {
    if (details->address != 0)
      d.address = details->address;
    else
      d.address = GUM_ADDRESS (dlsym (RTLD_DEFAULT, d.name));

    if (d.address != 0)
    {
      const GumModuleDetails * module_details;
      Dl_info info;

      if (ctx->module_map == NULL)
        ctx->module_map = gum_module_map_new ();
      module_details = gum_module_map_find (ctx->module_map, d.address);
      if (module_details != NULL)
        d.module = module_details->path;
      else if (dladdr (GSIZE_TO_POINTER (d.address), &info) != 0)
        d.module = info.dli_fname;
    }
  }

  if (d.module != NULL)
  {
    GumDarwinModule * module;
    GumExportDetails exp;

    module = gum_darwin_module_resolver_find_module (ctx->resolver, d.module);
    if (module != NULL)
    {
      if (gum_darwin_module_resolver_find_export_by_mangled_name (ctx->resolver,
          module, details->name, &exp))
      {
        d.type = exp.type;
        d.address = exp.address;
      }
    }
  }

  return ctx->func (&d, ctx->user_data);
}

static GumAddress
gum_resolve_export (const char * module_name,
                    const char * symbol_name,
                    gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumDarwinModule * module;

  if (module_name == NULL)
  {
    const char * name = gum_symbol_name_from_darwin (symbol_name);
    return GUM_ADDRESS (dlsym (RTLD_DEFAULT, name));
  }

  module = gum_darwin_module_resolver_find_module (ctx->resolver, module_name);
  if (module != NULL)
  {
    GumExportDetails exp;

    if (gum_darwin_module_resolver_find_export_by_mangled_name (ctx->resolver,
        module, symbol_name, &exp))
    {
      return exp.address;
    }
  }

  return 0;
}

void
gum_darwin_enumerate_exports (mach_port_t task,
                              const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.resolver = gum_darwin_module_resolver_new (task, NULL);
  if (ctx.resolver == NULL)
    return;
  ctx.module = gum_darwin_module_resolver_find_module (ctx.resolver,
      module_name);
  ctx.carry_on = TRUE;
  if (ctx.module != NULL)
  {
    gum_darwin_module_enumerate_exports (ctx.module, gum_emit_export, &ctx);

    if (gum_darwin_module_get_lacks_exports_for_reexports (ctx.module))
    {
      GPtrArray * reexports = ctx.module->reexports;
      guint i;

      for (i = 0; ctx.carry_on && i != reexports->len; i++)
      {
        GumDarwinModule * reexport;

        reexport = gum_darwin_module_resolver_find_module (ctx.resolver,
            g_ptr_array_index (reexports, i));
        if (reexport != NULL)
        {
          ctx.module = reexport;
          gum_darwin_module_enumerate_exports (reexport, gum_emit_export, &ctx);
        }
      }
    }
  }

  gum_object_unref (ctx.resolver);
}

static gboolean
gum_emit_export (const GumDarwinExportDetails * details,
                 gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  GumExportDetails export;

  if (!gum_darwin_module_resolver_resolve_export (ctx->resolver, ctx->module,
      details, &export))
  {
    return TRUE;
  }

  ctx->carry_on = ctx->func (&export, ctx->user_data);

  return ctx->carry_on;
}

void
gum_darwin_enumerate_symbols (mach_port_t task,
                              const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GumDarwinModuleResolver * resolver;
  GumDarwinModule * module;

  resolver = gum_darwin_module_resolver_new (task, NULL);
  if (resolver == NULL)
    return;

  module = gum_darwin_module_resolver_find_module (resolver, module_name);
  if (module != NULL)
  {
    GumEnumerateSymbolsContext ctx;

    ctx.func = func;
    ctx.user_data = user_data;

    ctx.sections = g_array_new (FALSE, FALSE, sizeof (GumSymbolSection));
    g_array_set_clear_func (ctx.sections,
        (GDestroyNotify) gum_symbol_section_destroy);

    gum_darwin_module_enumerate_sections (module, gum_append_symbol_section,
        ctx.sections);

    gum_darwin_module_enumerate_symbols (module, gum_emit_symbol, &ctx);

    g_array_free (ctx.sections, TRUE);
  }

  gum_object_unref (resolver);
}

static gboolean
gum_emit_symbol (const GumDarwinSymbolDetails * details,
                 gpointer user_data)
{
  GumEnumerateSymbolsContext * ctx = user_data;
  GumSymbolDetails symbol;

  symbol.is_global = (details->type & N_EXT) != 0;

  switch (details->type & N_TYPE)
  {
    case N_UNDF: symbol.type = GUM_SYMBOL_UNDEFINED;          break;
    case N_ABS:  symbol.type = GUM_SYMBOL_ABSOLUTE;           break;
    case N_SECT: symbol.type = GUM_SYMBOL_SECTION;            break;
    case N_PBUD: symbol.type = GUM_SYMBOL_PREBOUND_UNDEFINED; break;
    case N_INDR: symbol.type = GUM_SYMBOL_INDIRECT;           break;
    default:     symbol.type = GUM_SYMBOL_UNKNOWN;            break;
  }

  if (details->section != NO_SECT && details->section <= ctx->sections->len)
  {
    symbol.section = &g_array_index (ctx->sections, GumSymbolSection,
        details->section - 1);
  }
  else
  {
    symbol.section = NULL;
  }

  symbol.name = gum_symbol_name_from_darwin (details->name);
  symbol.address = details->address;
  symbol.size = -1;

  return ctx->func (&symbol, ctx->user_data);
}

static gboolean
gum_append_symbol_section (const GumDarwinSectionDetails * details,
                            gpointer user_data)
{
  GArray * sections = user_data;
  GumSymbolSection section;

  section.id = g_strdup_printf ("%u.%s.%s", sections->len,
      details->segment_name, details->section_name);
  section.protection = gum_page_protection_from_mach (details->protection);

  g_array_append_val (sections, section);

  return TRUE;
}

static void
gum_symbol_section_destroy (GumSymbolSection * self)
{
  g_free ((gpointer) self->id);
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
  gboolean found = FALSE;
  const gchar * sysroot;
  guint sysroot_size;
  gchar * image_alias;
  guint count, i;

  sysroot = gum_darwin_query_sysroot ();
  sysroot_size = (sysroot != NULL) ? strlen (sysroot) : 0;

  image_alias = g_str_has_prefix (image_name, "/usr/lib/system/")
      ? g_strconcat ("/usr/lib/system/introspection/", image_name + 16, NULL)
      : NULL;

  count = _dyld_image_count ();

  for (i = 0; i != count; i++)
  {
    const gchar * candidate_name;

    candidate_name = _dyld_get_image_name (i);
    if (sysroot != NULL && g_str_has_prefix (candidate_name, sysroot))
      candidate_name += sysroot_size;

    if (gum_module_path_equals (candidate_name, image_name) ||
        ((image_alias != NULL) &&
         gum_module_path_equals (candidate_name, image_alias)))
    {
      *address = (gpointer) _dyld_get_image_header (i);
      *slide = (gpointer) _dyld_get_image_vmaddr_slide (i);
      found = TRUE;
      break;
    }
  }

  g_free (image_alias);

  return found;
}

static gchar *
gum_canonicalize_module_name (const gchar * name)
{
  GumCanonicalizeNameContext ctx;

  if (name[0] == '/')
    return g_strdup (name);

  ctx.module_name = name;
  ctx.module_path = NULL;
  gum_process_enumerate_modules (gum_store_module_path_if_module_name_matches,
      &ctx);
  return ctx.module_path;
}

static gboolean
gum_store_module_path_if_module_name_matches (const GumModuleDetails * details,
                                              gpointer user_data)
{
  GumCanonicalizeNameContext * ctx = user_data;

  if (strcmp (details->name, ctx->module_name) == 0)
  {
    ctx->module_path = g_strdup (details->path);
    return FALSE;
  }

  return TRUE;
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
    case TH_STATE_HALTED:
    default:
      return GUM_THREAD_HALTED;
  }
}

void
gum_darwin_parse_unified_thread_state (const GumDarwinUnifiedThreadState * ts,
                                       GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  gum_darwin_parse_native_thread_state (&ts->uts.ts32, ctx);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  gum_darwin_parse_native_thread_state (&ts->uts.ts64, ctx);
#elif defined (HAVE_ARM)
  gum_darwin_parse_native_thread_state (&ts->ts_32, ctx);
#elif defined (HAVE_ARM64)
  gum_darwin_parse_native_thread_state (&ts->ts_64, ctx);
#endif
}

void
gum_darwin_parse_native_thread_state (const GumDarwinNativeThreadState * ts,
                                      GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
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
  guint n;

  ctx->pc = ts->__pc;
  ctx->sp = ts->__sp;
  ctx->cpsr = ts->__cpsr;

  ctx->r8 = ts->__r[8];
  ctx->r9 = ts->__r[9];
  ctx->r10 = ts->__r[10];
  ctx->r11 = ts->__r[11];
  ctx->r12 = ts->__r[12];

  memset (ctx->v, 0, sizeof (ctx->v));

  for (n = 0; n != G_N_ELEMENTS (ctx->r); n++)
    ctx->r[n] = ts->__r[n];
  ctx->lr = ts->__lr;
#elif defined (HAVE_ARM64)
  guint n;

# ifdef HAVE_PTRAUTH
  ctx->pc = GPOINTER_TO_SIZE (ts->__opaque_pc);
  ctx->sp = GPOINTER_TO_SIZE (ts->__opaque_sp);

  ctx->fp = GPOINTER_TO_SIZE (ts->__opaque_fp);
  ctx->lr = GPOINTER_TO_SIZE (ts->__opaque_lr);
# else
  ctx->pc = GPOINTER_TO_SIZE (__darwin_arm_thread_state64_get_pc_fptr (*ts));
  ctx->sp = __darwin_arm_thread_state64_get_sp (*ts);

  ctx->fp = __darwin_arm_thread_state64_get_fp (*ts);
  ctx->lr = GPOINTER_TO_SIZE (__darwin_arm_thread_state64_get_lr_fptr (*ts));
# endif

  for (n = 0; n != G_N_ELEMENTS (ctx->x); n++)
    ctx->x[n] = ts->__x[n];

  memset (ctx->v, 0, sizeof (ctx->v));
#endif
}

void
gum_darwin_unparse_unified_thread_state (const GumCpuContext * ctx,
                                         GumDarwinUnifiedThreadState * ts)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  x86_state_hdr_t * header = &ts->tsh;

  header->flavor = x86_THREAD_STATE32;
  header->count = x86_THREAD_STATE32_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->uts.ts32);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  x86_state_hdr_t * header = &ts->tsh;

  header->flavor = x86_THREAD_STATE64;
  header->count = x86_THREAD_STATE64_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->uts.ts64);
#elif defined (HAVE_ARM)
  arm_state_hdr_t * header = &ts->ash;

  header->flavor = ARM_THREAD_STATE;
  header->count = ARM_THREAD_STATE_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->ts_32);
#elif defined (HAVE_ARM64)
  arm_state_hdr_t * header = &ts->ash;

  header->flavor = ARM_THREAD_STATE64;
  header->count = ARM_THREAD_STATE64_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->ts_64);
#endif
}

void
gum_darwin_unparse_native_thread_state (const GumCpuContext * ctx,
                                        GumDarwinNativeThreadState * ts)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
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
  guint n;

  ts->__pc = ctx->pc;
  ts->__sp = ctx->sp;
  ts->__cpsr = ctx->cpsr;

  ts->__r[8] = ctx->r8;
  ts->__r[9] = ctx->r9;
  ts->__r[10] = ctx->r10;
  ts->__r[11] = ctx->r11;
  ts->__r[12] = ctx->r12;

  for (n = 0; n != G_N_ELEMENTS (ctx->r); n++)
    ts->__r[n] = ctx->r[n];
  ts->__lr = ctx->lr;
#elif defined (HAVE_ARM64)
  guint n;

# ifdef HAVE_PTRAUTH
  ts->__opaque_pc = GSIZE_TO_POINTER (ctx->pc);
  ts->__opaque_sp = GSIZE_TO_POINTER (ctx->sp);

  ts->__opaque_fp = GSIZE_TO_POINTER (ctx->fp);
  ts->__opaque_lr = GSIZE_TO_POINTER (ctx->lr);
# else
  __darwin_arm_thread_state64_set_pc_fptr (*ts, GSIZE_TO_POINTER (ctx->pc));
  __darwin_arm_thread_state64_set_sp (*ts, ctx->sp);

  __darwin_arm_thread_state64_set_fp (*ts, ctx->fp);
  __darwin_arm_thread_state64_set_lr_fptr (*ts, GSIZE_TO_POINTER (ctx->lr));
# endif

  for (n = 0; n != G_N_ELEMENTS (ctx->x); n++)
    ts->__x[n] = ctx->x[n];
#endif
}

const char *
gum_symbol_name_from_darwin (const char * s)
{
  return (s[0] == '_') ? s + 1 : s;
}
