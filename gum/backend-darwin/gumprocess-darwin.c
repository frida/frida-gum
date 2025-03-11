/*
 * Copyright (C) 2010-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2022-2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2022-2025 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2023 Alex Soler <asoler@nowsecure.com>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gum-init.h"
#include "gum/gumdarwin.h"
#include "gumleb.h"
#include "gumdarwin-priv.h"
#include "gummodule-darwin.h"
#include "gummodulefacade.h"

#include <capstone.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <mach-o/dyld.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <unistd.h>

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

typedef struct _GumSetHardwareBreakpointContext GumSetHardwareBreakpointContext;
typedef struct _GumSetHardwareWatchpointContext GumSetHardwareWatchpointContext;
typedef void (* GumModifyDebugRegistersFunc) (GumDarwinNativeDebugState * ds,
    gpointer user_data);
typedef struct _GumFindEntrypointContext GumFindEntrypointContext;
typedef struct _GumEnumerateMallocRangesContext GumEnumerateMallocRangesContext;
typedef struct _GumFindModuleByNameContext GumFindModuleByNameContext;

struct _GumSetHardwareBreakpointContext
{
  guint breakpoint_id;
  GumAddress address;
};

struct _GumSetHardwareWatchpointContext
{
  guint watchpoint_id;
  GumAddress address;
  gsize size;
  GumWatchConditions conditions;
};

struct _GumFindEntrypointContext
{
  GumAddress result;
  mach_port_t task;
  guint alignment;
};

struct _GumEnumerateMallocRangesContext
{
  GumFoundMallocRangeFunc func;
  gpointer user_data;
  gboolean carry_on;
};

struct _GumFindModuleByNameContext
{
  const gchar * name;
  GumModule * module;
};

typedef enum {
  GUM_OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION = 0x10000,
  GUM_OS_UNFAIR_LOCK_ADAPTIVE_SPIN        = 0x40000,
} GumUnfairLockOptions;

extern int __proc_info (int callnum, int pid, int flavor, uint64_t arg,
    void * buffer, int buffersize);
extern void os_unfair_lock_lock_with_options (os_unfair_lock_t lock,
    GumUnfairLockOptions options);

static void gum_deinit_libc_module (void);
static void gum_do_set_hardware_breakpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static void gum_do_unset_hardware_breakpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static void gum_do_set_hardware_watchpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static void gum_do_unset_hardware_watchpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static gboolean gum_modify_debug_registers (GumThreadId thread_id,
    GumModifyDebugRegistersFunc func, gpointer user_data, GError ** error);
static void gum_emit_malloc_ranges (task_t task,
    void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t gum_read_malloc_memory (task_t remote_task,
    vm_address_t remote_address, vm_size_t size, void ** local_memory);
static void gum_deinit_sysroot (void);
static gboolean gum_probe_range_for_entrypoint (const GumRangeDetails * details,
    gpointer user_data);
static gboolean gum_try_resolve_module_by_name (GumModule * module,
    gpointer user_data);
static gboolean gum_try_resolve_module_by_path (GumModule * module,
    gpointer user_data);

static gboolean gum_compute_pthread_spec (GumDarwinPThreadSpec * spec);
static gboolean gum_detect_pthread_basics (csh capstone, cs_insn * insn,
    GumDarwinPThreadSpec * spec);
static gboolean gum_detect_pthread_name_offset (csh capstone, cs_insn * insn,
    guint * name_offset);

static GumThreadState gum_thread_state_from_darwin (integer_t run_state);

static GumModule * gum_libc_module;

GumModule *
gum_process_get_libc_module (void)
{
  static gsize modules_value = 0;

  if (g_once_init_enter (&modules_value))
  {
    gum_libc_module =
        gum_process_find_module_by_name ("/usr/lib/libSystem.B.dylib");

    _gum_register_destructor (gum_deinit_libc_module);

    g_once_init_leave (&modules_value, GPOINTER_TO_SIZE (gum_libc_module));
  }

  return GSIZE_TO_POINTER (modules_value);
}

static void
gum_deinit_libc_module (void)
{
  g_object_unref (gum_libc_module);
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
                           gpointer user_data,
                           GumModifyThreadFlags flags)
{
  return gum_darwin_modify_thread (thread_id, func, user_data, flags);
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data,
                                GumThreadFlags flags)
{
  gum_darwin_enumerate_threads (mach_task_self (), func, user_data, flags);
}

gboolean
_gum_process_collect_main_module (GumModule * module,
                                  gpointer user_data)
{
  GumModule ** out = user_data;
  gum_mach_header_t * header;

  header = GSIZE_TO_POINTER (gum_module_get_range (module)->base_address);
  if (header->filetype == MH_EXECUTE)
  {
    *out = g_object_ref (module);

    return FALSE;
  }

  return TRUE;
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
gum_thread_set_hardware_breakpoint (GumThreadId thread_id,
                                    guint breakpoint_id,
                                    GumAddress address,
                                    GError ** error)
{
  GumSetHardwareBreakpointContext bpc;

  bpc.breakpoint_id = breakpoint_id;
  bpc.address = address;

  return gum_modify_debug_registers (thread_id, gum_do_set_hardware_breakpoint,
      &bpc, error);
}

static void
gum_do_set_hardware_breakpoint (GumDarwinNativeDebugState * ds,
                                gpointer user_data)
{
  GumSetHardwareBreakpointContext * bpc = user_data;

#ifdef HAVE_ARM64
  _gum_arm64_set_breakpoint (ds->__bcr, ds->__bvr, bpc->breakpoint_id,
      bpc->address);
#else
  _gum_x86_set_breakpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      bpc->breakpoint_id, bpc->address);
#endif
}

gboolean
gum_thread_unset_hardware_breakpoint (GumThreadId thread_id,
                                      guint breakpoint_id,
                                      GError ** error)
{
  return gum_modify_debug_registers (thread_id,
      gum_do_unset_hardware_breakpoint, GUINT_TO_POINTER (breakpoint_id),
      error);
}

static void
gum_do_unset_hardware_breakpoint (GumDarwinNativeDebugState * ds,
                                  gpointer user_data)
{
  guint breakpoint_id = GPOINTER_TO_UINT (user_data);

#ifdef HAVE_ARM64
  _gum_arm64_unset_breakpoint (ds->__bcr, ds->__bvr, breakpoint_id);
#else
  _gum_x86_unset_breakpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      breakpoint_id);
#endif
}

gboolean
gum_thread_set_hardware_watchpoint (GumThreadId thread_id,
                                    guint watchpoint_id,
                                    GumAddress address,
                                    gsize size,
                                    GumWatchConditions wc,
                                    GError ** error)
{
  GumSetHardwareWatchpointContext wpc;

  wpc.watchpoint_id = watchpoint_id;
  wpc.address = address;
  wpc.size = size;
  wpc.conditions = wc;

  return gum_modify_debug_registers (thread_id, gum_do_set_hardware_watchpoint,
      &wpc, error);
}

static void
gum_do_set_hardware_watchpoint (GumDarwinNativeDebugState * ds,
                                gpointer user_data)
{
  GumSetHardwareWatchpointContext * wpc = user_data;

#if defined (HAVE_ARM64)
  _gum_arm64_set_watchpoint (ds->__wcr, ds->__wvr, wpc->watchpoint_id,
      wpc->address, wpc->size, wpc->conditions);
#else
  _gum_x86_set_watchpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      wpc->watchpoint_id, wpc->address, wpc->size, wpc->conditions);
#endif
}

gboolean
gum_thread_unset_hardware_watchpoint (GumThreadId thread_id,
                                      guint watchpoint_id,
                                      GError ** error)
{
  return gum_modify_debug_registers (thread_id,
      gum_do_unset_hardware_watchpoint, GUINT_TO_POINTER (watchpoint_id),
      error);
}

static void
gum_do_unset_hardware_watchpoint (GumDarwinNativeDebugState * ds,
                                  gpointer user_data)
{
  guint watchpoint_id = GPOINTER_TO_UINT (user_data);

#if defined (HAVE_ARM64)
  _gum_arm64_unset_watchpoint (ds->__wcr, ds->__wvr, watchpoint_id);
#else
  _gum_x86_unset_watchpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      watchpoint_id);
#endif
}

static gboolean
gum_modify_debug_registers (GumThreadId thread_id,
                            GumModifyDebugRegistersFunc func,
                            gpointer user_data,
                            GError ** error)
{
#ifdef HAVE_WATCHOS
  g_set_error (error,
      GUM_ERROR,
      GUM_ERROR_NOT_SUPPORTED,
      "Not supported");
  return FALSE;
#else
  gboolean success = FALSE;
  kern_return_t kr;
  GumDarwinNativeDebugState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_DEBUG_STATE_COUNT;
  thread_state_flavor_t state_flavor = GUM_DARWIN_DEBUG_STATE_FLAVOR;

  kr = thread_get_state (thread_id, state_flavor, (thread_state_t) &state,
      &state_count);
  if (kr != KERN_SUCCESS)
    goto failure;

  func (&state, user_data);

  kr = thread_set_state (thread_id, state_flavor, (thread_state_t) &state,
      state_count);
  if (kr != KERN_SUCCESS)
    goto failure;

  success = TRUE;
  goto beach;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "Unable to modify debug registers: %s", mach_error_string (kr));
    goto beach;
  }
beach:
  {
    return success;
  }
#endif
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

const gchar *
gum_darwin_query_sysroot (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    gchar * result = NULL;
    guint n, i;

    n = _dyld_image_count ();
    for (i = 0; i != n; i++)
    {
      const gchar * name, * p;

      name = _dyld_get_image_name (i);
      if (name == NULL)
        break;

      p = strstr (name, "/usr/lib/libSystem.B.dylib");
      if (p != NULL)
      {
        if (p != name)
        {
          result = g_strndup (name, p - name);
          _gum_register_destructor (gum_deinit_sysroot);
        }

        break;
      }
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

  if (!_gum_darwin_fill_file_mapping (pid, address, &file, &region))
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
                          gpointer user_data,
                          GumModifyThreadFlags flags)
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

  if ((flags & GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY) != 0)
  {
    kr = thread_abort_safely (thread);
    if (kr != KERN_SUCCESS)
      goto beach;
  }

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
                              gpointer user_data,
                              GumThreadFlags flags)
{
  mach_port_t self;
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  GArray * entries;
  GPtrArray * names;
  GHashTable * pending_ports;
  guint i;
  GHashTableIter iter;
  gpointer key;

  self = mach_task_self ();

  if (task_threads (task, &threads, &count) != KERN_SUCCESS)
    return;

  entries = g_array_sized_new (FALSE, FALSE, sizeof (GumThreadDetails), count);
  names = g_ptr_array_new_full (count, g_free);
  pending_ports = g_hash_table_new (NULL, NULL);
  for (i = 0; i != count; i++)
    g_hash_table_add (pending_ports, GUINT_TO_POINTER (threads[i]));

  if (task == self &&
      (flags & (GUM_THREAD_FLAGS_NAME |
                GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE |
                GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER)) != 0)
  {
    const GumDarwinPThreadSpec * spec;
    GumDarwinPThreadIter iter;
    pthread_t pth;

    spec = gum_darwin_query_pthread_spec ();

    gum_darwin_lock_pthread_list (spec);

    gum_darwin_pthread_iter_init (&iter, spec);
    while (gum_darwin_pthread_iter_next (&iter, &pth))
    {
      mach_port_t thread;
      GumThreadDetails entry = { 0, };
      gpointer start_routine;

      thread = gum_darwin_query_pthread_port (pth, spec);
      g_hash_table_remove (pending_ports, GUINT_TO_POINTER (thread));

      entry.id = thread;

      if ((flags & GUM_THREAD_FLAGS_NAME) != 0)
      {
        gchar * name = g_strdup (gum_darwin_query_pthread_name (pth, spec));
        if (name != NULL)
        {
          entry.name = name;
          entry.flags |= GUM_THREAD_FLAGS_NAME;

          g_ptr_array_add (names, name);
        }
      }

      if ((flags & GUM_THREAD_FLAGS_STATE) != 0)
      {
        if (!gum_darwin_query_thread_state (thread, &entry.state))
          continue;
        entry.flags |= GUM_THREAD_FLAGS_STATE;
      }

      if ((flags & GUM_THREAD_FLAGS_CPU_CONTEXT) != 0)
      {
        if (!gum_darwin_query_thread_cpu_context (thread, &entry.cpu_context))
          continue;
        entry.flags |= GUM_THREAD_FLAGS_CPU_CONTEXT;
      }

      start_routine = gum_darwin_query_pthread_start_routine (pth, spec);
      if (start_routine != NULL)
      {
        if ((flags & GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE) != 0)
        {
          entry.entrypoint.routine = GUM_ADDRESS (start_routine);
          entry.flags |= GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE;
        }

        if ((flags & GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER) != 0)
        {
          entry.entrypoint.parameter = GUM_ADDRESS (
              gum_darwin_query_pthread_start_parameter (pth, spec));
          entry.flags |= GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER;
        }
      }

      g_array_append_val (entries, entry);
    }

    gum_darwin_unlock_pthread_list (spec);
  }

  g_hash_table_iter_init (&iter, pending_ports);
  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    thread_t thread = GPOINTER_TO_UINT (key);
    GumThreadDetails entry = { 0, };

    entry.id = thread;

    if ((flags & GUM_THREAD_FLAGS_STATE) != 0)
    {
      if (!gum_darwin_query_thread_state (thread, &entry.state))
        continue;
      entry.flags |= GUM_THREAD_FLAGS_STATE;
    }

    if ((flags & GUM_THREAD_FLAGS_CPU_CONTEXT) != 0)
    {
      if (!gum_darwin_query_thread_cpu_context (thread, &entry.cpu_context))
        continue;
      entry.flags |= GUM_THREAD_FLAGS_CPU_CONTEXT;
    }

    g_array_append_val (entries, entry);
  }

  for (i = 0; i != entries->len; i++)
  {
    GumThreadDetails * entry = &g_array_index (entries, GumThreadDetails, i);

    if (!func (entry, user_data))
      break;
  }

  g_hash_table_unref (pending_ports);
  g_ptr_array_unref (names);
  g_array_unref (entries);

  for (i = 0; i != count; i++)
    mach_port_deallocate (self, threads[i]);
  vm_deallocate (self, (vm_address_t) threads, count * sizeof (thread_t));
}

void
gum_darwin_pthread_iter_init (GumDarwinPThreadIter * iter,
                              const GumDarwinPThreadSpec * spec)
{
  iter->node = NULL;
  iter->spec = spec;
}

gboolean
gum_darwin_pthread_iter_next (GumDarwinPThreadIter * self,
                              pthread_t * thread)
{
  struct _GumDarwinPThread * pth = self->node;

  if (pth != NULL)
    pth = TAILQ_NEXT (pth, tl_plist);
  else
    pth = TAILQ_FIRST (self->spec->thread_list);
  if (pth == NULL)
    return FALSE;
  self->node = pth;

  *thread = (pthread_t) pth;
  return TRUE;
}

GumModule *
gum_darwin_find_module_by_name (mach_port_t task,
                                const gchar * name)
{
  GumFindModuleByNameContext ctx = {
    .name = name,
    .module = NULL
  };

  if (g_path_is_absolute (name))
    gum_darwin_enumerate_modules (task, gum_try_resolve_module_by_path, &ctx);
  else
    gum_darwin_enumerate_modules (task, gum_try_resolve_module_by_name, &ctx);

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

void
gum_darwin_enumerate_modules (mach_port_t task,
                              GumFoundModuleFunc func,
                              gpointer user_data)
{
  GumDarwinModuleResolver * resolver;
  GPtrArray * modules;
  gboolean carry_on;
  guint i;

  if (task == mach_task_self ())
  {
    gum_module_registry_enumerate_modules (gum_module_registry_obtain (), func,
        user_data);
    return;
  }

  resolver = gum_darwin_module_resolver_new (task, NULL);
  if (resolver == NULL)
    return;

  gum_darwin_module_resolver_fetch_modules (resolver, &modules, NULL);

  for (carry_on = TRUE, i = 0; carry_on && i != modules->len; i++)
  {
    GumModule * module;
    GumModuleFacade * facade;

    module = g_ptr_array_index (modules, i);
    facade = _gum_module_facade_new (module, G_OBJECT (resolver));

    carry_on = func (GUM_MODULE (facade), user_data);

    g_object_unref (facade);
  }

  g_ptr_array_unref (modules);

  g_object_unref (resolver);
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

      if (pid != 0 && _gum_darwin_fill_file_mapping (pid, address, &file,
          &region))
      {
        details.file = &file;
        _gum_darwin_clamp_range_size (&range, &file);
      }

      if (!func (&details, user_data))
        return;
    }

    address += size;
    size = 0;
  }
}

gboolean
_gum_darwin_fill_file_mapping (gint pid,
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

void
_gum_darwin_clamp_range_size (GumMemoryRange * range,
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

gboolean
gum_darwin_query_thread_state (mach_port_t thread,
                               GumThreadState * state)
{
  thread_basic_info_data_t info;
  mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;

  if (thread_info (thread, THREAD_BASIC_INFO, (thread_info_t) &info,
        &info_count) != KERN_SUCCESS)
    return FALSE;

  *state = gum_thread_state_from_darwin (info.run_state);
  return TRUE;
}

gboolean
gum_darwin_query_thread_cpu_context (mach_port_t thread,
                                     GumCpuContext * ctx)
{
#ifdef HAVE_WATCHOS
  bzero (ctx, sizeof (GumCpuContext));
#else
  GumDarwinUnifiedThreadState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;

  if (thread_get_state (thread, GUM_DARWIN_THREAD_STATE_FLAVOR,
        (thread_state_t) &state, &state_count) != KERN_SUCCESS)
    return FALSE;

  gum_darwin_parse_unified_thread_state (&state, ctx);
  return TRUE;
#endif
}

mach_port_t
gum_darwin_query_pthread_port (pthread_t thread,
                               const GumDarwinPThreadSpec * spec)
{
  return *((mach_port_t *) ((guint8 *) thread + spec->mach_port_offset));
}

const gchar *
gum_darwin_query_pthread_name (pthread_t thread,
                               const GumDarwinPThreadSpec * spec)
{
  const gchar * name;

  name = (char *) thread + spec->name_offset;
  if (name[0] == '\0')
    return NULL;

  return name;
}

gpointer
gum_darwin_query_pthread_start_routine (pthread_t thread,
                                        const GumDarwinPThreadSpec * spec)
{
  return *((gpointer *) ((guint8 *) thread + spec->start_routine_offset));
}

gpointer
gum_darwin_query_pthread_start_parameter (pthread_t thread,
                                          const GumDarwinPThreadSpec * spec)
{
 return *((gpointer *) ((guint8 *) thread + spec->start_parameter_offset));
}

void
gum_darwin_lock_pthread_list (const GumDarwinPThreadSpec * spec)
{
  os_unfair_lock_lock_with_options (spec->thread_list_lock,
      GUM_OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION |
      GUM_OS_UNFAIR_LOCK_ADAPTIVE_SPIN);
}

void
gum_darwin_unlock_pthread_list (const GumDarwinPThreadSpec * spec)
{
  os_unfair_lock_unlock (spec->thread_list_lock);
}

const GumDarwinPThreadSpec *
gum_darwin_query_pthread_spec (void)
{
  static GumDarwinPThreadSpec spec;
  static gsize initialized = FALSE;

  if (g_once_init_enter (&initialized))
  {
    if (!gum_compute_pthread_spec (&spec))
      g_error ("Unsupported Apple system; please file a bug");

    g_once_init_leave (&initialized, TRUE);
  }

  return &spec;
}

static gboolean
gum_compute_pthread_spec (GumDarwinPThreadSpec * spec)
{
  gboolean success = FALSE;
  csh capstone;
  cs_insn * insn;

  gum_cs_arch_register_native ();
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option (capstone, CS_OPT_SKIPDATA, CS_OPT_ON);

  insn = cs_malloc (capstone);

  if (!gum_detect_pthread_basics (capstone, insn, spec))
    goto beach;

  if (!gum_detect_pthread_name_offset (capstone, insn, &spec->name_offset))
    goto beach;

  spec->start_routine_offset =
      spec->name_offset + GUM_DARWIN_MAX_THREAD_NAME_SIZE;
  spec->start_parameter_offset = spec->start_routine_offset + sizeof (gpointer);

  success = TRUE;

beach:
  cs_free (insn, 1);

  cs_close (&capstone);

  return success;
}

static gboolean
gum_detect_pthread_basics (csh capstone,
                           cs_insn * insn,
                           GumDarwinPThreadSpec * spec)
{
  gboolean success = FALSE;
  gpointer pfmt_prologue;
  const uint8_t * code;
  size_t size;
  uint64_t addr;
  gpointer locations[2];
  guint num_locations;
  guint mach_port_offset;

  pfmt_prologue = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_get_libc_module (), "pthread_from_mach_thread_np"));

  code = gum_strip_code_pointer (pfmt_prologue);
  code += gum_interceptor_detect_hook_size (code, capstone, insn);
  size = 256;
  addr = GPOINTER_TO_SIZE (code);

  num_locations = 0;
  mach_port_offset = 0;

#if defined (HAVE_I386)
  {
    while ((num_locations != 2 || mach_port_offset == 0) &&
        cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_x86 * x86 = &insn->detail->x86;

      switch (insn->id)
      {
        case X86_INS_LEA:
        {
          const cs_x86_op * dst = &x86->operands[0];
          const cs_x86_op * src = &x86->operands[1];

          if (num_locations == 0 &&
              dst->reg == X86_REG_RDI &&
              src->mem.base == X86_REG_RIP)
          {
            locations[num_locations++] =
                GSIZE_TO_POINTER (addr + src->mem.disp);
          }

          break;
        }
        case X86_INS_MOV:
        {
          const cs_x86_op * src = &x86->operands[1];

          if (num_locations == 1 &&
              src->type == X86_OP_MEM &&
              src->mem.base == X86_REG_RIP)
          {
            locations[num_locations++] =
                GSIZE_TO_POINTER (addr + src->mem.disp);
          }

          break;
        }
        case X86_INS_CMP:
        {
          const cs_x86_op * lhs = &x86->operands[0];
          const cs_x86_op * rhs = &x86->operands[1];

          if (mach_port_offset == 0 &&
              lhs->type == X86_OP_MEM &&
              rhs->type == X86_OP_REG)
          {
            mach_port_offset = lhs->mem.disp;
          }

          break;
        }
        default:
          break;
      }
    }
  }
#elif defined (HAVE_ARM64)
  {
    const uint8_t * adrp_location = NULL;
    arm64_reg adrp_reg = ARM64_REG_INVALID;
    gsize accumulated_value = 0;

    while ((num_locations != 2 || mach_port_offset == 0) &&
        cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_arm64 * arm64 = &insn->detail->arm64;

      switch (insn->id)
      {
        case ARM64_INS_ADRP:
        {
          adrp_location = code - insn->size;
          adrp_reg = arm64->operands[0].reg;
          accumulated_value = arm64->operands[1].imm;

          break;
        }
        case ARM64_INS_ADD:
        {
          const uint8_t * add_location = code - insn->size;
          const cs_arm64_op * dst = &arm64->operands[0];
          const cs_arm64_op * n = &arm64->operands[1];
          const cs_arm64_op * m = &arm64->operands[2];

          if (adrp_location != NULL &&
              add_location - 4 == adrp_location &&
              dst->reg == adrp_reg &&
              n->reg == dst->reg &&
              m->type == ARM64_OP_IMM)
          {
            accumulated_value += m->imm;
          }

          break;
        }
        case ARM64_INS_LDR:
        {
          const arm64_op_mem * src = &arm64->operands[1].mem;

          if (mach_port_offset == 0 &&
              src->base != ARM64_REG_SP &&
              src->base != ARM64_REG_FP &&
              src->index == ARM64_REG_INVALID &&
              src->disp != 0)
          {
            mach_port_offset = src->disp;
          }

          break;
        }
        default:
        {
          if (num_locations != 2 && accumulated_value != 0)
          {
            locations[num_locations++] = GSIZE_TO_POINTER (accumulated_value);
            accumulated_value = 0;
          }

          break;
        }
      }
    }
  }
#else
# error Unsupported architecture
#endif

  if (num_locations == 2)
  {
    spec->thread_list_lock = locations[0];
    spec->thread_list = locations[1];

    spec->mach_port_offset = mach_port_offset;

    success = TRUE;
  }

  return success;
}

static gboolean
gum_detect_pthread_name_offset (csh capstone,
                                cs_insn * insn,
                                guint * name_offset)
{
  gpointer setname_prologue;
  const uint8_t * code;
  size_t size;
  uint64_t addr;

  setname_prologue = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_get_libc_module (), "pthread_setname_np"));

  code = gum_strip_code_pointer (setname_prologue);
  code += gum_interceptor_detect_hook_size (code, capstone, insn);
  size = 512;
  addr = GPOINTER_TO_SIZE (code);

#if defined (HAVE_I386)
  {
    while (cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_x86 * x86 = &insn->detail->x86;

      switch (insn->id)
      {
        case X86_INS_ADD:
        {
          const cs_x86_op * dst = &x86->operands[0];
          const cs_x86_op * src = &x86->operands[1];

          if (dst->type == X86_OP_REG &&
              src->type == X86_OP_IMM)
          {
            *name_offset = src->imm;
            return TRUE;
          }

          break;
        }
        default:
          break;
      }
    }
  }
#elif defined (HAVE_ARM64)
  {
    while (cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_arm64 * arm64 = &insn->detail->arm64;

      switch (insn->id)
      {
        case ARM64_INS_ADD:
        {
          const cs_arm64_op * dst = &arm64->operands[0];
          const cs_arm64_op * n = &arm64->operands[1];
          const cs_arm64_op * m = &arm64->operands[2];

          if (dst->reg == ARM64_REG_X0 &&
              n->reg != ARM64_REG_SP &&
              m->type == ARM64_OP_IMM)
          {
            *name_offset = m->imm;
            return TRUE;
          }

          break;
        }
        default:
          break;
      }
    }
  }
#else
# error Unsupported architecture
#endif

  return FALSE;
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
