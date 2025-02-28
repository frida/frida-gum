/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry-priv.h"

#include "guminterceptor.h"
#include "gum/gumlinux.h"
#ifndef HAVE_ANDROID
# include "gumsystemtap.h"
#endif

#include <capstone.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

typedef struct _GumPThreadSpec GumPThreadSpec;
typedef struct _GumPThread GumPThread;

typedef struct _GumGlibcList GumGlibcList;
typedef int GumGlibcLock;

struct _GumPThreadSpec
{
#if defined (HAVE_GLIBC)
  GumGlibcList * stack_used;
  GumGlibcList * stack_user;
  GumGlibcLock * stack_lock;
#elif defined (HAVE_ANDROID)
  GumPThread ** thread_list;
  pthread_rwlock_t * thread_list_lock;
#endif

  gpointer start_impl;
  guint start_routine_offset;
  guint start_parameter_offset;

  gpointer terminate_impl;
};

struct _GumGlibcList
{
  GumGlibcList * next;
  GumGlibcList * prev;
};

struct _GumPThread
{
#if defined (HAVE_GLIBC)
  union
  {
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    guint8 tcb_header[704];
#endif
    gpointer padding[24];
  } header;
  GumGlibcList list;
  pid_t tid;
#elif defined (HAVE_ANDROID)
  GumPThread * next;
  GumPThread * prev;
  pid_t tid;
#endif
};

static gboolean gum_add_existing_thread (const GumThreadDetails * thread,
    gpointer user_data);
static void gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
    gpointer user_data);
static void gum_compute_thread_details_from_pthread (GumPThread * pthread,
    const GumPThreadSpec * spec, GumThreadDetails * details, gpointer * storage);

static void gum_lock_thread_list (GumPThreadSpec * spec);
static void gum_unlock_thread_list (GumPThreadSpec * spec);
static void gum_enumerate_threads (GumPThreadSpec * spec,
    GumFoundThreadFunc func, gpointer user_data);

static gboolean gum_compute_pthread_spec (GumPThreadSpec * spec);
#if defined (HAVE_GLIBC)
static gboolean gum_detect_rtld_globals (GumPThreadSpec * spec);
static gboolean gum_find_thread_start (const GumSystemTapProbeDetails * probe,
    gpointer user_data);

static void glibc_lock_acquire (GumGlibcLock * lock);
static void glibc_lock_release (GumGlibcLock * lock);

static gint gum_ptr_compare (gconstpointer a, gconstpointer b);
#endif

static GumThreadRegistry * gum_registry;
static GumPThreadSpec gum_pthread;

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_start_handler;
static GumInvocationListener * gum_terminate_handler;
static GumInvocationListener * gum_rename_handler = NULL;

static int (* gum_pthread_getname_np) (pthread_t thread, char * name,
    size_t size);

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  GumModule * libc;
  gpointer setname_impl;

  gum_registry = self;

  if (!gum_compute_pthread_spec (&gum_pthread))
    g_error ("Unsupported Linux system; please file a bug");

  libc = gum_process_get_libc_module ();
  gum_pthread_getname_np = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        libc, "pthread_getname_np"));
  setname_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        libc, "pthread_setname_np"));

  gum_start_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_start, gum_registry, NULL);
  gum_terminate_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_terminate, gum_registry, NULL);
  if (setname_impl != NULL)
  {
    gum_rename_handler = gum_make_probe_listener (
        gum_thread_registry_on_pthread_setname, gum_registry, NULL);
  }

  gum_thread_interceptor = gum_interceptor_obtain ();
  gum_interceptor_begin_transaction (gum_thread_interceptor);

  gum_lock_thread_list (&gum_pthread);

  gum_interceptor_attach (gum_thread_interceptor, gum_pthread.start_impl,
      gum_start_handler, NULL);
  gum_interceptor_attach (gum_thread_interceptor, gum_pthread.terminate_impl,
      gum_terminate_handler, NULL);
  if (setname_impl != NULL)
  {
    gum_interceptor_attach (gum_thread_interceptor, setname_impl,
        gum_rename_handler, NULL);
  }

  gum_interceptor_end_transaction (gum_thread_interceptor);

  gum_enumerate_threads (&gum_pthread, gum_add_existing_thread, gum_registry);

  gum_unlock_thread_list (&gum_pthread);
}

void
_gum_thread_registry_deactivate (GumThreadRegistry * self)
{
  GumInvocationListener ** handlers[] = {
    &gum_start_handler,
    &gum_rename_handler,
    &gum_terminate_handler,
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (handlers); i++)
  {
    GumInvocationListener ** handler = handlers[i];

    if (*handler != NULL)
    {
      gum_interceptor_detach (gum_thread_interceptor, *handler);

      g_object_unref (*handler);
      *handler = NULL;
    }
  }

  g_clear_object (&gum_thread_interceptor);
}

static gboolean
gum_add_existing_thread (const GumThreadDetails * thread,
                         gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_register (registry, thread);

  return TRUE;
}

static void
gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
                                      gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  GumThreadDetails thread;
  gpointer storage;

  gum_compute_thread_details_from_pthread (GSIZE_TO_POINTER (pthread_self ()),
      &gum_pthread, &thread, &storage);

  _gum_thread_registry_register (registry, &thread);

  g_free (storage);
}

static void
gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
                                          gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_unregister (registry,
      gum_process_get_current_thread_id ());
}

static void
gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
                                        gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  GumPThread * thread;
  const char * name;

  thread = gum_invocation_context_get_nth_argument (ic, 0);
  name = gum_invocation_context_get_nth_argument (ic, 1);

  _gum_thread_registry_rename (registry, thread->tid, name);
}

static void
gum_compute_thread_details_from_pthread (GumPThread * thread,
                                         const GumPThreadSpec * spec,
                                         GumThreadDetails * details,
                                         gpointer * storage)
{
  gchar * name;

  bzero (details, sizeof (GumThreadDetails));
  *storage = NULL;

  details->id = thread->tid;

  details->name = NULL;
  if (gum_pthread_getname_np != NULL)
  {
    gsize name_max_size = 64;

    name = g_malloc (name_max_size);
    gum_pthread_getname_np (GPOINTER_TO_SIZE (thread), name, name_max_size);
    if (name[0] != '\0')
    {
      details->name = name;
      *storage = g_steal_pointer (&name);
    }
  }
  else
  {
    name = gum_linux_query_thread_name (thread->tid);
    if (name != NULL)
    {
      details->name = name;
      *storage = g_steal_pointer (&name);
    }
  }
  if (details->name != NULL)
    details->flags |= GUM_THREAD_FLAGS_NAME;

  details->entrypoint.routine = GUM_ADDRESS (
      *((gpointer *) ((guint8 *) thread + spec->start_routine_offset)));
  details->entrypoint.parameter = GUM_ADDRESS (
      *((gpointer *) ((guint8 *) thread + spec->start_parameter_offset)));
  if (details->entrypoint.routine != 0)
  {
    details->flags |=
        GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE |
        GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER;
  }

  g_free (name);
}

#if defined (HAVE_GLIBC)

static void
gum_lock_thread_list (GumPThreadSpec * spec)
{
  glibc_lock_acquire (spec->stack_lock);
}

static void
gum_unlock_thread_list (GumPThreadSpec * spec)
{
  glibc_lock_release (spec->stack_lock);
}

static void
gum_enumerate_threads (GumPThreadSpec * spec,
                       GumFoundThreadFunc func,
                       gpointer user_data)
{
  GumGlibcList * lists[] = {
    spec->stack_user,
    spec->stack_used,
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (lists); i++)
  {
    GumGlibcList * list = lists[i];
    GumGlibcList * cur;

    for (cur = list->prev; cur != list; cur = cur->prev)
    {
      GumPThread * pth = (GumPThread *)
          ((gchar *) cur - G_STRUCT_OFFSET (GumPThread, list));
      GumThreadDetails thread;
      gpointer storage;
      gboolean carry_on;

      gum_compute_thread_details_from_pthread (pth, spec, &thread, &storage);

      carry_on = func (&thread, user_data);

      g_free (storage);

      if (!carry_on)
        return;
    }
  }
}

static gboolean
gum_compute_pthread_spec (GumPThreadSpec * spec)
{
  if (!gum_detect_rtld_globals (spec))
    return FALSE;

  spec->start_impl = NULL;
  gum_system_tap_enumerate_probes (gum_process_get_libc_module (),
      gum_find_thread_start, spec);
  if (spec->start_impl == NULL)
    return FALSE;

  spec->terminate_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_get_libc_module (), "__call_tls_dtors"));
  return spec->terminate_impl != NULL;
}

static gboolean
gum_detect_rtld_globals (GumPThreadSpec * spec)
{
  gboolean success = FALSE;
  gpointer create_prologue;
#ifdef HAVE_ARM
  gboolean is_thumb;
#endif
  csh capstone;
  const uint8_t * code;
  size_t size;
  cs_insn * insn;
  uint64_t addr;
  guint stack_lock_offset;
  GPtrArray * offsets;

  create_prologue = GSIZE_TO_POINTER (gum_module_find_symbol_by_name (
        gum_process_get_libc_module (), "pthread_create@GLIBC_2.2.5"));

  gum_cs_arch_register_native ();
#ifdef HAVE_ARM
  is_thumb = (GPOINTER_TO_SIZE (create_prologue) & 1) != 0;
  cs_open (GUM_DEFAULT_CS_ARCH,
      is_thumb
        ? CS_MODE_THUMB | CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN
        : GUM_DEFAULT_CS_MODE,
      &capstone);
  code = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (create_prologue) & ~1);
#else
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone);
  code = create_prologue;
#endif
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  code += gum_interceptor_detect_hook_size (code, capstone, insn);
  size = 16384;
  addr = GPOINTER_TO_SIZE (code);

  insn = cs_malloc (capstone);

  stack_lock_offset = 0;
  offsets = g_ptr_array_sized_new (4);

#if defined (HAVE_I386)
  {
    while (offsets->len != 3 &&
        cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_x86 * x86 = &insn->detail->x86;

      switch (insn->id)
      {
        case X86_INS_CMPXCHG:
        {
          const cs_x86_op * dst = &x86->operands[0];

          if (stack_lock_offset == 0 && dst->mem.base != X86_REG_RIP)
            stack_lock_offset = dst->mem.disp;

          break;
        }
        case X86_INS_LEA:
        {
          const cs_x86_op * src = &x86->operands[1];
          int64_t disp = src->mem.disp;

          if (src->mem.base != X86_REG_RIP &&
              src->mem.base != X86_REG_RBP &&
              disp < stack_lock_offset &&
              disp >= stack_lock_offset - 128)
          {
            if (!g_ptr_array_find (offsets, GSIZE_TO_POINTER (disp), NULL))
              g_ptr_array_add (offsets, GSIZE_TO_POINTER (disp));
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

  g_ptr_array_sort (offsets, gum_ptr_compare);

  if (offsets->len == 3)
  {
    guint stack_used_offset, stack_user_offset;
    gpointer rtld_global;

    stack_used_offset = GPOINTER_TO_UINT (g_ptr_array_index (offsets, 0));
    stack_user_offset = GPOINTER_TO_UINT (g_ptr_array_index (offsets, 1));

    rtld_global = GSIZE_TO_POINTER (
        gum_module_find_global_export_by_name ("_rtld_global"));

    spec->stack_used = (GumGlibcList *)
        ((guint8 *) rtld_global + stack_used_offset);
    spec->stack_user = (GumGlibcList *)
        ((guint8 *) rtld_global + stack_user_offset);
    spec->stack_lock = (GumGlibcLock *)
        ((guint8 *) rtld_global + stack_lock_offset);

    success = TRUE;
  }

  g_ptr_array_unref (offsets);

  cs_free (insn, 1);

  cs_close (&capstone);

  return success;
}

static gboolean
gum_find_thread_start (const GumSystemTapProbeDetails * probe,
                       gpointer user_data)
{
  GumPThreadSpec * spec = user_data;

  if (strcmp (probe->name, "pthread_start") == 0)
  {
    gchar ** args;

    spec->start_impl = GSIZE_TO_POINTER (probe->address);

    args = g_strsplit (probe->args, " ", 0);
    spec->start_routine_offset = atoi (strchr (args[1], '@') + 1);
    spec->start_parameter_offset = atoi (strchr (args[2], '@') + 1);
    g_strfreev (args);

    return FALSE;
  }

  return TRUE;
}

static void
glibc_lock_acquire (GumGlibcLock * lock)
{
  if (!__sync_bool_compare_and_swap (lock, 0, 1))
  {
    if (__atomic_load_n (lock, __ATOMIC_RELAXED) == 2)
      goto wait;

    while (__atomic_exchange_n (lock, 2, __ATOMIC_ACQUIRE) != 0)
    {
wait:
      syscall (SYS_futex, lock, FUTEX_WAIT_PRIVATE, 2, NULL);
    }
  }
}

static void
glibc_lock_release (GumGlibcLock * lock)
{
  if (__atomic_exchange_n (lock, 0, __ATOMIC_RELEASE) != 1)
    syscall (SYS_futex, lock, FUTEX_WAKE_PRIVATE, 1);
}

static gint
gum_ptr_compare (gconstpointer a,
                 gconstpointer b)
{
  const gpointer * ptr_a = a;
  const gpointer * ptr_b = b;

  return GPOINTER_TO_INT (*ptr_a) - GPOINTER_TO_INT (*ptr_b);
}

#elif defined (HAVE_ANDROID)

static void
gum_lock_thread_list (GumPThreadSpec * spec)
{
  pthread_rwlock_rdlock (spec->thread_list_lock);
}

static void
gum_unlock_thread_list (GumPThreadSpec * spec)
{
  pthread_rwlock_unlock (spec->thread_list_lock);
}

static void
gum_enumerate_threads (GumPThreadSpec * spec,
                       GumFoundThreadFunc func,
                       gpointer user_data)
{
  GumPThread * tail, * cur;

  for (tail = NULL, cur = *spec->thread_list; cur != NULL; cur = cur->next)
    tail = cur;

  for (cur = tail; cur != NULL; cur = cur->prev)
  {
    GumThreadDetails thread;
    gpointer storage;
    gboolean carry_on;

    gum_compute_thread_details_from_pthread (cur, spec, &thread, &storage);

    carry_on = func (&thread, user_data);

    g_free (storage);

    if (!carry_on)
      return;
  }
}

static gboolean
gum_compute_pthread_spec (GumPThreadSpec * spec)
{
  GumModule * libc;
  gpointer start_prologue;
#ifdef HAVE_ARM
  gboolean is_thumb;
#endif
  csh capstone;
  const uint8_t * code;
  size_t size;
  cs_insn * insn;
  uint64_t addr;

  libc = gum_process_get_libc_module ();

  spec->thread_list = GSIZE_TO_POINTER (gum_module_find_symbol_by_name (libc,
      "_ZL13g_thread_list"));
  spec->thread_list_lock = GSIZE_TO_POINTER (gum_module_find_symbol_by_name (
        libc, "_ZL18g_thread_list_lock"));
  if (spec->thread_list == NULL || spec->thread_list_lock == NULL)
    return FALSE;

  start_prologue = GSIZE_TO_POINTER (gum_module_find_symbol_by_name (libc,
        "_ZL15__pthread_startPv"));
  if (start_prologue == NULL)
    return FALSE;

  gum_cs_arch_register_native ();
#ifdef HAVE_ARM
  is_thumb = (GPOINTER_TO_SIZE (start_prologue) & 1) != 0;
  cs_open (GUM_DEFAULT_CS_ARCH,
      is_thumb
        ? CS_MODE_THUMB | CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN
        : GUM_DEFAULT_CS_MODE,
      &capstone);
  code = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (start_prologue) & ~1);
#else
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone);
  code = start_prologue;
#endif
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  code += gum_interceptor_detect_hook_size (code, capstone, insn);
  size = 1024;
  addr = GPOINTER_TO_SIZE (code);

  insn = cs_malloc (capstone);

  spec->start_impl = NULL;
  spec->start_routine_offset = 0;
  spec->start_parameter_offset = 0;

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_CS_XSP_REG X86_REG_ESP
#  define GUM_CS_XBP_REG X86_REG_EBP
# else
#  define GUM_CS_XSP_REG X86_REG_RSP
#  define GUM_CS_XBP_REG X86_REG_RBP
# endif
  {
    gpointer mov_location = NULL;

    while (spec->start_impl == NULL &&
        cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_x86 * x86 = &insn->detail->x86;

      switch (insn->id)
      {
        case X86_INS_MOV:
        {
          const cs_x86_op * src = &x86->operands[1];

          if (src->type == X86_OP_MEM &&
              src->mem.segment == X86_REG_INVALID &&
              src->mem.base != GUM_CS_XSP_REG &&
              src->mem.base != GUM_CS_XBP_REG &&
              src->mem.index == X86_REG_INVALID)
          {
            mov_location = (gpointer) (code - insn->size);
            spec->start_parameter_offset = src->mem.disp;
          }

          break;
        }
        case X86_INS_CALL:
        {
          const cs_x86_op * target = &x86->operands[0];

          if (target->type == X86_OP_MEM && mov_location != NULL)
          {
            spec->start_impl = mov_location;
            spec->start_routine_offset = target->mem.disp;
          }

          break;
        }
        default:
          break;
      }
    }
  }
#elif defined (HAVE_ARM)
  {
    gpointer ldrd_location = NULL;
    arm_reg func_reg = ARM_REG_INVALID;

    while (spec->start_impl == NULL &&
        cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_arm * arm = &insn->detail->arm;

      switch (insn->id)
      {
        case ARM_INS_LDRD:
          ldrd_location = (gpointer) (code - insn->size);
          func_reg = arm->operands[0].reg;
          spec->start_routine_offset = arm->operands[2].mem.disp;
          spec->start_parameter_offset = spec->start_routine_offset + 4;
          break;
        case ARM_INS_BLX:
          if (arm->operands[0].type == ARM_OP_REG &&
              arm->operands[0].reg == func_reg)
          {
            spec->start_impl = is_thumb
                ? GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ldrd_location) | 1)
                : ldrd_location;
          }
          break;
        default:
          break;
      }
    }
  }
#elif defined (HAVE_ARM64)
  {
    gpointer ldp_location = NULL;
    arm64_reg func_reg = ARM64_REG_INVALID;

    while (spec->start_impl == NULL &&
        cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_arm64 * arm64 = &insn->detail->arm64;

      switch (insn->id)
      {
        case ARM64_INS_LDP:
          ldp_location = (gpointer) (code - insn->size);
          func_reg = arm64->operands[0].reg;
          spec->start_routine_offset = arm64->operands[2].mem.disp;
          spec->start_parameter_offset = spec->start_routine_offset + 8;
          break;
        case ARM64_INS_BLR:
          if (arm64->operands[0].reg == func_reg)
            spec->start_impl = ldp_location;
          break;
        default:
          break;
      }
    }
  }
#else
# error Unsupported architecture
#endif

  cs_free (insn, 1);

  cs_close (&capstone);

  if (spec->start_impl == NULL)
    return FALSE;

  spec->terminate_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (libc,
        "pthread_exit"));

  return spec->terminate_impl != NULL;
}

#endif
