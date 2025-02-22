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
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

typedef struct _GumPThreadSpec GumPThreadSpec;
typedef struct _GumGlibcThread GumGlibcThread;
typedef struct _GumGlibcList GumGlibcList;
typedef int GumGlibcLock;

struct _GumPThreadSpec
{
  guint lock_offset;

  gpointer start_impl;
  guint start_routine_offset;
  guint start_arg_offset;

  gpointer terminate_impl;
};

struct _GumGlibcList
{
  GumGlibcList * next;
  GumGlibcList * prev;
};

struct _GumGlibcThread
{
  union
  {
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    guint8 tcb_header[704];
#endif
    gpointer padding[24];
  } header;
  GumGlibcList list;
  pid_t tid;
};

static gpointer hello_proc (gpointer data);
static gpointer hello2_proc (gpointer data);
static void gum_add_existing_threads (GumThreadRegistry * registry);
static void gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
    gpointer user_data);

static gboolean gum_compute_pthread_spec (GumPThreadSpec * spec);
#ifndef HAVE_ANDROID
static gboolean gum_detect_rtld_global_offsets (GumPThreadSpec * spec);
static gboolean gum_find_thread_start (const GumSystemTapProbeDetails * probe,
    gpointer user_data);
#endif

static void glibc_lock_acquire (GumGlibcLock * lock);
static void glibc_lock_release (GumGlibcLock * lock);

static GumThreadRegistry * gum_registry;
static GumPThreadSpec gum_pthread;

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_start_handler = NULL;
static GumInvocationListener * gum_rename_handler = NULL;
static GumInvocationListener * gum_terminate_handler = NULL;

static int (* gum_pthread_getname_np) (pthread_t thread, char * name,
    size_t size);

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  GumModule * libc;
  gpointer setname_impl;

  gum_registry = self;

  g_thread_unref (g_thread_new ("hello", hello_proc, GSIZE_TO_POINTER (1337)));

  if (!gum_compute_pthread_spec (&gum_pthread))
    g_error ("Unsupported Linux system; please file a bug");

  g_printerr ("Found libc at %p\n",
      GSIZE_TO_POINTER (gum_module_get_range (gum_process_get_libc_module ())->base_address));
  g_printerr ("Using start_impl=libc!0x%x terminate_impl=libc!0x%x start_routine_offset=0x%x start_arg_offset=0x%x\n",
      (guint) (GUM_ADDRESS (gum_pthread.start_impl) - gum_module_get_range (gum_process_get_libc_module ())->base_address),
      (guint) (GUM_ADDRESS (gum_pthread.terminate_impl) - gum_module_get_range (gum_process_get_libc_module ())->base_address),
      gum_pthread.start_routine_offset,
      gum_pthread.start_arg_offset);

  gum_thread_interceptor = gum_interceptor_obtain ();

  gum_start_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_start, gum_registry, NULL);
  gum_interceptor_attach (gum_thread_interceptor, gum_pthread.start_impl,
      gum_start_handler, NULL);

  gum_terminate_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_terminate, gum_registry, NULL);
  gum_interceptor_attach (gum_thread_interceptor, gum_pthread.terminate_impl,
      gum_terminate_handler, NULL);

  libc = gum_process_get_libc_module ();

  gum_pthread_getname_np = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        libc, "pthread_getname_np"));
  setname_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        libc, "pthread_setname_np"));

  if (setname_impl != NULL)
  {
    gum_rename_handler = gum_make_probe_listener (
        gum_thread_registry_on_pthread_setname, gum_registry, NULL);
    gum_interceptor_attach (gum_thread_interceptor, setname_impl,
        gum_rename_handler, NULL);
  }

  gum_add_existing_threads (gum_registry);
}

static gpointer
hello_proc (gpointer data)
{
  g_thread_unref (g_thread_new ("hello", hello2_proc, GSIZE_TO_POINTER (1337)));

  while (TRUE)
  {
    g_printerr ("Hello! TID=%d\n", gettid ());
    g_usleep (G_USEC_PER_SEC);
  }

  return NULL;
}

static gpointer
hello2_proc (gpointer data)
{
  while (TRUE)
  {
    g_printerr ("Hello2! TID=%d\n", gettid ());
    g_usleep (G_USEC_PER_SEC);
  }

  return NULL;
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

static void
gum_add_existing_threads (GumThreadRegistry * registry)
{
  gpointer rtld_global;
  GumGlibcList * stack_used, * stack_user, * cur;
  GumGlibcLock * lock;
  GDir * dir;
  const gchar * name;
  gboolean carry_on = TRUE;

  dir = g_dir_open ("/proc/self/task", 0, NULL);
  g_assert (dir != NULL);

  rtld_global =
      GSIZE_TO_POINTER (gum_module_find_global_export_by_name ("_rtld_global"));

  stack_used = (GumGlibcList *) ((guint8 *) rtld_global + 0x10b8);
  stack_user = (GumGlibcList *) ((guint8 *) rtld_global + 0x10c8);
  lock = (GumGlibcLock *) ((guint8 *) rtld_global + 0x10f8);

  glibc_lock_acquire (lock);

  for (cur = stack_used->next; cur != stack_used; cur = cur->next)
  {
    GumGlibcThread * thread = (GumGlibcThread *)
        ((gchar *) cur - G_STRUCT_OFFSET (GumGlibcThread, list));

    g_printerr ("[stack_used] Found pthread_t %p with TID %u\n", thread, thread->tid);
  }

  for (cur = stack_user->next; cur != stack_user; cur = cur->next)
  {
    GumGlibcThread * thread = (GumGlibcThread *)
        ((gchar *) cur - G_STRUCT_OFFSET (GumGlibcThread, list));

    g_printerr ("[stack_user] Found pthread_t %p with TID %u\n", thread, thread->tid);
  }

  glibc_lock_release (lock);

  while (carry_on && (name = g_dir_read_name (dir)) != NULL)
  {
    GumThreadDetails t;

    t.id = atoi (name);
    t.name = gum_linux_query_thread_name (t.id);
    t.state = GUM_THREAD_RUNNING;
    bzero (&t.cpu_context, sizeof (GumCpuContext));

    _gum_thread_registry_register (registry, &t, NULL, NULL);

    g_free ((gpointer) t.name);
  }

  g_dir_close (dir);
}

static void
gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
                                      gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  pthread_t thread;
  GumThreadDetails t;
  gchar name[64];
  gchar * name_malloc_data = NULL;
  gpointer routine, arg;

  thread = pthread_self ();
  g_printerr ("\n=== %s thread=0x%lx\n", G_STRFUNC, thread);

  t.id = gum_process_get_current_thread_id ();

  t.name = NULL;
  if (gum_pthread_getname_np != NULL)
  {
    gum_pthread_getname_np (thread, name, sizeof (name));
    if (name[0] != '\0')
      t.name = name;
  }
  else
  {
    name_malloc_data = gum_linux_query_thread_name (t.id);
    t.name = name_malloc_data;
  }

  t.state = GUM_THREAD_RUNNING;

  bzero (&t.cpu_context, sizeof (GumCpuContext));

  routine =
      *((gpointer *) ((guint8 *) thread + gum_pthread.start_routine_offset));
  arg = *((gpointer *) ((guint8 *) thread + gum_pthread.start_arg_offset));

  _gum_thread_registry_register (registry, &t, routine, arg);

  g_free (name_malloc_data);
}

static void
gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
                                        gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  pthread_t thread;
  const char * name;
  GumThreadId id;

  thread = GPOINTER_TO_SIZE (gum_invocation_context_get_nth_argument (ic, 0));
  name = gum_invocation_context_get_nth_argument (ic, 1);

  /* XXX: Should we handle rename from a different thread? */
  if (thread != pthread_self ())
    return;

  id = gum_process_get_current_thread_id ();

  _gum_thread_registry_rename (registry, id, name);
}

static void
gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
                                          gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_unregister (registry,
      gum_process_get_current_thread_id ());
}

#ifdef HAVE_ANDROID

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

  size = 1024;
  addr = GPOINTER_TO_SIZE (code);

  insn = cs_malloc (capstone);

  spec->start_impl = NULL;
  spec->start_routine_offset = 0;
  spec->start_arg_offset = 0;

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
            spec->start_arg_offset = src->mem.disp;
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
          spec->start_arg_offset = spec->start_routine_offset + 4;
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
          spec->start_arg_offset = spec->start_routine_offset + 8;
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

#else

static gboolean
gum_compute_pthread_spec (GumPThreadSpec * spec)
{
  gum_detect_rtld_global_offsets (spec);

  spec->start_impl = NULL;
  gum_system_tap_enumerate_probes (gum_process_get_libc_module (),
      gum_find_thread_start, &spec->start_impl);
  if (spec->start_impl == NULL)
    return FALSE;

  spec->terminate_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_get_libc_module (), "__call_tls_dtors"));
  return spec->terminate_impl != NULL;
}

static gboolean
gum_detect_rtld_global_offsets (GumPThreadSpec * spec)
{
  GumModule * libc;
  guint8 * libc_base;
  gpointer create_prologue;
#ifdef HAVE_ARM
  gboolean is_thumb;
#endif
  csh capstone;
  const uint8_t * code;
  size_t size;
  cs_insn * insn;
  uint64_t addr;

  libc = gum_process_get_libc_module ();
  libc_base = GSIZE_TO_POINTER (gum_module_get_range (libc)->base_address);

  create_prologue = GSIZE_TO_POINTER (gum_module_find_symbol_by_name (libc,
        "pthread_create@GLIBC_2.2.5"));
  g_printerr ("create_prologue=%p\n", create_prologue);

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

  size = 16384;
  addr = GPOINTER_TO_SIZE (code);

  insn = cs_malloc (capstone);

  spec->lock_offset = 0;

#if defined (HAVE_I386)
  {
    while (cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_x86 * x86 = &insn->detail->x86;

      switch (insn->id)
      {
        case X86_INS_CMPXCHG:
        {
          const cs_x86_op * dst = &x86->operands[0];

          if (spec->lock_offset == 0 &&
              dst->mem.base != X86_REG_RIP)
          {
            g_printerr ("libc!0x%lx\t%s %s\n", code - libc_base, insn->mnemonic,
                insn->op_str);
            spec->lock_offset = dst->mem.disp;
          }

          break;
        }
        case X86_INS_LEA:
        {
          const cs_x86_op * src = &x86->operands[1];

          if (src->mem.base != X86_REG_RIP &&
              src->mem.base != X86_REG_RBP &&
              src->mem.disp < spec->lock_offset &&
              spec->lock_offset - src->mem.disp <= 64)
          {
            g_printerr ("libc!0x%lx\t%s %s\n", code - libc_base, insn->mnemonic,
                insn->op_str);
          }

          break;
        }
        default:
          //g_printerr ("%s %s\n", insn->mnemonic, insn->op_str);
          break;
      }
    }

    g_printerr ("lost track at %p\n", code);
  }
#else
# error Unsupported architecture
#endif

  cs_free (insn, 1);

  cs_close (&capstone);

  return FALSE;
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
    spec->start_arg_offset = atoi (strchr (args[2], '@') + 1);
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

#endif
