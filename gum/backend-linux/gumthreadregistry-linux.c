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

#ifdef HAVE_ANDROID
# include <capstone.h>
#endif

typedef struct _GumPThreadSpec GumPThreadSpec;

struct _GumPThreadSpec
{
  gpointer start_impl;
  gpointer terminate_impl;
  guint thread_func_offset;
};

static void gum_add_existing_threads (GumThreadRegistry * registry);
static void gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
    gpointer user_data);

static gboolean gum_compute_pthread_spec (GumPThreadSpec * spec);
#ifdef HAVE_ANDROID
#else
static gboolean gum_find_thread_start (const GumSystemTapProbeDetails * probe,
    gpointer user_data);
#endif

static GumThreadRegistry * gum_registry;

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_start_handler = NULL;
static GumInvocationListener * gum_rename_handler = NULL;
static GumInvocationListener * gum_terminate_handler = NULL;

static int (* gum_pthread_getname_np) (pthread_t thread, char * name,
    size_t size);

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  GumPThreadSpec pthread;
  GumModule * libc;
  gpointer setname_impl;

  gum_registry = self;

  if (!gum_compute_pthread_spec (&pthread))
    g_error ("Unsupported Linux system; please file a bug");

  g_printerr ("Found libc at %p\n",
      GSIZE_TO_POINTER (gum_module_get_range (gum_process_get_libc_module ())->base_address));
  g_printerr ("Using start_impl=libc!0x%x terminate_impl=libc!0x%x thread_func_offset=0x%x\n",
      (guint) (GUM_ADDRESS (pthread.start_impl) - gum_module_get_range (gum_process_get_libc_module ())->base_address),
      (guint) (GUM_ADDRESS (pthread.terminate_impl) - gum_module_get_range (gum_process_get_libc_module ())->base_address),
      pthread.thread_func_offset);

  gum_thread_interceptor = gum_interceptor_obtain ();

  gum_start_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_start, gum_registry, NULL);
  gum_interceptor_attach (gum_thread_interceptor, pthread.start_impl,
      gum_start_handler, NULL);

  gum_terminate_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_terminate, gum_registry, NULL);
  gum_interceptor_attach (gum_thread_interceptor, pthread.terminate_impl,
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
  GDir * dir;
  const gchar * name;
  gboolean carry_on = TRUE;

  dir = g_dir_open ("/proc/self/task", 0, NULL);
  g_assert (dir != NULL);

  while (carry_on && (name = g_dir_read_name (dir)) != NULL)
  {
    GumThreadDetails t;

    t.id = atoi (name);
    t.name = gum_linux_query_thread_name (t.id);
    t.state = GUM_THREAD_RUNNING;
    bzero (&t.cpu_context, sizeof (GumCpuContext));

    _gum_thread_registry_register (registry, &t);

    g_free ((gpointer) t.name);
  }

  g_dir_close (dir);
}

static void
gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
                                      gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  GumThreadDetails t;
  gchar name[64];
  gchar * name_malloc_data = NULL;

  t.id = gum_process_get_current_thread_id ();

  t.name = NULL;
  if (gum_pthread_getname_np != NULL)
  {
    gum_pthread_getname_np (pthread_self (), name, sizeof (name));
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

  _gum_thread_registry_register (registry, &t);

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

  /* TODO: Support setting name from a different thread. */
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

#if defined (HAVE_I386)
  {
    gpointer mov_location = NULL;

    while (spec->start_impl == NULL &&
        cs_disasm_iter (capstone, &code, &size, &addr, insn))
    {
      const cs_x86 * x86 = &insn->detail->x86;

      switch (insn->id)
      {
        case X86_INS_MOV:
          mov_location = (gpointer) (code - insn->size);
          break;
        case X86_INS_CALL:
          if (x86->operands[0].type == X86_OP_MEM)
          {
            spec->start_impl = mov_location;
            spec->thread_func_offset = x86->operands[0].mem.disp;
          }
          break;
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
          spec->thread_func_offset = arm->operands[2].mem.disp;
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
          spec->thread_func_offset = arm64->operands[2].mem.disp;
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
  GumModule * libc;

  libc = gum_process_get_libc_module ();

  spec->start_impl = NULL;
  gum_system_tap_enumerate_probes (libc, gum_find_thread_start,
      &spec->start_impl);
  if (spec->start_impl == NULL)
    return FALSE;

  spec->thread_func_offset = 0; /* TODO */

  spec->terminate_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_get_libc_module (), "__call_tls_dtors"));
  return spec->terminate_impl != NULL;
}

static gboolean
gum_find_thread_start (const GumSystemTapProbeDetails * probe,
                       gpointer user_data)
{
  gpointer * start_impl = user_data;

  if (strcmp (probe->name, "pthread_start") == 0)
  {
    *start_impl = GSIZE_TO_POINTER (probe->address);
    return FALSE;
  }

  return TRUE;
}

#endif
