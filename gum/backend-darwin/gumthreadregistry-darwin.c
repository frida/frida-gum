/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry-priv.h"

#include "gumdarwin-priv.h"
#include "guminterceptor.h"

#include <capstone.h>
#include <strings.h>
#include <os/lock.h>
#include <pthread/introspection.h>
#include <sys/queue.h>

typedef struct _GumPThreadSpec GumPThreadSpec;
typedef struct _GumPThreadList GumPThreadList;
typedef struct _GumPThread GumPThread;

TAILQ_HEAD (_GumPThreadList, _GumPThread);

struct _GumPThreadSpec
{
  struct _GumPThreadList * thread_list;
  os_unfair_lock_t thread_list_lock;

  guint mach_port_offset;
  guint name_offset;
  guint start_routine_offset;
  guint start_parameter_offset;
};

struct _GumPThread
{
  long sig;
  gpointer __cleanup_stack;
  TAILQ_ENTRY (_GumPThread) tl_plist;
};

typedef enum {
  GUM_OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION = 0x10000,
  GUM_OS_UNFAIR_LOCK_ADAPTIVE_SPIN        = 0x40000,
} GumUnfairLockOptions;

extern void os_unfair_lock_lock_with_options (os_unfair_lock_t lock,
    GumUnfairLockOptions options);

static gboolean gum_add_existing_thread (const GumThreadDetails * thread,
    gpointer user_data);
static void gum_thread_registry_on_thread_event (unsigned int event,
    pthread_t thread, void * addr, size_t size);
static void gum_thread_registry_on_setname (GumInvocationContext * ic,
    gpointer user_data);

static void gum_enumerate_threads (GumPThreadSpec * spec,
    GumFoundThreadFunc func, gpointer user_data);
static void gum_compute_thread_details_from_pthread (GumPThread * pthread,
    const GumPThreadSpec * spec, GumThreadDetails * details);
static gboolean gum_compute_pthread_spec (GumPThreadSpec * spec);
static gboolean gum_detect_pthread_basics (csh capstone, cs_insn * insn,
    GumPThreadSpec * spec);
static gboolean gum_detect_pthread_name_offset (csh capstone, cs_insn * insn,
    guint * name_offset);

static GumThreadRegistry * gum_registry;
static GumPThreadSpec gum_pthread;

static gboolean gum_hook_installed = FALSE;
static pthread_introspection_hook_t gum_previous_hook;

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_rename_handler;

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  gum_registry = self;

  if (!gum_compute_pthread_spec (&gum_pthread))
    g_error ("Unsupported Apple system; please file a bug");

  gum_rename_handler = gum_make_call_listener (NULL,
      gum_thread_registry_on_setname, gum_registry, NULL);

  gum_thread_interceptor = gum_interceptor_obtain ();

  os_unfair_lock_lock_with_options (gum_pthread.thread_list_lock,
      GUM_OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION |
      GUM_OS_UNFAIR_LOCK_ADAPTIVE_SPIN);

  gum_previous_hook =
      pthread_introspection_hook_install (gum_thread_registry_on_thread_event);
  gum_hook_installed = TRUE;

  gum_interceptor_attach (gum_thread_interceptor,
      GSIZE_TO_POINTER (gum_module_find_export_by_name (
          gum_process_get_libc_module (), "pthread_setname_np")),
      gum_rename_handler, NULL);

  gum_enumerate_threads (&gum_pthread, gum_add_existing_thread, gum_registry);

  os_unfair_lock_unlock (gum_pthread.thread_list_lock);
}

void
_gum_thread_registry_deactivate (GumThreadRegistry * self)
{
  if (gum_rename_handler != NULL)
  {
    gum_interceptor_detach (gum_thread_interceptor, gum_rename_handler);

    g_object_unref (gum_rename_handler);
    gum_rename_handler = NULL;

    g_object_unref (gum_thread_interceptor);
    gum_thread_interceptor = NULL;
  }

  if (gum_hook_installed)
  {
    (void) pthread_introspection_hook_install (gum_previous_hook);
    gum_previous_hook = NULL;

    gum_hook_installed = FALSE;
  }
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
gum_thread_registry_on_thread_event (unsigned int event,
                                     pthread_t thread,
                                     void * addr,
                                     size_t size)
{
  switch (event)
  {
    case PTHREAD_INTROSPECTION_THREAD_START:
    {
      GumThreadDetails t;

      gum_compute_thread_details_from_pthread ((GumPThread *) thread,
          &gum_pthread, &t);

      _gum_thread_registry_register (gum_registry, &t);

      break;
    }
    case PTHREAD_INTROSPECTION_THREAD_TERMINATE:
    {
      _gum_thread_registry_unregister (gum_registry,
          pthread_mach_thread_np (thread));
      break;
    }
    default:
      break;
  }

  if (gum_previous_hook != NULL)
    gum_previous_hook (event, thread, addr, size);
}

static void
gum_thread_registry_on_setname (GumInvocationContext * ic,
                                gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  pthread_t thread;
  GumThreadId id;
  const char * name;

  thread = pthread_self ();

  id = pthread_mach_thread_np (thread);

  name = (char *) pthread_self () + gum_pthread.name_offset;
  if (name[0] == '\0')
    name = NULL;

  _gum_thread_registry_rename (registry, id, name);
}

static void
gum_enumerate_threads (GumPThreadSpec * spec,
                       GumFoundThreadFunc func,
                       gpointer user_data)
{
  struct _GumPThread * pth = NULL;

  TAILQ_FOREACH (pth, spec->thread_list, tl_plist)
  {
    GumThreadDetails thread;

    gum_compute_thread_details_from_pthread (pth, spec, &thread);

    if (!func (&thread, user_data))
      return;
  }
}

static void
gum_compute_thread_details_from_pthread (GumPThread * thread,
                                         const GumPThreadSpec * spec,
                                         GumThreadDetails * details)
{
  const char * name;

  bzero (details, sizeof (GumThreadDetails));

  details->id = *((mach_port_t *) ((guint8 *) thread + spec->mach_port_offset));

  name = (char *) thread + spec->name_offset;
  if (name[0] != '\0')
  {
    details->name = name;
    details->flags |= GUM_THREAD_FLAGS_HAS_NAME;
  }

  details->entrypoint.routine = GUM_ADDRESS (
      *((gpointer *) ((guint8 *) thread + spec->start_routine_offset)));
  details->entrypoint.parameter = GUM_ADDRESS (
      *((gpointer *) ((guint8 *) thread + spec->start_parameter_offset)));
  if (details->entrypoint.routine != 0)
    details->flags |= GUM_THREAD_FLAGS_HAS_ENTRYPOINT;
}

static gboolean
gum_compute_pthread_spec (GumPThreadSpec * spec)
{
  gboolean success = FALSE;
  csh capstone;
  cs_insn * insn;

  gum_cs_arch_register_native ();
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

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
                           GumPThreadSpec * spec)
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

  code = pfmt_prologue;
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
              arm64->operands[1].type == ARM64_OP_MEM &&
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

  code = setname_prologue;
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
