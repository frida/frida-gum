/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptorbackend.h"

#include "gum/gumwindows.h"
#include "gumarm64writer.h"
#include "gumx86writer.h"

#include <capstone.h>
#include <tchar.h>

#ifndef GUM_DIET

typedef BOOL (WINAPI * GumWindowsExceptionHandler) (
    EXCEPTION_RECORD * exception_record, CONTEXT * context);

struct _GumExceptorBackend
{
  GObject parent;

  GumExceptionHandler handler;
  gpointer handler_data;

  GumWindowsExceptionHandler system_handler;

  gpointer dispatcher_impl;
#ifdef HAVE_ARM64
  guint32 * dispatcher_impl_bl;
#else
  gint32 * dispatcher_impl_call_immediate;
#endif
  DWORD previous_page_protection;

  gpointer trampoline;
};

static void gum_exceptor_backend_finalize (GObject * object);

static BOOL gum_exceptor_backend_dispatch (EXCEPTION_RECORD * exception_record,
    CONTEXT * context);

G_DEFINE_TYPE (GumExceptorBackend, gum_exceptor_backend, G_TYPE_OBJECT)

static GumExceptorBackend * the_backend = NULL;

#endif

void
_gum_exceptor_backend_prepare_to_fork (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_parent (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_child (void)
{
}

#ifndef GUM_DIET

static void
gum_exceptor_backend_class_init (GumExceptorBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_exceptor_backend_finalize;
}

static void
gum_exceptor_backend_init (GumExceptorBackend * self)
{
  HMODULE ntdll_mod;
  csh capstone;
  G_GNUC_UNUSED cs_err err;
  guint offset;

  the_backend = self;

  ntdll_mod = GetModuleHandle (_T ("ntdll.dll"));
  g_assert (ntdll_mod != NULL);

  self->dispatcher_impl = GUM_FUNCPTR_TO_POINTER (
      GetProcAddress (ntdll_mod, "KiUserExceptionDispatcher"));
  g_assert (self->dispatcher_impl != NULL);

  gum_cs_arch_register_native ();
  err = cs_open (GUM_DEFAULT_CS_ARCH, GUM_CPU_MODE, &capstone);
  g_assert (err == CS_ERR_OK);
  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  offset = 0;
  while (self->system_handler == NULL)
  {
    cs_insn * insn = NULL;

    cs_disasm (capstone,
        (guint8 *) self->dispatcher_impl + offset, 16,
        GPOINTER_TO_SIZE (self->dispatcher_impl) + offset,
        1, &insn);
    g_assert (insn != NULL);

    offset += insn->size;

#ifdef HAVE_ARM64
    if (insn->id == ARM64_INS_BL)
    {
      guint32 * bl = GSIZE_TO_POINTER (insn->address);
      cs_arm64_op * op = &insn->detail->arm64.operands[0];
      gssize distance;

      self->system_handler = GUM_POINTER_TO_FUNCPTR (
          GumWindowsExceptionHandler, op->imm);

      VirtualProtect (self->dispatcher_impl, 4096,
          PAGE_EXECUTE_READWRITE, &self->previous_page_protection);
      self->dispatcher_impl_bl = bl;

      distance = (gssize) gum_exceptor_backend_dispatch - (gssize) bl;
      if (!GUM_IS_WITHIN_INT28_RANGE (distance))
      {
        GumAddressSpec as;
        GumArm64Writer cw;

        as.near_address = self->dispatcher_impl;
        as.max_distance = G_MAXINT32 - 16384;
        self->trampoline = gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &as);

        gum_arm64_writer_init (&cw, self->trampoline);
        gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_X8,
            GUM_ADDRESS (gum_exceptor_backend_dispatch));
        gum_arm64_writer_put_br_reg (&cw, ARM64_REG_X8);
        gum_arm64_writer_clear (&cw);

        distance = (gssize) self->trampoline - (gssize) bl;
      }

      *bl = (*bl & ~GUM_INT26_MASK) | ((distance / 4) & GUM_INT26_MASK);
    }
#else
    if (insn->id == X86_INS_CALL)
    {
      cs_x86_op * op = &insn->detail->x86.operands[0];
      if (op->type == X86_OP_IMM)
      {
        guint8 * call_start, * call_end;
        gssize distance;

        call_start = GSIZE_TO_POINTER (insn->address);
        call_end = call_start + insn->size;

        self->system_handler = GUM_POINTER_TO_FUNCPTR (
            GumWindowsExceptionHandler, op->imm);

        VirtualProtect (self->dispatcher_impl, 4096,
            PAGE_EXECUTE_READWRITE, &self->previous_page_protection);
        self->dispatcher_impl_call_immediate = (gint32 *) (call_start + 1);

        distance = (gssize) gum_exceptor_backend_dispatch - (gssize) call_end;
        if (!GUM_IS_WITHIN_INT32_RANGE (distance))
        {
          GumAddressSpec as;
          GumX86Writer cw;

          as.near_address = self->dispatcher_impl;
          as.max_distance = G_MAXINT32 - 16384;
          self->trampoline = gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &as);

          gum_x86_writer_init (&cw, self->trampoline);
          gum_x86_writer_put_jmp_address (&cw,
              GUM_ADDRESS (gum_exceptor_backend_dispatch));
          gum_x86_writer_clear (&cw);

          distance = (gssize) self->trampoline - (gssize) call_end;
        }

        *self->dispatcher_impl_call_immediate = distance;
      }
    }
#endif

    cs_free (insn, 1);
  }

  cs_close (&capstone);
}

static void
gum_exceptor_backend_finalize (GObject * object)
{
  GumExceptorBackend * self = GUM_EXCEPTOR_BACKEND (object);
  DWORD prot;

#ifdef HAVE_ARM64
  gssize distance;

  distance = (gssize) self->system_handler - (gssize) self->dispatcher_impl_bl;

  *self->dispatcher_impl_bl = (*self->dispatcher_impl_bl & ~GUM_INT26_MASK) |
      ((distance / 4) & GUM_INT26_MASK);
  self->dispatcher_impl_bl = NULL;
#else
  *self->dispatcher_impl_call_immediate =
      (gssize) self->system_handler -
      (gssize) (self->dispatcher_impl_call_immediate + 1);
  self->dispatcher_impl_call_immediate = NULL;
#endif

  VirtualProtect (self->dispatcher_impl, 4096,
      self->previous_page_protection, &prot);

  self->system_handler = NULL;

  self->dispatcher_impl = NULL;
  self->previous_page_protection = 0;

  g_clear_pointer (&self->trampoline, gum_free_pages);

  the_backend = NULL;

  G_OBJECT_CLASS (gum_exceptor_backend_parent_class)->finalize (object);
}

GumExceptorBackend *
gum_exceptor_backend_new (GumExceptionHandler handler,
                          gpointer user_data)
{
  GumExceptorBackend * backend;

  backend = g_object_new (GUM_TYPE_EXCEPTOR_BACKEND, NULL);
  backend->handler = handler;
  backend->handler_data = user_data;

  return backend;
}

static BOOL
gum_exceptor_backend_dispatch (EXCEPTION_RECORD * exception_record,
                               CONTEXT * context)
{
  GumExceptorBackend * self = the_backend;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  GumWindowsExceptionHandler system_handler;

  ed.thread_id = gum_process_get_current_thread_id ();

  switch (exception_record->ExceptionCode)
  {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;
      break;
    case EXCEPTION_GUARD_PAGE:
      ed.type = GUM_EXCEPTION_GUARD_PAGE;
      break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
      ed.type = GUM_EXCEPTION_ILLEGAL_INSTRUCTION;
      break;
    case EXCEPTION_STACK_OVERFLOW:
      ed.type = GUM_EXCEPTION_STACK_OVERFLOW;
      break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
      ed.type = GUM_EXCEPTION_ARITHMETIC;
      break;
    case EXCEPTION_BREAKPOINT:
      ed.type = GUM_EXCEPTION_BREAKPOINT;
      break;
    case EXCEPTION_SINGLE_STEP:
      ed.type = GUM_EXCEPTION_SINGLE_STEP;
      break;
    default:
      ed.type = GUM_EXCEPTION_SYSTEM;
      break;
  }

  ed.address = exception_record->ExceptionAddress;

  switch (exception_record->ExceptionCode)
  {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_GUARD_PAGE:
    case EXCEPTION_IN_PAGE_ERROR:
      switch (exception_record->ExceptionInformation[0])
      {
        case 0:
          md->operation = GUM_MEMOP_READ;
          break;
        case 1:
          md->operation = GUM_MEMOP_WRITE;
          break;
        case 8:
          md->operation = GUM_MEMOP_EXECUTE;
          break;
        default:
          md->operation = GUM_MEMOP_INVALID;
          break;
      }
      md->address =
          GSIZE_TO_POINTER (exception_record->ExceptionInformation[1]);
      break;
    default:
      md->operation = GUM_MEMOP_INVALID;
      md->address = 0;
      break;
  }

  gum_windows_parse_context (context, cpu_context);
  ed.native_context = context;

  if (self->handler (&ed, self->handler_data))
  {
    gum_windows_unparse_context (cpu_context, context);
    return TRUE;
  }

  system_handler = self->system_handler;

  return system_handler (exception_record, context);
}

#endif
