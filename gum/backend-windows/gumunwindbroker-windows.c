/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumunwindbroker-priv.h"

#include "guminterceptor.h"
#include "gum/gumwindows.h"

#include <capstone.h>

#define GUM_VIRTUAL_UNWIND_CONTEXT_ARG_INDEX 4

typedef BOOL (WINAPI * GumIsWow64Process2Func) (HANDLE process,
    USHORT * process_machine, USHORT * native_machine);

static gboolean gum_process_is_emulated (void);
static void gum_unwind_broker_on_virtual_unwind_enter (
    GumInvocationContext * ic, gpointer user_data);
static void gum_unwind_broker_on_virtual_unwind_leave (
    GumInvocationContext * ic, gpointer user_data);
static gpointer gum_find_virtual_unwind_impl (void);
static GumAddress gum_unwind_broker_translate_pc (GumAddress code_address);
static gpointer gum_find_last_direct_call_target (gconstpointer function);
static gboolean gum_call_is_direct (const cs_insn * insn);
static gpointer gum_get_call_target (const cs_insn * insn);

static GumInterceptor * gum_unwind_ntdll_interceptor = NULL;
static GumInvocationListener * gum_virtual_unwind_listener = NULL;

void
_gum_unwind_broker_backend_activate (void)
{
  GumAttachReturn res G_GNUC_UNUSED;

  if (gum_process_is_emulated ())
    return;

  gum_unwind_ntdll_interceptor = gum_interceptor_obtain ();
  gum_virtual_unwind_listener = gum_make_call_listener (
      gum_unwind_broker_on_virtual_unwind_enter,
      gum_unwind_broker_on_virtual_unwind_leave, NULL, NULL);

  res = gum_interceptor_attach (gum_unwind_ntdll_interceptor,
      gum_find_virtual_unwind_impl (), gum_virtual_unwind_listener, NULL);
  g_assert (res == GUM_ATTACH_OK);
}

void
_gum_unwind_broker_backend_deactivate (void)
{
  if (gum_unwind_ntdll_interceptor == NULL)
    return;

  gum_interceptor_detach (gum_unwind_ntdll_interceptor,
      gum_virtual_unwind_listener);

  g_clear_object (&gum_virtual_unwind_listener);
  g_clear_object (&gum_unwind_ntdll_interceptor);
}

static gboolean
gum_process_is_emulated (void)
{
#ifdef HAVE_I386
  GumIsWow64Process2Func is_wow64_process2;
  USHORT process_machine, native_machine;

  is_wow64_process2 = (GumIsWow64Process2Func) GetProcAddress (
      GetModuleHandleW (L"kernel32.dll"), "IsWow64Process2");
  if (is_wow64_process2 == NULL)
    return FALSE;

  is_wow64_process2 (GetCurrentProcess (), &process_machine, &native_machine);

  return native_machine != IMAGE_FILE_MACHINE_AMD64;
#else
  return FALSE;
#endif
}

static void
gum_unwind_broker_on_virtual_unwind_enter (GumInvocationContext * ic,
                                           gpointer user_data)
{
  PCONTEXT * context = GUM_IC_GET_INVOCATION_DATA (ic, PCONTEXT);

  *context = gum_invocation_context_get_nth_argument (ic,
      GUM_VIRTUAL_UNWIND_CONTEXT_ARG_INDEX);
}

static void
gum_unwind_broker_on_virtual_unwind_leave (GumInvocationContext * ic,
                                           gpointer user_data)
{
  CONTEXT * context = *GUM_IC_GET_INVOCATION_DATA (ic, PCONTEXT);
  GumAddress real_pc;

#ifdef HAVE_ARM64
  real_pc = gum_unwind_broker_translate_pc (context->Pc);
  if (real_pc != 0)
    context->Pc = real_pc;
#else
  real_pc = gum_unwind_broker_translate_pc (context->Rip);
  if (real_pc != 0)
    context->Rip = real_pc;
#endif
}

static gpointer
gum_find_virtual_unwind_impl (void)
{
  return gum_find_last_direct_call_target (GetProcAddress (
      GetModuleHandleW (L"ntdll.dll"), "RtlVirtualUnwind"));
}

static GumAddress
gum_unwind_broker_translate_pc (GumAddress code_address)
{
  gpointer translated;
  GumAddress result;

  translated = gum_invocation_stack_translate (
      gum_interceptor_get_current_stack (), GSIZE_TO_POINTER (code_address));
  if (translated != GSIZE_TO_POINTER (code_address))
    return GUM_ADDRESS (translated);

  result = _gum_unwind_broker_dispatch_translate (code_address);
  if (result == code_address)
    return 0;

  return result;
}

static gpointer
gum_find_last_direct_call_target (gconstpointer function)
{
  gpointer target = NULL;
  csh capstone;
  cs_insn * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  gum_cs_arch_register_native ();
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  insn = cs_malloc (capstone);

  code = function;
  size = 1024;
  address = GUM_ADDRESS (function);

  while (cs_disasm_iter (capstone, &code, &size, &address, insn) &&
      !cs_insn_group (capstone, insn, CS_GRP_RET))
  {
    if (cs_insn_group (capstone, insn, CS_GRP_CALL) &&
        gum_call_is_direct (insn))
      target = gum_get_call_target (insn);
  }

  cs_free (insn, 1);
  cs_close (&capstone);

  return target;
}

static gboolean
gum_call_is_direct (const cs_insn * insn)
{
#ifdef HAVE_ARM64
  return insn->detail->arm64.operands[0].type == ARM64_OP_IMM;
#else
  return insn->detail->x86.operands[0].type == X86_OP_IMM;
#endif
}

static gpointer
gum_get_call_target (const cs_insn * insn)
{
#ifdef HAVE_ARM64
  return GSIZE_TO_POINTER (insn->detail->arm64.operands[0].imm);
#else
  return GSIZE_TO_POINTER (insn->detail->x86.operands[0].imm);
#endif
}
