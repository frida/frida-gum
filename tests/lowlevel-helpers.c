/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "lowlevel-helpers.h"

#include "gumcodewriter.h"
#include "gummemory.h"

#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#else
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#endif
#include <string.h>

ClobberTestFunc clobber_test_function = NULL;

typedef void (GUM_THUNK * InvokeWithCpuContextFunc) (
    const GumCpuContext * input, GumCpuContext * output);
typedef void (GUM_THUNK * InvokeWithCpuFlagsFunc) (
    gsize * flags_input, gsize * flags_output);

void
lowlevel_helpers_init (void)
{
  GumCodeWriter cw;

  g_assert (clobber_test_function == NULL);

  clobber_test_function =
      (ClobberTestFunc) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_code_writer_init (&cw, (gpointer) (gsize) clobber_test_function);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_ret (&cw);
  gum_code_writer_free (&cw);
}

void
lowlevel_helpers_deinit (void)
{
  g_assert (clobber_test_function != NULL);

  gum_free_pages (clobber_test_function);
  clobber_test_function = NULL;
}

void
fill_cpu_context_with_magic_values (GumCpuContext * ctx)
{
#if GLIB_SIZEOF_VOID_P == 4
  ctx->edi = 0x1234a001;
  ctx->esi = 0x12340b02;
  ctx->ebp = 0x123400c3;
  ctx->ebx = 0x12340d04;
  ctx->edx = 0x1234e005;
  ctx->ecx = 0x12340f06;
  ctx->eax = 0x12340107;
#else
  ctx->rdi = 0x876543211234a001;
  ctx->rsi = 0x8765432112340b02;
  ctx->rbp = 0x87654321123400c3;
  ctx->rbx = 0x8765432112340d04;
  ctx->rdx = 0x876543211234e005;
  ctx->rcx = 0x8765432112340f06;
  ctx->rax = 0x8765432112340107;

  ctx->r15 = 0x8765abcd1234a001;
  ctx->r14 = 0x8765abcd12340b02;
  ctx->r13 = 0x8765abcd123400c3;
  ctx->r12 = 0x8765abcd12340d04;
  ctx->r11 = 0x8765abcd1234e005;
  ctx->r10 = 0x8765abcd12340f06;
  ctx->r9  = 0x8765abcd12340107;
  ctx->r8  = 0x8765abcd12340107;
#endif
}

void
assert_cpu_contexts_are_equal (GumCpuContext * input,
                               GumCpuContext * output)
{
#if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmphex (output->edi, ==, input->edi);
  g_assert_cmphex (output->esi, ==, input->esi);
  g_assert_cmphex (output->ebp, ==, input->ebp);
  g_assert_cmphex (output->ebx, ==, input->ebx);
  g_assert_cmphex (output->edx, ==, input->edx);
  g_assert_cmphex (output->ecx, ==, input->ecx);
  g_assert_cmphex (output->eax, ==, input->eax);
#else
  g_assert_cmphex (output->rdi, ==, input->rdi);
  g_assert_cmphex (output->rsi, ==, input->rsi);
  g_assert_cmphex (output->rbp, ==, input->rbp);
  g_assert_cmphex (output->rbx, ==, input->rbx);
  g_assert_cmphex (output->rdx, ==, input->rdx);
  g_assert_cmphex (output->rcx, ==, input->rcx);
  g_assert_cmphex (output->rax, ==, input->rax);

  g_assert_cmphex (output->r15, ==, input->r15);
  g_assert_cmphex (output->r14, ==, input->r14);
  g_assert_cmphex (output->r13, ==, input->r13);
  g_assert_cmphex (output->r12, ==, input->r12);
  g_assert_cmphex (output->r11, ==, input->r11);
  g_assert_cmphex (output->r10, ==, input->r10);
  g_assert_cmphex (output->r9, ==, input->r9);
  g_assert_cmphex (output->r8, ==, input->r8);
#endif
}

void
invoke_clobber_test_function_with_cpu_context (const GumCpuContext * input,
                                               GumCpuContext * output)
{
  GumAddressSpec addr_spec;
  guint8 * code;
  GumCodeWriter cw;
  InvokeWithCpuContextFunc func;

  addr_spec.near_address = clobber_test_function;
  addr_spec.max_distance = G_MAXINT32 - gum_query_page_size ();
  code = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &addr_spec);
  gum_code_writer_init (&cw, code);

  gum_code_writer_put_pushax (&cw);
  gum_code_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder for xip */

#if GLIB_SIZEOF_VOID_P == 4
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EAX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, eax));
  /* leave GUM_REG_ECX for last */
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EDX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edx));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EBX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EBP,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ESI,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, esi));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EDI,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edi));

  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ECX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx));
#else
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RAX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rax));
  /* leave GUM_REG_RCX for last */
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RDX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdx));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RBX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbx));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RBP,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbp));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RSI,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rsi));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RDI,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdi));

  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R8,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r8));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R9,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r9));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R10,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r10));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R11,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r11));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R12,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r12));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R13,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r13));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R14,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r14));
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R15,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r15));

  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RCX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rcx));
#endif

  gum_code_writer_put_call (&cw, clobber_test_function);

  gum_code_writer_put_push_reg (&cw, GUM_REG_XCX);

#if GLIB_SIZEOF_VOID_P == 4
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ECX,
      GUM_REG_ESP, 4 + G_STRUCT_OFFSET (GumCpuContext, edx));

  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, eax),
      GUM_REG_EAX);
  /* leave GUM_REG_ECX for last */
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edx),
      GUM_REG_EDX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx),
      GUM_REG_EBX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp),
      GUM_REG_EBP);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, esi),
      GUM_REG_ESI);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edi),
      GUM_REG_EDI);

  gum_code_writer_put_pop_reg (&cw, GUM_REG_EDX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx),
      GUM_REG_EDX);
#else
  gum_code_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RCX,
      GUM_REG_RSP, 8 + G_STRUCT_OFFSET (GumCpuContext, rdx));

  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rax),
      GUM_REG_RAX);
  /* leave GUM_REG_RCX for last */
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdx),
      GUM_REG_RDX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbx),
      GUM_REG_RBX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbp),
      GUM_REG_RBP);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rsi),
      GUM_REG_RSI);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdi),
      GUM_REG_RDI);

  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r8),
      GUM_REG_R8);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r9),
      GUM_REG_R9);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r10),
      GUM_REG_R10);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r11),
      GUM_REG_R11);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r12),
      GUM_REG_R12);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r13),
      GUM_REG_R13);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r14),
      GUM_REG_R14);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r15),
      GUM_REG_R15);

  gum_code_writer_put_pop_reg (&cw, GUM_REG_RDX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rcx),
      GUM_REG_RDX);
#endif

  gum_code_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_code_writer_put_popax (&cw);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  func = (InvokeWithCpuContextFunc) code;
  func (input, output);

  gum_free_pages (code);
}

void
invoke_clobber_test_function_with_carry_set (gsize * flags_input,
                                             gsize * flags_output)
{
  GumAddressSpec addr_spec;
  guint8 * code;
  GumCodeWriter cw;
  InvokeWithCpuFlagsFunc func;

  addr_spec.near_address = clobber_test_function;
  addr_spec.max_distance = G_MAXINT32 - gum_query_page_size ();
  code = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &addr_spec);
  gum_code_writer_init (&cw, code);

  gum_code_writer_put_stc (&cw); /* set carry flag, likely to get clobbered */

  gum_code_writer_put_pushfx (&cw);
  gum_code_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_code_writer_put_mov_reg_ptr_reg (&cw, GUM_REG_XCX, GUM_REG_XAX);

  gum_code_writer_put_call (&cw, clobber_test_function);

  gum_code_writer_put_pushfx (&cw);
  gum_code_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_code_writer_put_mov_reg_ptr_reg (&cw, GUM_REG_XDX, GUM_REG_XAX);

  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  func = (InvokeWithCpuFlagsFunc) code;
  func (flags_input, flags_output);

  gum_free_pages (code);
}

UnsupportedFunction *
unsupported_function_list_new (guint * count)
{
  static const UnsupportedFunction unsupported_functions[] =
  {
    { "ret",   1, { 0xc3                                           } },
    { "retf",  1, { 0xcb                                           } },
  };
  UnsupportedFunction * result;

  result = (UnsupportedFunction *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  memcpy (result, unsupported_functions, sizeof (unsupported_functions));
  *count = G_N_ELEMENTS (unsupported_functions);

  return result;
}

void
unsupported_function_list_free (UnsupportedFunction * functions)
{
  gum_free_pages (functions);
}

#define OPCODE_JMP (0xE9)

ProxyFunc
proxy_func_new_relative_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  func[0] = OPCODE_JMP;
  *((gint32 *) (func + 1)) =
      (guint8 *) GSIZE_TO_POINTER (target_func) - (func + 5);

  return (ProxyFunc) func;
}

ProxyFunc
proxy_func_new_absolute_indirect_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  func[0] = 0xff;
  func[1] = 0x25;
#if GLIB_SIZEOF_VOID_P == 4
  *((gpointer *) (func + 2)) = func + 6;
#else
  *((gint32 *) (func + 2)) = 0;
#endif
  *((TargetFunc *) (func + 6)) = target_func;

  return (ProxyFunc) func;
}

ProxyFunc
proxy_func_new_two_jumps_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  func[0] = OPCODE_JMP;
  *((gint32 *) (func + 1)) = (guint8 *) (func + 20) - (func + 5);

  func[20] = 0xff;
  func[21] = 0x25;
#if GLIB_SIZEOF_VOID_P == 4
  *((gpointer *)   (func + 22)) = func + 30;
#else
  *((gint32 *)     (func + 22)) = 4;
#endif
  *((TargetFunc *) (func + 30)) = target_func;

  return (ProxyFunc) func;
}

ProxyFunc
proxy_func_new_early_call_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  func[0] = 0xFF; /* push dword [esp + 4] */
  func[1] = 0x74;
  func[2] = 0x24;
  func[3] = 0x04;

  func[4] = 0xe8; /* call */
  *((gssize *) (func + 5)) = ((gssize) GPOINTER_TO_SIZE (target_func))
      - ((gssize) GPOINTER_TO_SIZE (func + 9));

  func[9] = 0x83; /* add esp, 4 */
  func[10] = 0xC4;
  func[11] = 0x04;

  func[12] = 0xC3; /* ret */

  return (ProxyFunc) func;
}

void
proxy_func_free (ProxyFunc proxy_func)
{
  gum_free_pages ((gpointer) (gsize) proxy_func);
}
