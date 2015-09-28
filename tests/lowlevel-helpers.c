/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "lowlevel-helpers.h"

#include "gumx86writer.h"
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
  GumX86Writer cw;

  g_assert (clobber_test_function == NULL);

  clobber_test_function = GUM_POINTER_TO_FUNCPTR (ClobberTestFunc,
      gum_alloc_n_pages (1, GUM_PAGE_RWX));
  gum_x86_writer_init (&cw, (gpointer) (gsize) clobber_test_function);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_ret (&cw);
  gum_x86_writer_free (&cw);
}

void
lowlevel_helpers_deinit (void)
{
  g_assert (clobber_test_function != NULL);

  gum_free_pages (GUM_FUNCPTR_TO_POINTER (clobber_test_function));
  clobber_test_function = NULL;
}

void
fill_cpu_context_with_magic_values (GumCpuContext * ctx)
{
#ifdef HAVE_I386
# if GLIB_SIZEOF_VOID_P == 4
  ctx->edi = 0x1234a001;
  ctx->esi = 0x12340b02;
  ctx->ebp = 0x123400c3;
  ctx->ebx = 0x12340d04;
  ctx->edx = 0x1234e005;
  ctx->ecx = 0x12340f06;
  ctx->eax = 0x12340107;
# else
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
# endif
#endif
}

void
assert_cpu_contexts_are_equal (GumCpuContext * input,
                               GumCpuContext * output)
{
#ifdef HAVE_I386
# if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmphex (output->edi, ==, input->edi);
  g_assert_cmphex (output->esi, ==, input->esi);
  g_assert_cmphex (output->ebp, ==, input->ebp);
  g_assert_cmphex (output->ebx, ==, input->ebx);
  g_assert_cmphex (output->edx, ==, input->edx);
  g_assert_cmphex (output->ecx, ==, input->ecx);
  g_assert_cmphex (output->eax, ==, input->eax);
# else
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
# endif
#endif
}

void
invoke_clobber_test_function_with_cpu_context (const GumCpuContext * input,
                                               GumCpuContext * output)
{
#ifdef HAVE_I386
  GumAddressSpec addr_spec;
  guint8 * code;
  GumX86Writer cw;
  InvokeWithCpuContextFunc func;
  guint align_correction = 0;

# if GLIB_SIZEOF_VOID_P == 4
  align_correction = 8;
# endif

  addr_spec.near_address = GUM_FUNCPTR_TO_POINTER (clobber_test_function);
  addr_spec.max_distance = G_MAXINT32 - gum_query_page_size ();
  code = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &addr_spec);
  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder for xip */

# if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EAX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, eax));
  /* leave GUM_REG_ECX for last */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EDX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EBX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EBP,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ESI,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, esi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EDI,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edi));

  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ECX,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx));
# else
  if (cw.target_abi == GUM_ABI_UNIX)
    gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_RCX, GUM_REG_RDI);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RAX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rax));
  /* leave GUM_REG_RCX for last */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RDX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RBX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RBP,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbp));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RSI,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rsi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RDI,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdi));

  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R8,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r8));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R9,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r9));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R10,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r10));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R11,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r11));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R12,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r12));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R13,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r13));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R14,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r14));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_R15,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r15));

  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RCX,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rcx));
# endif

  if (align_correction != 0)
    gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction);

  gum_x86_writer_put_call (&cw,
      GUM_FUNCPTR_TO_POINTER (clobber_test_function));

  if (align_correction != 0)
    gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction);

  gum_x86_writer_put_push_reg (&cw, GUM_REG_XCX);

# if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ECX,
      GUM_REG_ESP, 4 + G_STRUCT_OFFSET (GumCpuContext, edx));

  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, eax),
      GUM_REG_EAX);
  /* leave GUM_REG_ECX for last */
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edx),
      GUM_REG_EDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx),
      GUM_REG_EBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp),
      GUM_REG_EBP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, esi),
      GUM_REG_ESI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edi),
      GUM_REG_EDI);

  gum_x86_writer_put_pop_reg (&cw, GUM_REG_EDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx),
      GUM_REG_EDX);
# else
  if (cw.target_abi == GUM_ABI_UNIX)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RCX,
        GUM_REG_RSP, 8 + G_STRUCT_OFFSET (GumCpuContext, rsi));
  }
  else
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RCX,
        GUM_REG_RSP, 8 + G_STRUCT_OFFSET (GumCpuContext, rdx));
  }

  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rax),
      GUM_REG_RAX);
  /* leave GUM_REG_RCX for last */
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdx),
      GUM_REG_RDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbx),
      GUM_REG_RBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rbp),
      GUM_REG_RBP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rsi),
      GUM_REG_RSI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rdi),
      GUM_REG_RDI);

  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r8),
      GUM_REG_R8);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r9),
      GUM_REG_R9);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r10),
      GUM_REG_R10);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r11),
      GUM_REG_R11);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r12),
      GUM_REG_R12);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r13),
      GUM_REG_R13);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r14),
      GUM_REG_R14);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, r15),
      GUM_REG_R15);

  gum_x86_writer_put_pop_reg (&cw, GUM_REG_RDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_RCX, G_STRUCT_OFFSET (GumCpuContext, rcx),
      GUM_REG_RDX);
# endif

  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_popax (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_free (&cw);

  func = GUM_POINTER_TO_FUNCPTR (InvokeWithCpuContextFunc, code);
  func (input, output);

  gum_free_pages (code);
#endif
}

void
invoke_clobber_test_function_with_carry_set (gsize * flags_input,
                                             gsize * flags_output)
{
#ifdef HAVE_I386
  GumAddressSpec addr_spec;
  guint8 * code;
  GumX86Writer cw;
  InvokeWithCpuFlagsFunc func;
  guint align_correction = 0, i;

# if GLIB_SIZEOF_VOID_P == 8
  align_correction = 8;
# else
  align_correction = 12;
# endif

  addr_spec.near_address = clobber_test_function;
  addr_spec.max_distance = G_MAXINT32 - gum_query_page_size ();
  code = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &addr_spec);
  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_stc (&cw); /* set carry flag, likely to get clobbered */

  gum_x86_writer_put_pushfx (&cw);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_mov_reg_ptr_reg (&cw,
      gum_x86_writer_get_cpu_register_for_nth_argument (&cw, 0), GUM_REG_XAX);

  /* cannot use sub instruction here because it clobbers CPU flags */
  for (i = 0; i != align_correction; i += sizeof (gpointer))
    gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX);

  gum_x86_writer_put_call (&cw, clobber_test_function);

  for (i = 0; i != align_correction; i += sizeof (gpointer))
    gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX);

  gum_x86_writer_put_pushfx (&cw);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_mov_reg_ptr_reg (&cw,
      gum_x86_writer_get_cpu_register_for_nth_argument (&cw, 1), GUM_REG_XAX);

  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_free (&cw);

  func = GUM_POINTER_TO_FUNCPTR (InvokeWithCpuFlagsFunc, code);
  func (flags_input, flags_output);

  gum_free_pages (code);
#endif
}

UnsupportedFunction *
unsupported_function_list_new (guint * count)
{
  static const UnsupportedFunction unsupported_functions[] =
  {
#if defined (HAVE_I386)
    { "ret",   1, 0, { 0xc3                                           } },
    { "retf",  1, 0, { 0xcb                                           } },
#elif defined (HAVE_ARM)
    { "ret",   2, 1, { 0x70, 0x47                                     } },
#endif
  };
  UnsupportedFunction * result;

  result = (UnsupportedFunction *) gum_alloc_n_pages (1, GUM_PAGE_RW);
  memcpy (result, unsupported_functions, sizeof (unsupported_functions));
  *count = G_N_ELEMENTS (unsupported_functions);

  return result;
}

void
unsupported_function_list_free (UnsupportedFunction * functions)
{
  gum_free_pages (functions);
}

#ifdef HAVE_I386

ProxyFunc
proxy_func_new_relative_with_target (TargetFunc target_func)
{
  GumAddressSpec addr_spec;
  guint8 * func;

  addr_spec.near_address = target_func;
  addr_spec.max_distance = G_MAXINT32 - gum_query_page_size ();
  func = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &addr_spec);
  func[0] = 0xe9;
  *((gint32 *) (func + 1)) =
      ((gssize) target_func) - (gssize) (func + 5);

  return GUM_POINTER_TO_FUNCPTR (ProxyFunc, func);
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

  return GUM_POINTER_TO_FUNCPTR (ProxyFunc, func);
}

ProxyFunc
proxy_func_new_two_jumps_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  func[0] = 0xe9;
  *((gint32 *) (func + 1)) = (guint8 *) (func + 20) - (func + 5);

  func[20] = 0xff;
  func[21] = 0x25;
#if GLIB_SIZEOF_VOID_P == 4
  *((gpointer *)   (func + 22)) = func + 30;
#else
  *((gint32 *)     (func + 22)) = 4;
#endif
  *((TargetFunc *) (func + 30)) = target_func;

  return GUM_POINTER_TO_FUNCPTR (ProxyFunc, func);
}

ProxyFunc
proxy_func_new_early_call_with_target (TargetFunc target_func)
{
  GumAddressSpec addr_spec;
  guint8 * func, * code;

  addr_spec.near_address = target_func;
  addr_spec.max_distance = G_MAXINT32 - gum_query_page_size ();
  func = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &addr_spec);

  code = func;

#if GLIB_SIZEOF_VOID_P == 4
  code[0] = 0xff; /* push dword [esp + 4] */
  code[1] = 0x74;
  code[2] = 0x24;
  code[3] = 0x04;
  code += 4;
#else
  code[0] = 0x48; /* sub rsp, 0x28 (4 * sizeof (gpointer) + 8) */
  code[1] = 0x83;
  code[2] = 0xec;
  code[3] = 0x28;
  code += 4;
#endif

  code[0] = 0xe8; /* call */
  *((gssize *) (code + 1)) = (gssize) target_func - (gssize) (code + 5);
  code += 5;

#if GLIB_SIZEOF_VOID_P == 4
  code[0] = 0x83; /* add esp, 4 */
  code[1] = 0xc4;
  code[2] = 0x04;
  code += 3;
#else
  code[0] = 0x48; /* add rsp, 0x28 */
  code[1] = 0x83;
  code[2] = 0xc4;
  code[3] = 0x28;
  code += 4;
#endif

  *code++ = 0xc3; /* ret */

  return GUM_POINTER_TO_FUNCPTR (ProxyFunc, func);
}

void
proxy_func_free (ProxyFunc proxy_func)
{
  gum_free_pages ((gpointer) (gsize) proxy_func);
}

#endif
