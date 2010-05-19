/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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

#include "guminterceptor-priv.h"

#include "gummemory.h"
#include "gumrelocator.h"

#include <string.h>

#define OPCODE_PUSH_IMM32        (0x68)
#define OPCODE_NOP               (0x90)
#define OPCODE_CALL_REL32        (0xE8)
#define OPCODE_JUMP_REL32        (0xE9)

typedef struct _RedirectStub32          RedirectStub32;
typedef struct _MonitorTrampolineHead32 MonitorTrampolineHead32;
typedef struct _ReplaceTrampolineHead32 ReplaceTrampolineHead32;

#pragma pack (push, 1)

struct _RedirectStub32
{
  guint8 jmp_insn;
  gint32 jmp_offset;
};

struct _MonitorTrampolineHead32
{
  guint8 push_func_ctx_insn;
  FunctionContext * push_func_ctx_address;
  guint8 call_on_enter_insn;
  gint32 call_on_enter_offset;

  guint8 overwritten_prologue[0];
};

struct _ReplaceTrampolineHead32
{
  guint8 push_userdata_insn;
  gpointer push_userdata_ptr;
  guint8 push_origimpl_insn;
  gpointer push_origimpl_ptr;
  guint8 call_replacement_insn;
  gint32 call_replacement_offset;
  guint8 pop_origimpl_to_ecx_insn;
  guint8 pop_userdata_to_ecx_insn;
  guint8 ret_insn;

  guint8 overwritten_prologue[0];
};

#pragma pack (pop)

static gboolean jump_target_is_normal_trampoline (guint8 * jump_target);
static gboolean jump_target_is_replace_trampoline (guint8 * jump_target);

void
_gum_function_ctx_make_monitor_trampoline (FunctionContext * ctx)
{
  MonitorTrampolineHead32 * trampoline;
  RedirectStub32 * trampoline_jump_back;

  ctx->trampoline = trampoline =
      gum_alloc_n_pages (1, GUM_PAGE_READ|GUM_PAGE_WRITE|GUM_PAGE_EXECUTE);
  trampoline->push_func_ctx_insn = OPCODE_PUSH_IMM32;
  trampoline->push_func_ctx_address = ctx;
  trampoline->call_on_enter_insn = OPCODE_CALL_REL32;
  trampoline->call_on_enter_offset =
      (gssize) (&_gum_interceptor_function_context_on_enter_thunk)
      - (gssize) &trampoline->overwritten_prologue;

  ctx->overwritten_prologue_len =
      gum_relocator_relocate (ctx->function_address, GUM_REDIRECT_CODE_SIZE,
          trampoline->overwritten_prologue);
  g_assert_cmpuint (ctx->overwritten_prologue_len, <=,
      sizeof (ctx->overwritten_prologue));
  memcpy (ctx->overwritten_prologue, ctx->function_address,
      ctx->overwritten_prologue_len);

  trampoline_jump_back = (RedirectStub32 *) (
    ((guint8 *) trampoline->overwritten_prologue)
    + ctx->overwritten_prologue_len);
  trampoline_jump_back->jmp_insn = OPCODE_JUMP_REL32;
  trampoline_jump_back->jmp_offset = (gssize) (
    (guint8 *) ctx->function_address + ctx->overwritten_prologue_len)
      - (gssize) (trampoline_jump_back + 1);
}

void
_gum_function_ctx_make_replace_trampoline (FunctionContext * ctx,
                                           gpointer replacement_address,
                                           gpointer user_data)
{
  ReplaceTrampolineHead32 * trampoline;
  RedirectStub32 * trampoline_jump_back;

  ctx->trampoline = trampoline =
      gum_alloc_n_pages (1, GUM_PAGE_READ|GUM_PAGE_WRITE|GUM_PAGE_EXECUTE);
  trampoline->push_userdata_insn = OPCODE_PUSH_IMM32;
  trampoline->push_userdata_ptr = user_data;
  trampoline->push_origimpl_insn = OPCODE_PUSH_IMM32;
  trampoline->push_origimpl_ptr = trampoline->overwritten_prologue;
  trampoline->call_replacement_insn = OPCODE_CALL_REL32;
  trampoline->call_replacement_offset = (gssize) replacement_address
    - (gssize) &trampoline->pop_origimpl_to_ecx_insn;
  trampoline->pop_origimpl_to_ecx_insn = 0x59;
  trampoline->pop_userdata_to_ecx_insn = 0x59;
  trampoline->ret_insn = 0xC3;

  ctx->overwritten_prologue_len =
      gum_relocator_relocate (ctx->function_address, GUM_REDIRECT_CODE_SIZE,
          trampoline->overwritten_prologue);
  g_assert_cmpuint (ctx->overwritten_prologue_len, <=,
      sizeof (ctx->overwritten_prologue));
  memcpy (ctx->overwritten_prologue, ctx->function_address,
      ctx->overwritten_prologue_len);

  trampoline_jump_back = (RedirectStub32 *) (
      ((guint8 *) trampoline->overwritten_prologue) +
      ctx->overwritten_prologue_len);
  trampoline_jump_back->jmp_insn = OPCODE_JUMP_REL32;
  trampoline_jump_back->jmp_offset = (gssize) (
    (guint8 *) ctx->function_address + ctx->overwritten_prologue_len)
      - (gssize) (trampoline_jump_back + 1);
}

void
_gum_function_ctx_destroy_trampoline (FunctionContext * ctx)
{
  gum_free_pages (ctx->trampoline);
  ctx->trampoline = NULL;
}

void
_gum_function_ctx_activate_trampoline (FunctionContext * ctx)
{
  RedirectStub32 * stub = ctx->function_address;
  gsize padding;

  stub->jmp_insn = OPCODE_JUMP_REL32;
  stub->jmp_offset = (gssize) ctx->trampoline - (gssize) (stub + 1);

  padding = ctx->overwritten_prologue_len - sizeof (RedirectStub32);
  if (padding > 0)
    memset (stub + 1, OPCODE_NOP, padding);
}

/* FIXME: don't duplicate this */
static void
make_function_prologue_read_write_execute (gpointer prologue_address)
{
  gum_mprotect (prologue_address, 16, GUM_PAGE_READ | GUM_PAGE_WRITE
      | GUM_PAGE_EXECUTE);
}

void
_gum_function_ctx_deactivate_trampoline (FunctionContext * ctx)
{
  make_function_prologue_read_write_execute (ctx->function_address);
  memcpy (ctx->function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}