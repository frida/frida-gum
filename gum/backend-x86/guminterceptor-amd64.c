/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include <string.h>

#define OPCODE_NOP               (0x90)

typedef struct _RedirectStub64          RedirectStub64;
typedef struct _MonitorTrampolineHead64 MonitorTrampolineHead64;
typedef struct _MonitorTrampolineTail64 MonitorTrampolineTail64;

#pragma pack (push, 1)

struct _RedirectStub64
{
  guint8 jmp_indirect_pfx;
  guint8 jmp_indirect_insn;
  gint32 jmp_indirect_offset;
  gpointer jmp_address;
};

struct _MonitorTrampolineHead64
{
  guint8 push_func_ctx_pfx;
  guint8 push_func_ctx_insn;
  gint32 push_func_ctx_offset;
  guint8 call_on_enter_pfx;
  guint8 call_on_enter_insn;
  gint32 call_on_enter_offset;

  guint8 overwritten_prologue[1];
};

struct _MonitorTrampolineTail64
{
  gpointer function_ctx;
  gpointer on_enter_thunk;
};

#pragma pack (pop)

void
_gum_function_ctx_make_monitor_trampoline (FunctionContext * ctx)
{
  MonitorTrampolineHead64 * head;
  MonitorTrampolineTail64 * tail;
  RedirectStub64 * jump_back_stub;

  /* TODO: migrate to Relocator once it supports x64 */
  ctx->overwritten_prologue_len =
      _gum_interceptor_find_displacement_size (ctx->function_address,
          GUM_REDIRECT_CODE_SIZE);
  g_assert (ctx->overwritten_prologue_len != 0);

  ctx->trampoline = head =
      gum_alloc_n_pages (1, GUM_PAGE_READ|GUM_PAGE_WRITE|GUM_PAGE_EXECUTE);
  tail = (MonitorTrampolineTail64 *) (
      (guint8 *) head + gum_query_page_size ()
      - sizeof (MonitorTrampolineTail64));
  head->push_func_ctx_pfx = 0xff;
  head->push_func_ctx_insn = 0x35;
  head->push_func_ctx_offset = (gssize) (&tail->function_ctx)
      - (gssize) (&head->call_on_enter_pfx);
  head->call_on_enter_pfx = 0xff;
  head->call_on_enter_insn = 0x15;
  head->call_on_enter_offset = (gssize) (&tail->on_enter_thunk)
      - (gssize) (&head->overwritten_prologue);
  memcpy (head->overwritten_prologue, ctx->function_address,
      ctx->overwritten_prologue_len);

  g_assert_cmpuint (ctx->overwritten_prologue_len, <=,
      sizeof (ctx->overwritten_prologue));
  memcpy (ctx->overwritten_prologue, ctx->function_address,
      ctx->overwritten_prologue_len);

  jump_back_stub = (RedirectStub64 *) (
      ((guint8 *) head->overwritten_prologue) + ctx->overwritten_prologue_len);
  jump_back_stub->jmp_indirect_pfx = 0xff;
  jump_back_stub->jmp_indirect_insn = 0x25;
  jump_back_stub->jmp_indirect_offset = 0;
  jump_back_stub->jmp_address =
      (guint8 *) ctx->function_address + ctx->overwritten_prologue_len;

  tail->function_ctx = ctx;
  tail->on_enter_thunk = NULL; /* FIXME: _gum_interceptor_function_context_on_enter_thunk */
}

void
_gum_function_ctx_make_replace_trampoline (FunctionContext * ctx,
                                           gpointer replacement_address,
                                           gpointer user_data)
{
  g_assert_not_reached ();
}

void
_gum_function_ctx_destroy_trampoline (FunctionContext * ctx)
{
}

void
_gum_function_ctx_activate_trampoline (FunctionContext * ctx)
{
  RedirectStub64 * stub = ctx->function_address;
  gsize padding;

  stub->jmp_indirect_pfx = 0xff;
  stub->jmp_indirect_insn = 0x25;
  stub->jmp_indirect_offset = 0;
  stub->jmp_address = ctx->trampoline;

  padding = ctx->overwritten_prologue_len - sizeof (RedirectStub64);
  if (padding > 0)
    memset (stub + 1, OPCODE_NOP, padding);
}

void
_gum_function_ctx_deactivate_trampoline (FunctionContext * ctx)
{
  memcpy (ctx->function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}
