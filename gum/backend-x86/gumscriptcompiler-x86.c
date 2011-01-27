/*
 * Copyright (C) 2010-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumscriptcompiler.h"

#include "guminvocationcontext.h"
#include "gumx86writer.h"

struct _GumScriptCompilerBackend
{
  gpointer code_address;
  GumX86Writer code_writer;
};

GumScriptCompilerBackend *
gum_script_compiler_backend_new (gpointer code_address)
{
  GumScriptCompilerBackend * backend;

  backend = g_slice_new (GumScriptCompilerBackend);
  backend->code_address = code_address;
  gum_x86_writer_init (&backend->code_writer, code_address);

  return backend;
}

void
gum_script_compiler_backend_free (GumScriptCompilerBackend * backend)
{
  gum_x86_writer_free (&backend->code_writer);
  g_slice_free (GumScriptCompilerBackend, backend);
}

void
gum_script_compiler_backend_flush (GumScriptCompilerBackend * self)
{
  gum_x86_writer_flush (&self->code_writer);
}

guint
gum_script_compiler_backend_current_offset (GumScriptCompilerBackend * self)
{
  return gum_x86_writer_offset (&self->code_writer);
}

GumScriptEntrypoint
gum_script_compiler_backend_entrypoint_at (GumScriptCompilerBackend * self,
                                           guint offset)
{
  g_assert_cmpuint (offset, <=,
      gum_script_compiler_backend_current_offset (self));

  return GUM_POINTER_TO_FUNCPTR (GumScriptEntrypoint,
      (guint8 *) self->code_address + offset);
}

void
gum_script_compiler_backend_emit_prologue (GumScriptCompilerBackend * self)
{
  GumX86Writer * cw = &self->code_writer;

  gum_x86_writer_put_push_reg (cw, GUM_REG_XBP);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XBP, GUM_REG_XSP);
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, sizeof (gpointer));

  gum_x86_writer_put_push_reg (cw, GUM_REG_XBX);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XBX,
      gum_x86_writer_get_cpu_register_for_nth_argument (cw, 0));
}

void
gum_script_compiler_backend_emit_epilogue (GumScriptCompilerBackend * self)
{
  GumX86Writer * cw = &self->code_writer;

  gum_x86_writer_put_pop_reg (cw, GUM_REG_XBX);

  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSP, GUM_REG_XBP);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (cw);
}

void
gum_script_compiler_backend_emit_replace_argument (
    GumScriptCompilerBackend * self,
    guint index,
    GumAddress value)
{
  GumX86Writer * cw = &self->code_writer;

  gum_x86_writer_put_push_reg (cw, GUM_REG_XSI);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XSI, value);
  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (gum_invocation_context_replace_nth_argument), 3,
      GUM_ARG_REGISTER, GUM_REG_XBX,
      GUM_ARG_POINTER, GSIZE_TO_POINTER (index),
      GUM_ARG_REGISTER, GUM_REG_XSI);

  gum_x86_writer_put_pop_reg (cw, GUM_REG_XSI);
}

void
gum_script_compiler_backend_emit_send_item_commit (
    GumScriptCompilerBackend * self,
    GumScript * script,
    const GArray * send_arg_items)
{
  GumX86Writer * cw = &self->code_writer;
  gint item_index;

  if (cw->target_cpu == GUM_CPU_AMD64 && cw->target_abi == GUM_ABI_UNIX)
  {
    if (send_arg_items->len >= 2)
    {
      gum_x86_writer_put_push_u32 (cw, 0x9ADD176); /* alignment padding */
      gum_x86_writer_put_push_u32 (cw, G_MAXUINT);
    }
    else
    {
      gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_R8D, G_MAXUINT);
    }

    for (item_index = send_arg_items->len - 1; item_index >= 0; item_index--)
    {
      GumSendArgItem * item;

      item = &g_array_index (send_arg_items, GumSendArgItem, item_index);

      if (item_index == 0)
      {
        gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_ECX, item->type);
        gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_EDX, item->index);
      }
      else if (item_index == 1)
      {
        gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_R9D, item->type);
        gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_R8D, item->index);
      }
      else
      {
        gum_x86_writer_put_push_u32 (cw, item->type);
        gum_x86_writer_put_push_u32 (cw, item->index);
      }
    }

    gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_RSI, GUM_REG_RBX);
    gum_x86_writer_put_mov_reg_address (cw, GUM_REG_RDI, GUM_ADDRESS (script));

    gum_x86_writer_put_xor_reg_reg (cw, GUM_REG_EAX, GUM_REG_EAX);

    gum_x86_writer_put_mov_reg_address (cw, GUM_REG_R10,
        GUM_ADDRESS (GUM_FUNCPTR_TO_POINTER (_gum_script_send_item_commit)));
    gum_x86_writer_put_call_reg (cw, GUM_REG_R10);

    if (send_arg_items->len >= 2)
    {
      gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XSP,
          ((((send_arg_items->len - 2) * 2) + 2) * sizeof (gpointer)));
    }
  }
  else
  {
    guint align_correction = 0;

#if GLIB_SIZEOF_VOID_P == 4
    align_correction = (send_arg_items->len % 2 == 0) ? 0 : 8;
#endif

    if (align_correction != 0)
      gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, align_correction);

    gum_x86_writer_put_push_u32 (cw, 0x9ADD176); /* alignment padding */
    gum_x86_writer_put_push_u32 (cw, G_MAXUINT);

    for (item_index = send_arg_items->len - 1; item_index >= 0; item_index--)
    {
      GumSendArgItem * item;

      item = &g_array_index (send_arg_items, GumSendArgItem, item_index);

      if (cw->target_cpu == GUM_CPU_AMD64 && item_index == 0)
      {
        gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_R9D, item->type);
        gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_R8D, item->index);
      }
      else
      {
        gum_x86_writer_put_push_u32 (cw, item->type);
        gum_x86_writer_put_push_u32 (cw, item->index);
      }
    }

    if (cw->target_cpu == GUM_CPU_AMD64)
    {
      gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_RDX, GUM_REG_RBX);
      gum_x86_writer_put_mov_reg_address (cw, GUM_REG_RCX, GUM_ADDRESS (script));
      gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_RSP, 4 * sizeof (gpointer));
    }
    else
    {
      gum_x86_writer_put_push_reg (cw, GUM_REG_EBX);
      gum_x86_writer_put_push_u32 (cw, (guint32) GPOINTER_TO_SIZE (script));
    }

    gum_x86_writer_put_call (cw,
        GUM_FUNCPTR_TO_POINTER (_gum_script_send_item_commit));

    gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XSP,
        (2 + (send_arg_items->len * 2) + 2) * sizeof (gpointer) +
        align_correction);
  }
}
