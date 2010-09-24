/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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
#include "gumthumbwriter.h"

#define GUM_SCRIPT_COMPILER_IMPL(c) ((GumScriptCompilerImpl *) (c))

typedef struct _GumScriptCompilerImpl GumScriptCompilerImpl;

struct _GumScriptCompilerImpl
{
  gpointer code_address;
  GumThumbWriter code_writer;
};

void
gum_script_compiler_init (GumScriptCompiler * compiler, gpointer code_address)
{
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);

  self->code_address = code_address;
  gum_thumb_writer_init (&self->code_writer, code_address);
}

void
gum_script_compiler_free (GumScriptCompiler * compiler)
{
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);

  gum_thumb_writer_free (&self->code_writer);
}

guint
gum_script_compiler_current_offset (GumScriptCompiler * compiler)
{
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);

  return gum_thumb_writer_offset (&self->code_writer);
}

GumScriptEntrypoint
gum_script_compiler_get_entrypoint (GumScriptCompiler * compiler)
{
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);

  return (GumScriptEntrypoint) (self->code_address + 1);
}

void
gum_script_compiler_emit_prologue (GumScriptCompiler * compiler)
{
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);
  GumThumbWriter * cw = &self->code_writer;

  gum_thumb_writer_put_push_regs (cw, 3, GUM_AREG_R4, GUM_AREG_R7, GUM_AREG_LR);

  gum_thumb_writer_put_mov_reg_reg (cw, GUM_AREG_R7, GUM_AREG_R0);
}

void
gum_script_compiler_emit_epilogue (GumScriptCompiler * compiler)
{
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);
  GumThumbWriter * cw = &self->code_writer;

  gum_thumb_writer_put_pop_regs (cw, 3, GUM_AREG_R4, GUM_AREG_R7, GUM_AREG_PC);
}

void
gum_script_compiler_emit_replace_argument (GumScriptCompiler * compiler,
                                           guint index,
                                           GumAddress value)
{
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);
  GumThumbWriter * cw = &self->code_writer;

  gum_thumb_writer_put_mov_reg_reg (cw, GUM_AREG_R0, GUM_AREG_R7);
  gum_thumb_writer_put_ldr_reg_u32 (cw, GUM_AREG_R1, index);
  gum_thumb_writer_put_ldr_reg_address (cw, GUM_AREG_R2, value);
  gum_thumb_writer_put_ldr_reg_address (cw, GUM_AREG_R4,
      GUM_ADDRESS (gum_invocation_context_replace_nth_argument));
  gum_thumb_writer_put_blx_reg (cw, GUM_AREG_R4);
}

void
gum_script_compiler_emit_send_item_commit (GumScriptCompiler * compiler,
                                           const GArray * send_arg_items)
{
  /*
  GumScriptCompilerImpl * self = GUM_SCRIPT_COMPILER_IMPL (compiler);
  GumThumbWriter * cw = &self->code_writer;
  */

  g_assert_not_reached ();
}
