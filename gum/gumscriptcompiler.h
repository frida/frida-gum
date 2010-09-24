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

#ifndef __GUM_SCRIPT_COMPILER_H__
#define __GUM_SCRIPT_COMPILER_H__

#include "guminvocationcontext.h"

#ifdef _MSC_VER
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_SCRIPT_ENTRYPOINT_API __fastcall
# else
#  define GUM_SCRIPT_ENTRYPOINT_API
# endif
#else
# define GUM_SCRIPT_ENTRYPOINT_API
#endif

G_BEGIN_DECLS

typedef struct _GumScriptCompiler           GumScriptCompiler;

typedef void (GUM_SCRIPT_ENTRYPOINT_API * GumScriptEntrypoint)
    (GumInvocationContext * context);

struct _GumScriptCompiler
{
  gpointer impl[16];
};

void gum_script_compiler_init (GumScriptCompiler * compiler, gpointer code_address);
void gum_script_compiler_free (GumScriptCompiler * compiler);

guint gum_script_compiler_current_offset (GumScriptCompiler * compiler);
GumScriptEntrypoint gum_script_compiler_get_entrypoint (GumScriptCompiler * compiler);

void gum_script_compiler_emit_prologue (GumScriptCompiler * compiler);
void gum_script_compiler_emit_epilogue (GumScriptCompiler * compiler);

void gum_script_compiler_emit_replace_argument (GumScriptCompiler * compiler,
    guint index, GumAddress value);
void gum_script_compiler_emit_send_item_commit (GumScriptCompiler * compiler,
    const GArray * send_arg_items);

G_END_DECLS

#endif
