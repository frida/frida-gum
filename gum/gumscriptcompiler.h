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
#include "gumscript-priv.h"

G_BEGIN_DECLS

typedef struct _GumScriptCompilerBackend GumScriptCompilerBackend;

typedef enum _GumVariableType GumVariableType;
typedef struct _GumSendArgItem GumSendArgItem;

enum _GumVariableType
{
  GUM_VARIABLE_INT32,
  GUM_VARIABLE_ANSI_STRING,
  GUM_VARIABLE_WIDE_STRING,
  GUM_VARIABLE_ANSI_FORMAT_STRING,
  GUM_VARIABLE_WIDE_FORMAT_STRING,
  GUM_VARIABLE_BYTE_ARRAY
};

struct _GumSendArgItem
{
  guint32 index;
  GumVariableType type;
};

GumScript * gum_script_compiler_compile (const gchar * script_text,
    GError ** error);

void gum_script_code_free (GumScriptCode * code);
void gum_script_data_free (GumScriptData * data);

GumScriptCompilerBackend * gum_script_compiler_backend_new (
    gpointer code_address);
void gum_script_compiler_backend_free (GumScriptCompilerBackend * backend);

void gum_script_compiler_backend_flush (GumScriptCompilerBackend * self);
guint gum_script_compiler_backend_current_offset (
    GumScriptCompilerBackend * self);
GumScriptEntrypoint gum_script_compiler_backend_entrypoint_at (
    GumScriptCompilerBackend * self, guint offset);

void gum_script_compiler_backend_emit_prologue (
    GumScriptCompilerBackend * self);
void gum_script_compiler_backend_emit_epilogue (
    GumScriptCompilerBackend * self);
void gum_script_compiler_backend_emit_replace_argument (
    GumScriptCompilerBackend * self, guint index, GumAddress value);
void gum_script_compiler_backend_emit_send_item_commit (
    GumScriptCompilerBackend * self, GumScript * script,
    const GArray * send_arg_items);

G_END_DECLS

#endif
