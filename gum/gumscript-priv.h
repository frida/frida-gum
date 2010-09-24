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

#ifndef __GUM_SCRIPT_PRIV_H__
#define __GUM_SCRIPT_PRIV_H__

#include "guminvocationcontext.h"
#include "gumscript.h"

G_BEGIN_DECLS

typedef enum _GumVariableType GumVariableType;

typedef struct _GumSendArgItem GumSendArgItem;

enum _GumVariableType
{
  GUM_VARIABLE_INT32,
  GUM_VARIABLE_ANSI_STRING,
  GUM_VARIABLE_WIDE_STRING,
  GUM_VARIABLE_ANSI_FORMAT_STRING,
  GUM_VARIABLE_WIDE_FORMAT_STRING
};

struct _GumSendArgItem
{
  guint index;
  GumVariableType type;
};

void _gum_script_send_item_commit (GumScript * self,
    GumInvocationContext * context, guint argument_index, ...);

G_END_DECLS

#endif
