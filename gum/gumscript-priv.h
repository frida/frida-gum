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

#ifdef _MSC_VER
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_SCRIPT_ENTRYPOINT_API __fastcall
# else
#  define GUM_SCRIPT_ENTRYPOINT_API
# endif
#else
# define GUM_SCRIPT_ENTRYPOINT_API
#endif

typedef struct _GumScriptCode GumScriptCode;
typedef struct _GumScriptData GumScriptData;

typedef void (GUM_SCRIPT_ENTRYPOINT_API * GumScriptEntrypoint)
    (GumInvocationContext * context);

struct _GumScriptCode
{
  GumScriptEntrypoint enter_entrypoint;
  GumScriptEntrypoint leave_entrypoint;

  guint8 * start;
  guint size;
};

struct _GumScriptData
{
  GHashTable * variable_by_name;
  gchar * send_arg_type_signature[2];
};

struct _GumScriptPrivate
{
  GumScriptCode * code;
  GumScriptData * data;

  GumScriptMessageHandler message_handler_func;
  gpointer message_handler_data;
  GDestroyNotify message_handler_notify;
};

G_BEGIN_DECLS

void _gum_script_send_item_commit (GumScript * self,
    GumInvocationContext * context, guint argument_index, ...);

G_END_DECLS

#endif
