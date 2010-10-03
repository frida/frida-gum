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

#include "gumwinexceptionhook.h"

#include <tchar.h>
#include <udis86.h>

typedef struct _GumWinExceptionHook GumWinExceptionHook;
typedef struct _GumWinExceptionHandlerEntry GumWinExceptionHandlerEntry;

typedef BOOL (WINAPI * GumSystemExceptionHandler) (
    EXCEPTION_RECORD * exception_record, CONTEXT * context);

struct _GumWinExceptionHook
{
  GSList * client_handlers;
  GumSystemExceptionHandler system_handler;

  gpointer dispatcher_impl;
  gint32 * dispatcher_impl_call_immediate;
  DWORD previous_page_protection;
};

struct _GumWinExceptionHandlerEntry
{
  GumWinExceptionHandler func;
  gpointer user_data;
};

static BOOL gum_win_exception_dispatch (EXCEPTION_RECORD * exception_record,
    CONTEXT * context);

G_LOCK_DEFINE_STATIC (hook_instance);
static GumWinExceptionHook * hook_instance = NULL;

void
gum_win_exception_hook_add (GumWinExceptionHandler handler, gpointer user_data)
{
  GumWinExceptionHandlerEntry * entry;

  entry = g_slice_new (GumWinExceptionHandlerEntry);
  entry->func = handler;
  entry->user_data = user_data;

  G_LOCK (hook_instance);

  if (hook_instance == NULL)
  {
    HMODULE ntdll_mod;
    ud_t ud_obj;
    ud_operand_t * op;
    guint8 * call_begin, * call_end;

    hook_instance = g_new0 (GumWinExceptionHook, 1);

    ntdll_mod = GetModuleHandle (_T ("ntdll.dll"));
    g_assert (ntdll_mod != NULL);

    hook_instance->dispatcher_impl = GUM_FUNCPTR_TO_POINTER (
        GetProcAddress (ntdll_mod, "KiUserExceptionDispatcher"));
    g_assert (hook_instance->dispatcher_impl != NULL);

    ud_init (&ud_obj);
    ud_set_mode (&ud_obj, 32);

    ud_set_input_buffer (&ud_obj, (uint8_t *) hook_instance->dispatcher_impl,
        4096);

    do
    {
      guint insn_size;

      insn_size = ud_disassemble (&ud_obj);
      g_assert (insn_size != 0);

      op = &ud_obj.operand[0];
    } while (ud_obj.mnemonic != UD_Icall || op->type != UD_OP_JIMM ||
        op->base != UD_NONE || op->size != 32);

    call_begin =
        (guint8 *) hook_instance->dispatcher_impl + ud_insn_off (&ud_obj);
    call_end = call_begin + ud_insn_len (&ud_obj);

    hook_instance->system_handler = GUM_POINTER_TO_FUNCPTR (
        GumSystemExceptionHandler, call_end + op->lval.sdword);

    VirtualProtect (hook_instance->dispatcher_impl, 4096,
        PAGE_EXECUTE_READWRITE, &hook_instance->previous_page_protection);
    hook_instance->dispatcher_impl_call_immediate =
        (gint32 *) (call_begin + 1);
    *hook_instance->dispatcher_impl_call_immediate =
        (gssize) gum_win_exception_dispatch - (gssize) call_end;
  }

  hook_instance->client_handlers =
      g_slist_append (hook_instance->client_handlers, entry);

  G_UNLOCK (hook_instance);
}

void
gum_win_exception_hook_remove (GumWinExceptionHandler handler)
{
  GumWinExceptionHandlerEntry * matching_entry = NULL;
  GSList * walk;

  G_LOCK (hook_instance);

  g_assert (hook_instance != NULL);

  for (walk = hook_instance->client_handlers;
      walk != NULL && matching_entry == NULL;
      walk = walk->next)
  {
    GumWinExceptionHandlerEntry * entry =
        (GumWinExceptionHandlerEntry *) walk->data;

    if (entry->func == handler)
      matching_entry = entry;
  }

  g_assert (matching_entry != NULL);
  g_slice_free (GumWinExceptionHandlerEntry, matching_entry);
  hook_instance->client_handlers =
      g_slist_remove (hook_instance->client_handlers, matching_entry);

  if (hook_instance->client_handlers == NULL)
  {
    DWORD page_prot;

    *hook_instance->dispatcher_impl_call_immediate =
        (gssize) hook_instance->system_handler -
        (gssize) (hook_instance->dispatcher_impl_call_immediate + 1);
    VirtualProtect (hook_instance->dispatcher_impl, 4096,
        hook_instance->previous_page_protection, &page_prot);

    g_free (hook_instance);
    hook_instance = NULL;
  }

  G_UNLOCK (hook_instance);
}

static BOOL
gum_win_exception_dispatch (EXCEPTION_RECORD * exception_record, CONTEXT * context)
{
  GSList * walk;

  for (walk = hook_instance->client_handlers; walk != NULL; walk = walk->next)
  {
    GumWinExceptionHandlerEntry * entry =
        (GumWinExceptionHandlerEntry *) walk->data;

    if (entry->func (exception_record, context, entry->user_data))
      return TRUE;
  }

  return hook_instance->system_handler (exception_record, context);
}
