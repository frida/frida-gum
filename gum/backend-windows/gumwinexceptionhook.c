/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumwinexceptionhook.h"

#include "gumx86writer.h"

#include <capstone.h>
#include <tchar.h>

#define GUM_IS_WITHIN_INT32_RANGE(i) ((i) >= G_MININT32 && (i) <= G_MAXINT32)

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

  gpointer trampoline;
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
    csh capstone;
    cs_err err;
    guint offset;

    hook_instance = g_new0 (GumWinExceptionHook, 1);

    ntdll_mod = GetModuleHandle (_T ("ntdll.dll"));
    g_assert (ntdll_mod != NULL);

    hook_instance->dispatcher_impl = GUM_FUNCPTR_TO_POINTER (
        GetProcAddress (ntdll_mod, "KiUserExceptionDispatcher"));
    g_assert (hook_instance->dispatcher_impl != NULL);

    err = cs_open (CS_ARCH_X86, GUM_CPU_MODE, &capstone);
    g_assert_cmpint (err, == , CS_ERR_OK);
    err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
    g_assert_cmpint (err, == , CS_ERR_OK);

    offset = 0;
    while (hook_instance->system_handler == NULL)
    {
      cs_insn * insn;

      cs_disasm_ex (capstone,
          (guint8 *) hook_instance->dispatcher_impl + offset, 16,
          GPOINTER_TO_SIZE (hook_instance->dispatcher_impl) + offset,
          1, &insn);
      g_assert (insn != NULL);

      offset += insn->size;

      if (insn->id == X86_INS_CALL)
      {
        cs_x86_op * op = &insn->detail->x86.operands[0];
        if (op->type == X86_OP_IMM && op->size == 4)
        {
          guint8 * call_begin, * call_end;
          gssize distance;

          call_begin = (guint8 *) insn->address;
          call_end = call_begin + insn->size;

          hook_instance->system_handler = GUM_POINTER_TO_FUNCPTR (
              GumSystemExceptionHandler, op->imm);

          VirtualProtect (hook_instance->dispatcher_impl, 4096,
              PAGE_EXECUTE_READWRITE, &hook_instance->previous_page_protection);
          hook_instance->dispatcher_impl_call_immediate =
              (gint32 *) (call_begin + 1);

          distance = (gssize) gum_win_exception_dispatch - (gssize) call_end;
          if (!GUM_IS_WITHIN_INT32_RANGE (distance))
          {
            GumAddressSpec as;
            GumX86Writer cw;

            as.near_address = hook_instance->dispatcher_impl;
            as.max_distance = (G_MAXINT32 - 16384);
            hook_instance->trampoline =
                gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &as);

            gum_x86_writer_init (&cw, hook_instance->trampoline);
            gum_x86_writer_put_jmp (&cw,
                GUM_FUNCPTR_TO_POINTER (gum_win_exception_dispatch));
            gum_x86_writer_free (&cw);

            distance = (gssize) hook_instance->trampoline - (gssize) call_end;
          }

          *hook_instance->dispatcher_impl_call_immediate = distance;
        }
      }

      cs_free (insn, 1);
    }
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

    if (hook_instance->trampoline != NULL)
      gum_free_pages (hook_instance->trampoline);

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
