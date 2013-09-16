/*
 * Copyright (C) 2009-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumprocess.h"

#include "gumwindows.h"

#include <psapi.h>
#include <tlhelp32.h>

static gboolean gum_windows_get_thread_details (DWORD thread_id,
    GumThreadDetails * details);
static void gum_cpu_context_from_windows (const CONTEXT * context,
    GumCpuContext * cpu_context);
static void gum_cpu_context_to_windows (const GumCpuContext * cpu_context,
    CONTEXT * context);
static HMODULE get_module_handle_utf8 (const gchar * module_name);

GumThreadId
gum_process_get_current_thread_id (void)
{
  return GetCurrentThreadId ();
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  gboolean success = FALSE;
  HANDLE thread;
  __declspec (align (64)) CONTEXT context = { 0, };
  GumCpuContext cpu_context;

  thread = OpenThread (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
      THREAD_SUSPEND_RESUME, FALSE, thread_id);
  if (thread == NULL)
    goto beach;

  if (SuspendThread (thread) == (DWORD) -1)
    goto beach;

  context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  if (!GetThreadContext (thread, &context))
    goto beach;

  gum_cpu_context_from_windows (&context, &cpu_context);
  func (thread_id, &cpu_context, user_data);
  gum_cpu_context_to_windows (&cpu_context, &context);

  if (!SetThreadContext (thread, &context))
  {
    ResumeThread (thread);
    goto beach;
  }

  success = ResumeThread (thread) != (DWORD) -1;

beach:
  if (thread != NULL)
    CloseHandle (thread);

  return success;
}

void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data)
{
  DWORD this_process_id;
  HANDLE snapshot;
  THREADENTRY32 entry;

  this_process_id = GetCurrentProcessId ();

  snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    goto beach;

  entry.dwSize = sizeof (entry);
  if (!Thread32First (snapshot, &entry))
    goto beach;

  do
  {
    if (RTL_CONTAINS_FIELD (&entry, entry.dwSize, th32OwnerProcessID) &&
        entry.th32OwnerProcessID == this_process_id)
    {
      GumThreadDetails details;

      if (gum_windows_get_thread_details (entry.th32ThreadID, &details))
      {
        if (!func (&details, user_data))
          break;
      }
    }

    entry.dwSize = sizeof (entry);
  }
  while (Thread32Next (snapshot, &entry));

beach:
  if (snapshot != INVALID_HANDLE_VALUE)
    CloseHandle (snapshot);
}

static gboolean
gum_windows_get_thread_details (DWORD thread_id,
                                GumThreadDetails * details)
{
  gboolean success = FALSE;
  __declspec (align (64)) CONTEXT context = { 0, };

  details->id = thread_id;

  if (thread_id == GetCurrentThreadId ())
  {
    details->state = GUM_THREAD_RUNNING;

    RtlCaptureContext (&context);
    gum_cpu_context_from_windows (&context, &details->cpu_context);

    success = TRUE;
  }
  else
  {
    HANDLE thread;

    thread = OpenThread (THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE,
        thread_id);
    if (thread != NULL)
    {
      DWORD previous_suspend_count;

      previous_suspend_count = SuspendThread (thread);
      if (previous_suspend_count != (DWORD) -1)
      {
        if (previous_suspend_count == 0)
          details->state = GUM_THREAD_RUNNING;
        else
          details->state = GUM_THREAD_STOPPED;

        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext (thread, &context))
        {
          gum_cpu_context_from_windows (&context, &details->cpu_context);
          success = TRUE;
        }

        ResumeThread (thread);
      }

      CloseHandle (thread);
    }
  }

  return success;
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  HANDLE this_process;
  HMODULE first_module;
  DWORD modules_size = 0;
  HMODULE * modules = NULL;
  guint mod_idx;

  this_process = GetCurrentProcess ();

  if (!EnumProcessModules (this_process, &first_module, sizeof (first_module),
      &modules_size))
  {
    goto beach;
  }

  modules = (HMODULE *) g_malloc (modules_size);

  if (!EnumProcessModules (this_process, modules, modules_size, &modules_size))
  {
    goto beach;
  }

  for (mod_idx = 0; mod_idx != modules_size / sizeof (HMODULE); mod_idx++)
  {
    MODULEINFO mi;
    WCHAR module_path_utf16[MAX_PATH];
    gchar * module_path, * module_name;
    GumMemoryRange range;
    gboolean carry_on;

    if (!GetModuleInformation (this_process, modules[mod_idx], &mi,
        sizeof (mi)))
    {
      continue;
    }

    GetModuleFileNameW (modules[mod_idx], module_path_utf16, MAX_PATH);
    module_path_utf16[MAX_PATH - 1] = '\0';
    module_path = g_utf16_to_utf8 ((const gunichar2 *) module_path_utf16, -1,
        NULL, NULL, NULL);
    module_name = strrchr (module_path, '\\') + 1;

    range.base_address = GUM_ADDRESS (mi.lpBaseOfDll);
    range.size = mi.SizeOfImage;

    carry_on = func (module_name, &range, module_path, user_data);

    g_free (module_path);

    if (!carry_on)
      break;
  }

beach:
  g_free (modules);
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  guint8 * cur_base_address;

  cur_base_address = NULL;

  while (TRUE)
  {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret;

    ret = VirtualQuery (cur_base_address, &mbi, sizeof (mbi));
    if (ret == 0)
      break;

    if (mbi.Protect != 0 && (mbi.Protect & PAGE_GUARD) == 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_windows (mbi.Protect);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;

        range.base_address = GUM_ADDRESS (cur_base_address);
        range.size = mbi.RegionSize;

        if (!func (&range, cur_prot, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  gpointer module;
  guint8 * mod_base;
  IMAGE_DOS_HEADER * dos_hdr;
  IMAGE_NT_HEADERS * nt_hdrs;
  IMAGE_EXPORT_DIRECTORY * exp;
  guint8 * exp_begin, * exp_end;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  mod_base = (guint8 *) module;
  dos_hdr = (IMAGE_DOS_HEADER *) module;
  nt_hdrs = (IMAGE_NT_HEADERS *) &mod_base[dos_hdr->e_lfanew];
  exp = (IMAGE_EXPORT_DIRECTORY *)
      &mod_base[nt_hdrs->OptionalHeader.DataDirectory->VirtualAddress];
  exp_begin = mod_base + nt_hdrs->OptionalHeader.DataDirectory->VirtualAddress;
  exp_end = exp_begin + nt_hdrs->OptionalHeader.DataDirectory->Size - 1;

  if (exp->AddressOfNames != 0)
  {
    DWORD * name_rvas, * func_rvas;
    WORD * ord_rvas;
    DWORD index;

    name_rvas = (DWORD *) &mod_base[exp->AddressOfNames];
    ord_rvas = (WORD *) &mod_base[exp->AddressOfNameOrdinals];
    func_rvas = (DWORD *) &mod_base[exp->AddressOfFunctions];

    for (index = 0; index < exp->NumberOfNames; index++)
    {
      DWORD func_rva;
      guint8 * func_address;

      func_rva = func_rvas[ord_rvas[index]];
      func_address = &mod_base[func_rva];
      if (func_address < exp_begin || func_address > exp_end)
      {
        const gchar * func_name = (const gchar *) &mod_base[name_rvas[index]];

        if (!func (func_name, GUM_ADDRESS (func_address), user_data))
          return;
      }
    }
  }
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  HANDLE this_process = GetCurrentProcess ();
  HMODULE module;
  MODULEINFO mi;
  guint8 * cur_base_address, * end_address;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  if (!GetModuleInformation (this_process, module, &mi, sizeof (mi)))
    return;

  cur_base_address = (guint8 *) mi.lpBaseOfDll;
  end_address = (guint8 *) mi.lpBaseOfDll + mi.SizeOfImage;

  do
  {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret;

    ret = VirtualQuery (cur_base_address, &mbi, sizeof (mbi));
    g_assert (ret != 0);

    if (mbi.Protect != 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_windows (mbi.Protect);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;

        range.base_address = GUM_ADDRESS (cur_base_address);
        range.size = mbi.RegionSize;

        if (!func (&range, cur_prot, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
  while (cur_base_address < end_address);
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  return GUM_ADDRESS (get_module_handle_utf8 (module_name));
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  HMODULE module;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return 0;

  return GUM_ADDRESS (GetProcAddress (module, symbol_name));
}

static HMODULE
get_module_handle_utf8 (const gchar * module_name)
{
  HMODULE module;
  gunichar2 * wide_name;

  wide_name = g_utf8_to_utf16 (module_name, -1, NULL, NULL, NULL);
  module = GetModuleHandleW ((LPCWSTR) wide_name);
  g_free (wide_name);

  return module;
}

static void
gum_cpu_context_from_windows (const CONTEXT * context,
                              GumCpuContext * cpu_context)
{
#if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = context->Eip;

  cpu_context->edi = context->Edi;
  cpu_context->esi = context->Esi;
  cpu_context->ebp = context->Ebp;
  cpu_context->esp = context->Esp;
  cpu_context->ebx = context->Ebx;
  cpu_context->edx = context->Edx;
  cpu_context->ecx = context->Ecx;
  cpu_context->eax = context->Eax;
#else
  cpu_context->rip = context->Rip;

  cpu_context->r15 = context->R15;
  cpu_context->r14 = context->R14;
  cpu_context->r13 = context->R13;
  cpu_context->r12 = context->R12;
  cpu_context->r11 = context->R11;
  cpu_context->r10 = context->R10;
  cpu_context->r9 = context->R9;
  cpu_context->r8 = context->R8;

  cpu_context->rdi = context->Rdi;
  cpu_context->rsi = context->Rsi;
  cpu_context->rbp = context->Rbp;
  cpu_context->rsp = context->Rsp;
  cpu_context->rbx = context->Rbx;
  cpu_context->rdx = context->Rdx;
  cpu_context->rcx = context->Rcx;
  cpu_context->rax = context->Rax;
#endif
}

static void
gum_cpu_context_to_windows (const GumCpuContext * cpu_context,
                            CONTEXT * context)
{
#if GLIB_SIZEOF_VOID_P == 4
  context->Eip = cpu_context->eip;

  context->Edi = cpu_context->edi;
  context->Esi = cpu_context->esi;
  context->Ebp = cpu_context->ebp;
  context->Esp = cpu_context->esp;
  context->Ebx = cpu_context->ebx;
  context->Edx = cpu_context->edx;
  context->Ecx = cpu_context->ecx;
  context->Eax = cpu_context->eax;
#else
  context->Rip = cpu_context->rip;

  context->R15 = cpu_context->r15;
  context->R14 = cpu_context->r14;
  context->R13 = cpu_context->r13;
  context->R12 = cpu_context->r12;
  context->R11 = cpu_context->r11;
  context->R10 = cpu_context->r10;
  context->R9 = cpu_context->r9;
  context->R8 = cpu_context->r8;

  context->Rdi = cpu_context->rdi;
  context->Rsi = cpu_context->rsi;
  context->Rbp = cpu_context->rbp;
  context->Rsp = cpu_context->rsp;
  context->Rbx = cpu_context->rbx;
  context->Rdx = cpu_context->rdx;
  context->Rcx = cpu_context->rcx;
  context->Rax = cpu_context->rax;
#endif
}
