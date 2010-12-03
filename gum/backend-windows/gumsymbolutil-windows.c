/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumsymbolutil.h"

#include "gumwindows.h"

#include <psapi.h>

static HMODULE get_module_handle_utf8 (const gchar * module_name);

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  HANDLE this_process = GetCurrentProcess ();
  HMODULE first_module;
  DWORD modules_size = 0;
  HMODULE * modules = NULL;
  guint mod_idx;

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

    carry_on = func (module_name, mi.lpBaseOfDll, module_path, user_data);

    g_free (module_path);

    if (!carry_on)
      break;
  }

beach:
  g_free (modules);
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

  mod_base = module;
  dos_hdr = module;
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

        if (!func (func_name, func_address, user_data))
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

      if ((cur_prot & prot) != 0)
      {
        GumMemoryRange range;

        range.base_address = cur_base_address;
        range.size = mbi.RegionSize;

        if (!func (&range, cur_prot, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
  while (cur_base_address < end_address);
}

gpointer
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * export_name)
{
  HMODULE module;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return NULL;

  return GUM_FUNCPTR_TO_POINTER (GetProcAddress (module, export_name));
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
