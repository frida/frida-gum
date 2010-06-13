/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#define VC_EXTRALEAN
#include <windows.h>

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  gunichar2 * wide_name;
  gpointer module;
  guint8 * mod_base;
  IMAGE_DOS_HEADER * dos_hdr;
  IMAGE_NT_HEADERS * nt_hdrs;
  IMAGE_EXPORT_DIRECTORY * exp;
  guint8 * exp_begin, * exp_end;

  wide_name = g_utf8_to_utf16 (module_name, -1, NULL, NULL, NULL);
  module = GetModuleHandleW (wide_name);
  g_free (wide_name);

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
