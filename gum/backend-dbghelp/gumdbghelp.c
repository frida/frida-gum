/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumdbghelp.h"

struct _GumDbgHelpImplPrivate
{
  HMODULE module;
};

static HMODULE load_dbghelp (void);

static void gum_dbghelp_impl_lock (void);
static void gum_dbghelp_impl_unlock (void);

#define INIT_IMPL_FUNC(func) \
    impl->##func = GSIZE_TO_POINTER (GetProcAddress (mod, G_STRINGIFY (func)));\
    g_assert (impl->##func != NULL)

GumDbgHelpImpl *
gum_dbghelp_impl_obtain (void)
{
  GumDbgHelpImpl * impl;
  HMODULE mod;

  impl = g_new0 (GumDbgHelpImpl, 1);
  impl->priv = g_new (GumDbgHelpImplPrivate, 1);
  impl->priv->module = load_dbghelp ();

  mod = impl->priv->module;

  INIT_IMPL_FUNC (StackWalk64);
  INIT_IMPL_FUNC (SymInitialize);
  INIT_IMPL_FUNC (SymEnumSymbols);
  INIT_IMPL_FUNC (SymFromAddr);
  INIT_IMPL_FUNC (SymFunctionTableAccess64);
  INIT_IMPL_FUNC (SymGetLineFromAddr64);
  INIT_IMPL_FUNC (SymGetModuleBase64);
  INIT_IMPL_FUNC (SymGetTypeInfo);

  impl->Lock = gum_dbghelp_impl_lock;
  impl->Unlock = gum_dbghelp_impl_unlock;

  return impl;
}

void
gum_dbghelp_impl_release (GumDbgHelpImpl * impl)
{
  FreeLibrary (impl->priv->module);
  g_free (impl->priv);
  g_free (impl);
}

static HMODULE
load_dbghelp (void)
{
  HMODULE mod;
  WCHAR path[MAX_PATH + 1] = { 0, };
  WCHAR * filename;

  mod = GetModuleHandleW (NULL);
  g_assert (mod != NULL);

  if (GetModuleFileNameW (mod, path, MAX_PATH) == 0)
    return NULL;

  filename = wcsrchr (path, L'\\');
  g_assert (filename != NULL);
  filename++;
  memcpy (filename, L"dbghelp.dll", (11 + 1) * sizeof (WCHAR));

  return LoadLibraryW (path);
}

static GStaticMutex _gum_dbghelp_mutex = G_STATIC_MUTEX_INIT;

static void
gum_dbghelp_impl_lock (void)
{
  g_static_mutex_lock (&_gum_dbghelp_mutex);
}

static void
gum_dbghelp_impl_unlock (void)
{
  g_static_mutex_unlock (&_gum_dbghelp_mutex);
}
