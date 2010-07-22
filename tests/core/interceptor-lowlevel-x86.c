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

#include "interceptor-lowlevel.h"
#ifdef G_OS_WIN32
#define _WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#endif
#include <string.h>

static const UnsupportedFunction unsupported_functions[] =
{
  { "ret",   1, { 0xc3                                           } },
  { "retf",  1, { 0xcb                                           } },
};

static guint8 * executable_page_new (void);
static void executable_page_free (guint8 * page);

UnsupportedFunction *
unsupported_function_list_new (guint * count)
{
  UnsupportedFunction * result;

  result = (UnsupportedFunction *) executable_page_new ();
  memcpy (result, unsupported_functions, sizeof (unsupported_functions));
  *count = G_N_ELEMENTS (unsupported_functions);

  return result;
}

void
unsupported_function_list_free (UnsupportedFunction * functions)
{
  executable_page_free ((guint8 *) functions);
}

#define OPCODE_JMP (0xE9)

ProxyFunc
proxy_func_new_relative_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = executable_page_new ();
  func[0] = OPCODE_JMP;
  *((gint32 *) (func + 1)) =
      (guint8 *) GSIZE_TO_POINTER (target_func) - (func + 5);

  return (ProxyFunc) func;
}

ProxyFunc
proxy_func_new_absolute_indirect_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = executable_page_new ();
  func[0] = 0xff;
  func[1] = 0x25;
#if GLIB_SIZEOF_VOID_P == 4
  *((gpointer *) (func + 2)) = func + 6;
#else
  *((gint32 *) (func + 2)) = 0;
#endif
  *((TargetFunc *) (func + 6)) = target_func;

  return (ProxyFunc) func;
}

ProxyFunc
proxy_func_new_two_jumps_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = executable_page_new ();
  func[0] = OPCODE_JMP;
  *((gint32 *) (func + 1)) = (guint8 *) (func + 20) - (func + 5);

  func[20] = 0xff;
  func[21] = 0x25;
#if GLIB_SIZEOF_VOID_P == 4
  *((gpointer *)   (func + 22)) = func + 30;
#else
  *((gint32 *)     (func + 22)) = 4;
#endif
  *((TargetFunc *) (func + 30)) = target_func;

  return (ProxyFunc) func;
}

ProxyFunc
proxy_func_new_early_call_with_target (TargetFunc target_func)
{
  guint8 * func;

  func = executable_page_new ();
  func[0] = 0xFF; /* push dword [esp + 4] */
  func[1] = 0x74;
  func[2] = 0x24;
  func[3] = 0x04;

  func[4] = 0xe8; /* call */
  *((gssize *) (func + 5)) = ((gssize) GPOINTER_TO_SIZE (target_func))
      - ((gssize) GPOINTER_TO_SIZE (func + 9));

  func[9] = 0x83; /* add esp, 4 */
  func[10] = 0xC4;
  func[11] = 0x04;

  func[12] = 0xC3; /* ret */

  return (ProxyFunc) func;
}

void
proxy_func_free (ProxyFunc proxy_func)
{
  executable_page_free ((guint8 *) (gsize) proxy_func);
}

static guint8 *
executable_page_new (void)
{
  gpointer result;
  guint page_size;

#ifdef G_OS_WIN32
  page_size = 4096; /* FIXME */
  result = VirtualAlloc (NULL, page_size, MEM_COMMIT | MEM_RESERVE,
      PAGE_EXECUTE_READWRITE);
#else
  page_size = sysconf (_SC_PAGE_SIZE);
  g_assert (posix_memalign ((void **) &result, page_size, page_size) == 0);
  g_assert (mprotect (result, page_size,
      PROT_EXEC | PROT_READ | PROT_WRITE) == 0);
#endif

  return (guint8 *) result;
}

static void
executable_page_free (guint8 * page)
{
#ifdef G_OS_WIN32
  VirtualFree (page, 0, MEM_RELEASE);
#else
  free (page);
#endif
}

