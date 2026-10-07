/*
 * Copyright (C) 2010-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumansi.h"

#if defined (HAVE_WINDOWS)
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#elif defined (G_OS_NONE)
# include <string.h>
# include <gum/gumbarebone.h>
#endif

gboolean
_gum_ansi_is_supported (void)
{
#if defined (HAVE_WINDOWS)
  return TRUE;
#elif defined (G_OS_UNIX)
  return FALSE;
#else
  return strcmp (gum_barebone_query_platform (), "windows") == 0;
#endif
}

gchar *
_gum_ansi_string_to_utf8 (const gchar * str_ansi,
                          gint length)
{
#if defined (HAVE_WINDOWS)
  gint str_utf16_length;
  gsize str_utf16_size;
  WCHAR * str_utf16;
  gchar * str_utf8;

  if (length < 0)
    length = (gint) strlen (str_ansi);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      NULL, 0);
  str_utf16_size = (str_utf16_length + 1) * sizeof (WCHAR);
  str_utf16 = g_malloc (str_utf16_size);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      str_utf16, str_utf16_length);
  str_utf16[str_utf16_length] = L'\0';

  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);

  g_free (str_utf16);

  return str_utf8;
#elif defined (G_OS_UNIX)
  return NULL;
#else
  return gum_barebone_ansi_string_to_utf8 (str_ansi, length);
#endif
}

gchar *
_gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
#if defined (HAVE_WINDOWS)
  WCHAR * str_utf16;
  gchar * str_ansi;
  gint str_ansi_size;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  str_ansi_size = WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      NULL, 0, NULL, NULL);
  str_ansi = g_malloc (str_ansi_size);

  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);

  g_free (str_utf16);

  return str_ansi;
#elif defined (G_OS_UNIX)
  return NULL;
#else
  return gum_barebone_ansi_string_from_utf8 (str_utf8);
#endif
}
