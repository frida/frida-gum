/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumtls.h"

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

GumTlsKey
gum_tls_key_new (void)
{
  DWORD res;

  res = TlsAlloc ();
  g_assert (res != TLS_OUT_OF_INDEXES);

  return res;
}

void
gum_tls_key_free (GumTlsKey key)
{
  TlsFree (key);
}

gpointer
gum_tls_key_get_value (GumTlsKey key)
{
  return TlsGetValue (key);
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  TlsSetValue (key, value);
}
