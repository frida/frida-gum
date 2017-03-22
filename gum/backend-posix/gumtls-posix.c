/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumtls.h"

#include <pthread.h>

void
_gum_tls_init (void)
{
}

void
_gum_tls_realize (void)
{
}

void
_gum_tls_deinit (void)
{
}

GumTlsKey
gum_tls_key_new (void)
{
  pthread_key_t key;
  gint res;

  res = pthread_key_create (&key, NULL);
  g_assert_cmpint (res, ==, 0);

  return key;
}

void
gum_tls_key_free (GumTlsKey key)
{
  pthread_key_delete (key);
}

gpointer
gum_tls_key_get_value (GumTlsKey key)
{
  return pthread_getspecific (key);
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  pthread_setspecific (key, value);
}
