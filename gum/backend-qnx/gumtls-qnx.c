/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess.h"
#include "gumspinlock.h"
#include "gumtls.h"

#include <pthread.h>
#include <sys/syspage.h>

#define MAX_TMP_TLS_KEYS 200
typedef struct _GumTmpTlsKey GumTmpTlsKey;

struct _GumTmpTlsKey{
  GumThreadId tid;
  GumTlsKey key;
  gpointer value;
};

static GumTmpTlsKey _gum_tls_tmp_keys[MAX_TMP_TLS_KEYS];
static GumSpinlock _gum_tls_tmp_keys_lock;

static gpointer _gum_tls_key_get_tmp_value (GumTlsKey key);
static void _gum_tls_key_set_tmp_value (GumTlsKey key, gpointer value);
static void _gum_tls_key_delete_tmp_value (GumTlsKey key);

void
_gum_tls_init (void)
{
  gum_spinlock_init (&_gum_tls_tmp_keys_lock);
  memset (_gum_tls_tmp_keys, 0, sizeof (_gum_tls_tmp_keys));
}

static gpointer
_gum_tls_key_get_tmp_value (GumTlsKey key)
{
  guint i;
  GumThreadId tid = gum_process_get_current_thread_id ();
  gpointer value = NULL;

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == tid && _gum_tls_tmp_keys[i].key == key)
    {
      value = _gum_tls_tmp_keys[i].value;
      break;
    }
  }

  gum_spinlock_release (&_gum_tls_tmp_keys_lock);

  return value;
}

static void
_gum_tls_key_set_tmp_value (GumTlsKey key, gpointer value)
{
  guint i;
  GumThreadId tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == 0)
    {
      _gum_tls_tmp_keys[i].tid = tid;
      _gum_tls_tmp_keys[i].key = key;
      _gum_tls_tmp_keys[i].value = value;
      break;
    }
  }
  g_assert (i < MAX_TMP_TLS_KEYS);

  gum_spinlock_release (&_gum_tls_tmp_keys_lock);
}

static void
_gum_tls_key_delete_tmp_value (GumTlsKey key)
{
  guint i;
  GumThreadId tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == tid && _gum_tls_tmp_keys[i].key == key)
    {
      memset (&_gum_tls_tmp_keys[i], 0, sizeof (_gum_tls_tmp_keys[i]));
      break;
    }
  }
  g_assert (i < MAX_TMP_TLS_KEYS);

  gum_spinlock_release (&_gum_tls_tmp_keys_lock);
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
  if (key >= _cpupage_ptr->tls->__numkeys)
    return _gum_tls_key_get_tmp_value (key);
  else
    return _cpupage_ptr->tls->__keydata[key];
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  _gum_tls_key_set_tmp_value (key, value);
  pthread_setspecific (key, value);
  _gum_tls_key_delete_tmp_value (key);
}
