/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumtls.h"

#include "guminterceptor.h"
#include "gumprocess.h"
#include "gumspinlock.h"

#include <pthread.h>
#include <string.h>
#include <sys/syspage.h>

#define MAX_TMP_TLS_KEYS 5

typedef struct _GumTmpTlsKey GumTmpTlsKey;

struct _GumTmpTlsKey
{
  GumThreadId tid;
  GumTlsKey key;
  gpointer value;
};

static GumTmpTlsKey _gum_tls_tmp_keys[MAX_TMP_TLS_KEYS];
static GumSpinlock _gum_tls_tmp_keys_lock;

static gboolean _gum_tls_key_get_tmp_value (GumTlsKey key, gpointer * value);
static void _gum_tls_key_set_tmp_value (GumTlsKey key, gpointer value);
static void _gum_tls_key_delete_tmp_value (GumTlsKey key);
static void * _gum_tls_replacement_pthread_getspecific (pthread_key_t key);
static int _gum_tls_replacement_pthread_setspecific (pthread_key_t key,
    const void * value);

void
_gum_tls_init (void)
{
  gum_spinlock_init (&_gum_tls_tmp_keys_lock);
  memset (_gum_tls_tmp_keys, 0, sizeof (_gum_tls_tmp_keys));
}

void
_gum_tls_realize (void)
{
  GumInterceptor * interceptor = gum_interceptor_obtain ();

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_replace_function (interceptor, pthread_setspecific,
      _gum_tls_replacement_pthread_setspecific, NULL);
  gum_interceptor_replace_function (interceptor, pthread_getspecific,
      _gum_tls_replacement_pthread_getspecific, NULL);

  gum_interceptor_end_transaction (interceptor);
}

void
_gum_tls_deinit (void)
{
  GumInterceptor * interceptor = gum_interceptor_obtain ();

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_revert_function (interceptor, pthread_getspecific);
  gum_interceptor_revert_function (interceptor, pthread_setspecific);

  gum_interceptor_end_transaction (interceptor);
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
  gpointer value = NULL;

  if (_gum_tls_key_get_tmp_value (key, &value) == FALSE)
  {
    if (key < _cpupage_ptr->tls->__numkeys)
      value = _cpupage_ptr->tls->__keydata[key];
  }

  return value;
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  _gum_tls_key_set_tmp_value (key, value);

  if (key < _cpupage_ptr->tls->__numkeys)
  {
    _cpupage_ptr->tls->__keydata[key] = value;
  }
  else
  {
    int res = pthread_setspecific (key, value);
    if (res != 0)
      return;
  }

  _gum_tls_key_delete_tmp_value (key);
}

static gboolean
_gum_tls_key_get_tmp_value (GumTlsKey key,
                            gpointer * value)
{
  guint i;
  gboolean found = FALSE;
  GumThreadId tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == tid && _gum_tls_tmp_keys[i].key == key)
    {
      *value = _gum_tls_tmp_keys[i].value;
      found = TRUE;
      break;
    }
  }

  gum_spinlock_release (&_gum_tls_tmp_keys_lock);

  return found;
}

static void
_gum_tls_key_set_tmp_value (GumTlsKey key,
                            gpointer value)
{
  guint i;
  GumThreadId tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  /* Same TID & KEY */
  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == tid && _gum_tls_tmp_keys[i].key == key)
    {
      _gum_tls_tmp_keys[i].value = value;
      goto end;
    }
  }

  /* Empty slot */
  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == 0)
    {
      _gum_tls_tmp_keys[i].tid = tid;
      _gum_tls_tmp_keys[i].key = key;
      _gum_tls_tmp_keys[i].value = value;
      goto end;
    }
  }

end:
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

static void *
_gum_tls_replacement_pthread_getspecific (pthread_key_t key)
{
  return gum_tls_key_get_value (key);
}

static int
_gum_tls_replacement_pthread_setspecific (pthread_key_t key,
                                          const void * value)
{
  gum_tls_key_set_value (key, (gpointer) value);

  return 0;
}

