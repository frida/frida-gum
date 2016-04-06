/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"
#include "gumprocess.h"
#include "gumspinlock.h"
#include "gumtls.h"

#include <pthread.h>
#include <string.h>
#include <sys/syspage.h>

#define MAX_TMP_TLS_KEYS 5

#include <stdio.h>
//#define DBG_PRINT(fmt, ...) fprintf(stderr, "-----> %s() line %d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define DBG_PRINT(fmt, ...)

typedef struct _GumTmpTlsKey GumTmpTlsKey;

struct _GumTmpTlsKey
{
  GumThreadId tid;
  GumTlsKey key;
  gpointer value;
};

static GumTmpTlsKey _gum_tls_tmp_keys[MAX_TMP_TLS_KEYS];
static GumSpinlock _gum_tls_tmp_keys_lock;
static GRecMutex _gum_tls_mutex;

static gboolean _gum_tls_key_get_tmp_value (GumTlsKey key, gpointer* value);
static void _gum_tls_key_set_tmp_value (GumTlsKey key, gpointer value);
static void _gum_tls_key_delete_tmp_value (GumTlsKey key);
static void* _gum_tls_replacement_pthread_getspecific (pthread_key_t key);
static int _gum_tls_replacement_pthread_setspecific (pthread_key_t key, const void* value);

void
_gum_tls_init (void)
{
  gum_spinlock_init (&_gum_tls_tmp_keys_lock);
  g_rec_mutex_init (&_gum_tls_mutex);
  memset (_gum_tls_tmp_keys, 0, sizeof (_gum_tls_tmp_keys));
}

void
_gum_tls_late_init (void)
{
  GumInterceptor* interceptor = gum_interceptor_obtain ();
  gum_interceptor_begin_transaction (interceptor);
  int ret =0;

  DBG_PRINT("ENTER\n");
  gum_interceptor_replace_function (interceptor, pthread_setspecific, _gum_tls_replacement_pthread_setspecific, NULL);
  gum_interceptor_replace_function (interceptor, pthread_getspecific, _gum_tls_replacement_pthread_getspecific, NULL);

  DBG_PRINT("AFTER GET REPLACE\n");
  gum_interceptor_end_transaction (interceptor);
  DBG_PRINT("RET = %d\n", ret);
}

void
_gum_tls_deinit (void)
{
  printf("tls_deinit before\n");
  GumInterceptor* interceptor = gum_interceptor_obtain ();
  gum_interceptor_begin_transaction (interceptor);
  gum_interceptor_revert_function (interceptor, pthread_getspecific);
  gum_interceptor_revert_function (interceptor, pthread_setspecific);
  gum_interceptor_end_transaction (interceptor);
  printf("tls_deinit after\n");
}


GumTlsKey
gum_tls_key_new (void)
{
  pthread_key_t key;
  gint res;

  GumThreadId tid = gum_process_get_current_thread_id();
  DBG_PRINT("TID = %d\n", tid);

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
  // GumThreadId tid = gum_process_get_current_thread_id();

  gpointer value = NULL;
  if(_gum_tls_key_get_tmp_value (key, &value) == FALSE)
  {
    g_rec_mutex_lock (&_gum_tls_mutex);
    if (key < _cpupage_ptr->tls->__numkeys)
      value = _cpupage_ptr->tls->__keydata[key];
    g_rec_mutex_unlock (&_gum_tls_mutex);
  }

  //DBG_PRINT("TID = %d, KEY = %d, NUMKEYS = %d, PTR = 0x%x\n", tid, key, _cpupage_ptr->tls->__numkeys, value);
  return value;
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  GumThreadId tid = gum_process_get_current_thread_id();
  DBG_PRINT("TID = %d, KEY = %d, PTR=0x%x\n", tid, key, value); // , RET=%d\n", tid, key, value, ret);

  _gum_tls_key_set_tmp_value (key, value);

  // g_rec_mutex_lock (&_gum_tls_mutex);
  if (key < _cpupage_ptr->tls->__numkeys)
  {
       _cpupage_ptr->tls->__keydata[key] = value;
  }
  else
  {
      int res = pthread_setspecific(key, value);
      if(res)
          return;
      // guint new_numkeys = key + 1;
      // DBG_PRINT("About to realloc to %d keyslots\n", new_numkeys);
      // _cpupage_ptr->tls->__keydata = realloc(_cpupage_ptr->tls->__keydata, sizeof(void*) * new_numkeys);
      // memset (&_cpupage_ptr->tls->__keydata[_cpupage_ptr->tls->__numkeys], 0, sizeof(void*) * (new_numkeys - _cpupage_ptr->tls->__numkeys));

      // _cpupage_ptr->tls->__keydata[key] = value;
      // _cpupage_ptr->tls->__numkeys = new_numkeys;
  }
  // g_rec_mutex_unlock (&_gum_tls_mutex);

  _gum_tls_key_delete_tmp_value (key);
}

static gboolean
_gum_tls_key_get_tmp_value (GumTlsKey key, gpointer* value)
{
  guint i;
  GumThreadId tid = gum_process_get_current_thread_id ();
  gboolean found = FALSE;

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    //  DBG_PRINT ("entry %d tid %d key %d\n", i, _gum_tls_tmp_keys[i].tid, _gum_tls_tmp_keys[i].key);
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
_gum_tls_key_set_tmp_value (GumTlsKey key, gpointer value)
{
  guint i;
  GumThreadId tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  // Same TID & KEY
  for (i = 0; i != MAX_TMP_TLS_KEYS; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == tid && _gum_tls_tmp_keys[i].key == key)
    {
      _gum_tls_tmp_keys[i].value = value;
      goto end;
    }
  }

  // Empty slot
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

static void*
_gum_tls_replacement_pthread_getspecific (pthread_key_t key)
{
  DBG_PRINT("KEY = %d\n", key);
  return gum_tls_key_get_value(key);
}

static int
_gum_tls_replacement_pthread_setspecific (pthread_key_t key, const void* value)
{
  DBG_PRINT("KEY = %d, VALUE=%p\n", key, value);
  gum_tls_key_set_value(key, value);
  return 0;
}

