/*
* Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
* Copyright (C) 2015 Eloi Vanderbeken <eloi.vanderbeken@synacktiv.com>
*
* Licence: wxWindows Library Licence, Version 3.1
*/

#include "gumtls.h"

#include "gumprocess.h"
#include "gumspinlock.h"

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#if defined (HAVE_I386)

# define MAX_TMP_TLS_KEY 200

typedef struct _GumTmpTlsKey GumTmpTlsKey;

struct _GumTmpTlsKey
{
  GumThreadId tid;
  GumTlsKey key;
  gpointer value;
};

static gpointer _gum_tls_key_get_tmp_value (GumTlsKey key);
static void _gum_tls_key_set_tmp_value (GumTlsKey key, gpointer value);
static void _gum_tls_key_del_tmp_value (GumTlsKey key);

static GumTmpTlsKey _gum_tls_tmp_keys[MAX_TMP_TLS_KEY];
static GumSpinlock _gum_tls_tmp_keys_lock;

#endif

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

void
_gum_tls_init (void)
{
#if defined (HAVE_I386)
  gum_spinlock_init (&_gum_tls_tmp_keys_lock);
  memset (_gum_tls_tmp_keys, 0, sizeof (_gum_tls_tmp_keys));
#endif
}

void
_gum_tls_realize (void)
{
}

void
_gum_tls_deinit (void)
{
}

#if defined (HAVE_I386)

static gpointer
_gum_tls_key_get_tmp_value (GumTlsKey key)
{
  GumThreadId tid;
  gpointer value;
  guint i;

  tid = gum_process_get_current_thread_id ();
  value = NULL;

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEY; i++)
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
_gum_tls_key_set_tmp_value (GumTlsKey key,
                            gpointer value)
{
  GumThreadId tid;
  guint i;

  tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEY; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == 0)
    {
      _gum_tls_tmp_keys[i].tid = tid;
      _gum_tls_tmp_keys[i].key = key;
      _gum_tls_tmp_keys[i].value = value;
      break;
    }
  }
  g_assert (i < MAX_TMP_TLS_KEY);

  gum_spinlock_release (&_gum_tls_tmp_keys_lock);
}

static void
_gum_tls_key_del_tmp_value (GumTlsKey key)
{
  GumThreadId tid;
  guint i;

  tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&_gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEY; i++)
  {
    if (_gum_tls_tmp_keys[i].tid == tid && _gum_tls_tmp_keys[i].key == key)
    {
      memset (&_gum_tls_tmp_keys[i], 0, sizeof (_gum_tls_tmp_keys[i]));
      break;
    }
  }
  g_assert (i < MAX_TMP_TLS_KEY);

  gum_spinlock_release (&_gum_tls_tmp_keys_lock);
}

# if GLIB_SIZEOF_VOID_P == 4

gpointer
gum_tls_key_get_value (GumTlsKey key)
{
  if (key < 64)
  {
    return (gpointer) __readfsdword (3600 + key * sizeof (gpointer));
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer *) __readfsdword (3988);
    if (tls_expansion_slots != NULL)
      return tls_expansion_slots[key - 64];

    return _gum_tls_key_get_tmp_value (key);
  }

  return NULL;
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  if (key < 64)
  {
    __writefsdword (3600 + key * sizeof (gpointer), (DWORD) value);
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer *) __readfsdword (3988);
    if (tls_expansion_slots != NULL)
    {
      tls_expansion_slots[key - 64] = value;
    }
    else
    {
      _gum_tls_key_set_tmp_value (key, value);
      TlsSetValue (key, value);
      _gum_tls_key_del_tmp_value (key);
    }
  }
}

# elif GLIB_SIZEOF_VOID_P == 8

gpointer
gum_tls_key_get_value (GumTlsKey key)
{
  if (key < 64)
  {
    return (gpointer) __readgsqword (0x1480 + key * sizeof (gpointer));
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer) __readgsqword (0x1780);
    if (tls_expansion_slots != NULL)
      return tls_expansion_slots[key - 64];

    return _gum_tls_key_get_tmp_value (key);
  }
  return NULL;
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  if (key < 64)
  {
    __writegsqword (0x1480 + key * sizeof (gpointer), (guint64) value);
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer) __readgsqword (0x1780);
    if (tls_expansion_slots != NULL)
    {
      tls_expansion_slots[key - 64] = value;
    }
    else
    {
      _gum_tls_key_set_tmp_value (key, value);
      TlsSetValue (key, value);
      _gum_tls_key_del_tmp_value (key);
    }
  }
}

# else
#  error Unknown architecture
# endif

#else

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

#endif
