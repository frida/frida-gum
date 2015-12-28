/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukvalue.h"

#include "gumdukscript-priv.h"

GumDukWeakRef *
_gumjs_weak_ref_new (duk_context * ctx,
                     GumDukValue * value,
                     GumDukWeakNotify notify,
                     gpointer data,
                     GDestroyNotify data_destroy)
{
  /* TODO: implement */
  return NULL;
}

void
_gumjs_weak_ref_free (GumDukWeakRef * ref)
{
  /* TODO: implement */
}

gpointer
_gumjs_array_buffer_get_data (duk_context * ctx,
                              GumDukHeapPtr value,
                              gsize * size)
{
  gpointer data;

  if (!_gumjs_array_buffer_try_get_data (ctx, value, &data, size))
    _gumjs_panic (ctx, "failed to get ArrayBuffer data");

  return data;
}

gboolean
_gumjs_array_buffer_try_get_data (duk_context * ctx,
                                  GumDukHeapPtr value,
                                  gpointer * data,
                                  gsize * size)
{
  /* TODO: implement!
  ExecState * exec = toJS (ctx);
  JSLockHolder lock (exec);

  JSValue jsValue = toJS (exec, value);
  ArrayBuffer * buffer = toArrayBuffer (jsValue);
  if (buffer != NULL)
  {
    *data = buffer->data ();
    if (size != NULL)
      *size = buffer->byteLength ();
    return TRUE;
  }
  else
  {
    _gumjs_throw (ctx, exception, "expected an ArrayBuffer");
    return FALSE;
  }
  */
  return FALSE;
}
