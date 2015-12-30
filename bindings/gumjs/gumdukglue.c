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

gboolean
_gumjs_array_buffer_try_get_data (duk_context * ctx,
                                  GumDukHeapPtr value,
                                  gpointer * data,
                                  gsize * size)
{
  printf ("in _gumjs_array_buffer_try_get_data\n");
  duk_push_heapptr (ctx, value);
  duk_dump_context_stdout (ctx);

  printf ("data: %p, size: %d\n", *data, size);
  *data = duk_get_buffer_data (ctx, -1, size);
  printf ("data: %p, size: %d\n", *data, size);
  duk_pop (ctx);
  return TRUE;
}

gpointer
_gumjs_array_buffer_get_data (duk_context * ctx,
                              GumDukHeapPtr value,
                              gsize * size)
{
  gpointer data;

  if (!_gumjs_array_buffer_try_get_data (ctx, value, &data, size))
    _gumjs_panic (ctx, "failed to get ArrayBuffer data");

  printf ("data: %p, size: %d\n", data, size);
  return data;
}

