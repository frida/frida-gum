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
