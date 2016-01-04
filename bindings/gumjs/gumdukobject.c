/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukobject.h"

void
_gumjs_duk_create_subclass (duk_context * ctx,
                            const gchar * parent,
                            const gchar * name,
                            gpointer constructor,
                            gint constructor_nargs,
                            gpointer finalize)
{
  duk_push_global_object (ctx);
  // [ ... global ]
  duk_get_prop_string (ctx, -1, "Object");
  // [ ... global object ]
  duk_get_prop_string (ctx, -1, "create");
  // [ ... global object create ]

  duk_get_prop_string (ctx, -3, parent);
  // [ ... global object create parent ]
  duk_get_prop_string (ctx, -1, "prototype");
  // [ ... global object create parent parentproto ]
  duk_dup (ctx, -3);
  // [ ... global object create parent parentproto create]
  duk_dup (ctx, -2);
  // [ ... global object create parent parentproto create parentproto]
  duk_call (ctx, 1);
  // [ ... global object create parent parentproto childproto]

  if (constructor)
    duk_push_c_function (ctx, constructor, constructor_nargs);
  else
    duk_push_object (ctx);

  // [ ... global object create parent parentproto childproto constructor]
  duk_dup (ctx, -2);
  // [ ... global object create parent parentproto childproto constructor
  //       childproto]
  if (finalize)
  {
    duk_push_c_function (ctx, finalize, 1);
    // [ ... global object create parent parentproto childproto constructor
    //       childproto finalize]
    duk_set_finalizer (ctx, -2);
    // [ ... global object create parent parentproto childproto constructor
    //       childproto]
  }
  duk_put_prop_string (ctx, -2, "prototype");
  // [ ... global object create parent parentproto childproto constructor]
  duk_put_prop_string (ctx, -7, name);
  // [ ... global object create parent parentproto childproto]
  duk_pop_n (ctx, 6);
}

void
_gumjs_duk_add_properties_to_class_by_heapptr (duk_context * ctx,
                                               GumDukHeapPtr klass,
                                               const GumDukPropertyEntry * entries)
{
  const GumDukPropertyEntry * entry;
  duk_push_heapptr (ctx, klass);
  // [ proto ]

  for (entry = entries; entry->name != NULL; entry++)
  {
    int idx = 1;
    int flags = DUK_DEFPROP_HAVE_ENUMERABLE | DUK_DEFPROP_ENUMERABLE;

    duk_push_string (ctx, entry->name);
    idx++;
    // [ proto propname ]
    if (entry->getter != NULL)
    {
      idx++;
      flags |= DUK_DEFPROP_HAVE_GETTER;
      duk_push_c_function (ctx, entry->getter, 0);
      // [ proto propname getter ]
    }
    if (entry->setter != NULL)
    {
      idx++;
      flags |= DUK_DEFPROP_HAVE_SETTER;
      duk_push_c_function (ctx, entry->setter, 1);
      // [ proto propname {getter} setter ]
    }

    duk_def_prop (ctx, -idx, flags);
    // [ proto ]
  }

  duk_pop (ctx);
  // []
}

void
_gumjs_duk_add_properties_to_class (duk_context * ctx,
                                    gchar * classname,
                                    const GumDukPropertyEntry * entries)
{
  const GumDukPropertyEntry * entry;

  duk_get_global_string (ctx, classname);
  // [ class ]
  duk_get_prop_string (ctx, -1, "prototype");
  // [ class proto ]
  _gumjs_duk_add_properties_to_class_by_heapptr (ctx,
          duk_require_heapptr (ctx, -1), entries);
  duk_pop_2 (ctx);
  // []
}

gboolean
_gumjs_is_arg0_equal_to_prototype (duk_context * ctx,
                                   const gchar * class_name)
{
  gboolean result;

  duk_get_global_string (ctx, class_name);
  // [ arg0 ... class ]
  duk_get_prop_string (ctx, -1, "prototype");
  // [ arg0 ... class proto ]
  result = duk_equals (ctx, 0, -1);
  duk_pop_2 (ctx);

  return result;
}

GumDukHeapPtr
_gumjs_duk_get_this (duk_context * ctx)
{
  GumDukHeapPtr result;

  duk_push_this (ctx);
  result = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  return result;
}

void
_gumjs_duk_protect (duk_context * ctx,
                    GumDukHeapPtr object)
{
  gchar name[256];

  sprintf (name, "\xff" "protected_%p", object);

  duk_push_global_stash (ctx);
  // [ stash ]
  duk_get_prop_string (ctx, -1, name);
  // [ stash protprop ]
  if (duk_is_undefined (ctx, -1))
  {
    duk_pop (ctx);
    // [ stash ]
    duk_push_heapptr (ctx, object);
    // [ stash object ]
    duk_put_prop_string (ctx, -2, name);
    // [ stash ]
  }
  else
  {
    duk_pop (ctx);
    // [ stash ]
  }
  duk_pop (ctx);
  // []
}

void
_gumjs_duk_unprotect (duk_context * ctx,
                      GumDukHeapPtr object)
{
  gchar name[256];

  sprintf (name, "\xff" "protected_%p", object);

  duk_push_global_stash (ctx);
  // [ stash ]
  duk_get_prop_string (ctx, -1, name);
  // [ stash protprop ]
  if (duk_is_undefined (ctx, -1))
  {
    duk_pop (ctx);
    // [ stash ]
  }
  else
  {
    duk_pop (ctx);
    // [ stash ]
    duk_del_prop_string (ctx, -1, name);
  }
  duk_pop (ctx);
  // [ ]
}

GumDukHeapPtr
_gumjs_duk_get_heapptr (duk_context * ctx,
                        gint idx)
{
  GumDukHeapPtr result;

  result = duk_get_heapptr (ctx, idx);
  _gumjs_duk_protect (ctx, result);

  return result;
}

GumDukHeapPtr
_gumjs_duk_require_heapptr (duk_context * ctx,
                            gint idx)
{
  GumDukHeapPtr result;

  result = duk_require_heapptr (ctx, idx);
  _gumjs_duk_protect (ctx, result);

  return result;
}

void
_gumjs_duk_release_heapptr (duk_context * ctx,
                            GumDukHeapPtr heapptr)
{
  _gumjs_duk_unprotect (ctx, heapptr);
}

GumDukHeapPtr
_gumjs_duk_create_proxy_accessors (duk_context * ctx,
                                   gpointer getter,
                                   gpointer setter)
{
  gpointer result;

  duk_get_global_string (ctx, "Proxy");
  // [ Proxy ]
  duk_push_object (ctx);
  // [ Proxy targetobj ]
  duk_push_object (ctx);
  // [ Proxy targetobj handlerobj ]
  if (getter)
  {
    duk_push_c_function (ctx, getter, 3);
    // [ Proxy targetobj handlerobj getter ]
    duk_put_prop_string (ctx, -2, "get");
    // [ Proxy targetobj handlerobj ]
  }
  if (setter)
  {
    duk_push_c_function (ctx, setter, 4);
    // [ Proxy targetobj handlerobj setter ]
    duk_put_prop_string (ctx, -2, "set");
    // [ Proxy targetobj handlerobj ]
  }
  // [ Proxy targetobj handlerobj ]
  duk_new (ctx, 2);
  // [ proxyinst ]
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  return result;
}
