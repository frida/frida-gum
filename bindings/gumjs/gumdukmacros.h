/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_MACROS_H__
#define __GUM_DUK_MACROS_H__

#include "gumdukvalue.h"

typedef struct _GumDukPropertyEntry GumDukPropertyEntry;
struct _GumDukPropertyEntry
{
  gchar * name;
  gpointer getter;
  gpointer setter;
  gint flags;
};

#define GUMJS_RO (DUK_DEFPROP_HAVE_WRITABLE | 0)
#define GUMJS_RW (DUK_DEFPROP_HAVE_WRITABLE | DUK_DEFPROP_WRITABLE)

#define GUMJS_DECLARE_CONSTRUCTOR(N) \
  static int N (duk_context * ctx);
#define GUMJS_DECLARE_FINALIZER(N) \
  static int N (duk_context * ctx);
#define GUMJS_DECLARE_FUNCTION(N) \
  static int N (duk_context * ctx);
#define GUMJS_DECLARE_GETTER(N) \
  static int N (duk_context * ctx);
#define GUMJS_DECLARE_SETTER(N) \
  static int N (duk_context * ctx);

#define GUMJS_DEFINE_CONSTRUCTOR(N) \
  static int N##_impl (duk_context * ctx, GumDukArgs * args); \
  \
  static int \
  N (duk_context * ctx) \
  { \
    GumDukArgs args; \
    \
    args.count = duk_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    duk_get_global_string (ctx, "\xff" "core"); \
    args.core = duk_get_pointer (ctx, -1); \
    duk_pop (ctx); \
    \
    return N##_impl (ctx, args); \
  } \
  \
  static int \
  N##_impl (duk_context * ctx, \
            GumDukArgs * args)
#define GUMJS_DEFINE_FINALIZER(N) \
  static void \
  N (JSObjectRef object)
#define GUMJS_DEFINE_FUNCTION(N) \
  static int N##_impl (duk_context * ctx, GumDukArgs * args); \
  \
  static int \
  N (duk_context * ctx) \
  { \
    GumDukArgs args; \
    \
    args.count = duk_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    duk_get_global_string (ctx, "\xff" "core"); \
    args.core = duk_get_pointer (ctx, -1); \
    duk_pop (ctx); \
    \
    return N##_impl (ctx, args); \
  } \
  \
  static int \
  N##_impl (duk_context * ctx, \
            GumDukArgs * args)
#define GUMJS_DEFINE_GETTER(N) \
  static int N##_impl (duk_context * ctx, GumDukArgs * args); \
  \
  static int \
  N (duk_context * ctx) \
  { \
    GumDukArgs args; \
    \
    args.count = duk_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    duk_get_global_string (ctx, "\xff" "core"); \
    args.core = duk_get_pointer (ctx, -1); \
    duk_pop (ctx); \
    \
    return N##_impl (ctx, args); \
  } \
  \
  static int \
  N##_impl (duk_context * ctx, \
            GumDukArgs * args)
#define GUMJS_DEFINE_SETTER(N) \
  static int N##_impl (duk_context * ctx, GumDukArgs * args); \
  \
  static int \
  N (duk_context * ctx) \
  { \
    GumDukArgs args; \
    \
    args.count = duk_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    duk_get_global_string (ctx, "\xff" "core"); \
    args.core = duk_get_pointer (ctx, -1); \
    duk_pop (ctx); \
    \
    return N##_impl (ctx, args); \
  } \
  \
  static int \
  N##_impl (duk_context * ctx, \
            GumDukArgs * args)

#define GUMJS_ADD_GLOBAL_FUNCTION (N, F, NARGS) \
  duk_push_c_function (ctx, F, NARGS); \
  duk_put_global_string (ctx, N);

void inline gumjs_duk_create_subclass (duk_context * ctx, gchar * parent, gchar * name,
    gpointer constructor, gpointer finalize)
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

	duk_push_c_function (ctx, constructor, 1);
	// [ ... global object create parent parentproto childproto constructor]
	duk_dup (ctx, -2);
	// [ ... global object create parent parentproto childproto constructor childproto]
	duk_put_prop_string (ctx, -2, "prototype");
	// [ ... global object create parent parentproto childproto constructor]
	duk_push_c_function (ctx, finalize, 1);
	// [ ... global object create parent parentproto childproto constructor finalize]
    duk_set_finalizer (ctx, -2);
	// [ ... global object create parent parentproto childproto constructor]
	duk_put_prop_string (ctx, -7, name);
	// [ ... global object create parent parentproto childproto]
    duk_pop_n (ctx, 6);
}


void inline gumjs_duk_add_properties_to_class (duk_context * ctx, gchar * classname,
    GumDukPropertyEntry * entries)
{
  GumDukPropertyEntry * entry;
  duk_push_global_object (ctx);
  // [ global ]
  duk_get_prop_string (ctx, -1, classname);
  // [ global class ]

  for (entry = entries; entry->name != NULL; entry++)
  {
    int idx = 1;
    int flags = DUK_DEFPROP_HAVE_ENUMERABLE | DUK_DEFPROP_ENUMERABLE;
    duk_push_string (ctx, entry->name);
    // [ global class propname ]
    if (entry->getter != NULL)
    {
      idx++;
      flags |= DUK_DEFPROP_HAVE_GETTER;
      duk_push_c_function (ctx, entry->getter, 0);
      // [ global class propname getter ]
    }
    if (entry->setter != NULL)
    {
      idx++;
      flags |= DUK_DEFPROP_HAVE_SETTER;
      duk_push_c_function (ctx, entry->setter, 1);
      // [ global class propname {getter} setter ]
    }

    flags |= entry->flags;

    duk_def_prop (ctx, -idx, flags);
    // [ global class ]
  }

  duk_pop_2 (ctx);
}
#endif
