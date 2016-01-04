/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_MACROS_H__
#define __GUM_DUK_MACROS_H__

#include "gumdukobject.h"
#include "gumdukvalue.h"

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
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (duk_context * ctx, \
            GumDukArgs * args)
#define GUMJS_DEFINE_FINALIZER(N) \
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
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (duk_context * ctx, \
            GumDukArgs * args)
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
    return N##_impl (ctx, &args); \
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
    return N##_impl (ctx, &args); \
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
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (duk_context * ctx, \
            GumDukArgs * args)

#define GUMJS_ADD_GLOBAL_FUNCTION(N, F, NARGS) \
  duk_push_c_function (ctx, F, NARGS); \
  duk_put_global_string (ctx, N)

#endif
