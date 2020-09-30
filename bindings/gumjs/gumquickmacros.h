/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_MACROS_H__
#define __GUM_QUICK_MACROS_H__

#include "gumquickvalue.h"

#define GUMJS_DECLARE_CONSTRUCTOR(N) \
  static JSValue N (JSContext * ctx, JSValueConst func_obj, \
      JSValueConst this_val, int argc, JSValueConst * argv, int flags);
#define GUMJS_DECLARE_FINALIZER(N) \
  static void N (JSRuntime * rt, JSValue val);
#define GUMJS_DECLARE_FUNCTION(N) \
  static JSValue N (JSContext * ctx, JSValueConst this_val, int argc, \
      JSValueConst * argv);
#define GUMJS_DECLARE_GETTER(N) \
  static JSValue N (JSContext * ctx, JSValueConst this_val);
#define GUMJS_DECLARE_SETTER(N) \
  static JSValue N (JSContext * ctx, JSValueConst this_val, JSValueConst proto);

#define GUMJS_DEFINE_CONSTRUCTOR(N) \
  static int N##_impl (JSContext * ctx, const GumQuickArgs * args); \
  \
  static int \
  N (JSContext * ctx) \
  { \
    GumQuickArgs args; \
    \
    args.count = quick_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    quick_get_global_string (ctx, QUICK_HIDDEN_SYMBOL ("core")); \
    args.core = quick_get_pointer (ctx, -1); \
    quick_pop (ctx); \
    \
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (JSContext * ctx, \
            const GumQuickArgs * args)
#define GUMJS_DEFINE_FINALIZER(N) \
  static int N##_impl (JSContext * ctx, const GumQuickArgs * args); \
  \
  static int \
  N (JSContext * ctx) \
  { \
    GumQuickArgs args; \
    \
    args.count = quick_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    quick_get_global_string (ctx, QUICK_HIDDEN_SYMBOL ("core")); \
    args.core = quick_get_pointer (ctx, -1); \
    quick_pop (ctx); \
    \
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (JSContext * ctx, \
            const GumQuickArgs * args)
#define GUMJS_DEFINE_FUNCTION(N) \
  static int N##_impl (JSContext * ctx, const GumQuickArgs * args); \
  \
  static int \
  N (JSContext * ctx) \
  { \
    GumQuickArgs args; \
    \
    args.count = quick_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    quick_get_global_string (ctx, QUICK_HIDDEN_SYMBOL ("core")); \
    args.core = quick_get_pointer (ctx, -1); \
    quick_pop (ctx); \
    \
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (JSContext * ctx, \
            const GumQuickArgs * args)
#define GUMJS_DEFINE_GETTER(N) \
  static int N##_impl (JSContext * ctx, const GumQuickArgs * args); \
  \
  static int \
  N (JSContext * ctx) \
  { \
    GumQuickArgs args; \
    \
    args.count = quick_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    quick_get_global_string (ctx, QUICK_HIDDEN_SYMBOL ("core")); \
    args.core = quick_get_pointer (ctx, -1); \
    quick_pop (ctx); \
    \
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (JSContext * ctx, \
            const GumQuickArgs * args)
#define GUMJS_DEFINE_SETTER(N) \
  static int N##_impl (JSContext * ctx, const GumQuickArgs * args); \
  \
  static int \
  N (JSContext * ctx) \
  { \
    GumQuickArgs args; \
    \
    args.count = quick_get_top (ctx); \
    \
    args.ctx = ctx; \
    \
    quick_get_global_string (ctx, QUICK_HIDDEN_SYMBOL ("core")); \
    args.core = quick_get_pointer (ctx, -1); \
    quick_pop (ctx); \
    \
    return N##_impl (ctx, &args); \
  } \
  \
  static int \
  N##_impl (JSContext * ctx, \
            const GumQuickArgs * args)

#define GUMJS_ADD_GLOBAL_FUNCTION(N, F, NARGS) \
  quick_push_c_function (ctx, F, NARGS); \
  quick_put_global_string (ctx, N)

#endif
