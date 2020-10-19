/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_MACROS_H__
#define __GUM_QUICK_MACROS_H__

#include "gumquickvalue.h"

#define GUMJS_DECLARE_CONSTRUCTOR(N) \
  static JSValue N (JSContext * ctx, JSValueConst this_val, int argc, \
      JSValueConst * argv);
#define GUMJS_DECLARE_FINALIZER(N) \
  static void N (JSRuntime * rt, JSValue val);
#define GUMJS_DECLARE_FUNCTION(N) \
  static JSValue N (JSContext * ctx, JSValueConst this_val, int argc, \
      JSValueConst * argv);
#define GUMJS_DECLARE_GETTER(N) \
  static JSValue N (JSContext * ctx, JSValueConst this_val);
#define GUMJS_DECLARE_SETTER(N) \
  static JSValue N (JSContext * ctx, JSValueConst this_val, JSValueConst val);
#define GUMJS_DECLARE_CALL_HANDLER(N) \
  static JSValue N (JSContext * ctx, JSValueConst func_obj, \
      JSValueConst this_val, int argc, JSValueConst * argv, int flags);

#define GUMJS_DEFINE_CONSTRUCTOR(N) \
  static JSValue N##_impl (JSContext * ctx, JSValueConst new_target, \
      GumQuickArgs * args, GumQuickCore * core); \
  \
  static JSValue \
  N (JSContext * ctx, \
     JSValueConst new_target, \
     int argc, \
     JSValueConst * argv) \
  { \
    JSValue result; \
    GumQuickCore * core; \
    GumQuickArgs args; \
    \
    core = JS_GetContextOpaque (ctx); \
    _gum_quick_args_init (&args, ctx, argc, argv, core); \
    \
    result = N##_impl (ctx, new_target, &args, core); \
    \
    _gum_quick_args_destroy (&args); \
    \
    return result; \
  } \
  \
  static JSValue \
  N##_impl (JSContext * ctx, \
            JSValueConst new_target, \
            GumQuickArgs * args, \
            GumQuickCore * core)
#define GUMJS_DEFINE_FINALIZER(N) \
  static void N##_impl (JSRuntime * rt, JSValue val, GumQuickCore * core); \
  \
  static void \
  N (JSRuntime * rt, \
     JSValue val) \
  { \
    GumQuickCore * core = JS_GetRuntimeOpaque (rt); \
    \
    N##_impl (rt, val, core); \
  } \
  \
  static void \
  N##_impl (JSRuntime * rt, \
            JSValue val, \
            GumQuickCore * core)
#define GUMJS_DEFINE_FUNCTION(N) \
  static JSValue N##_impl (JSContext * ctx, JSValueConst this_val, \
      GumQuickArgs * args, GumQuickCore * core); \
  \
  static JSValue \
  N (JSContext * ctx, \
     JSValueConst this_val, \
     int argc, \
     JSValueConst * argv) \
  { \
    JSValue result; \
    GumQuickCore * core; \
    GumQuickArgs args; \
    \
    core = JS_GetContextOpaque (ctx); \
    _gum_quick_args_init (&args, ctx, argc, argv, core); \
    \
    result = N##_impl (ctx, this_val, &args, core); \
    \
    _gum_quick_args_destroy (&args); \
    \
    return result; \
  } \
  \
  static JSValue \
  N##_impl (JSContext * ctx, \
            JSValueConst this_val, \
            GumQuickArgs * args, \
            GumQuickCore * core)
#define GUMJS_DEFINE_GETTER(N) \
  static JSValue N##_impl (JSContext * ctx, JSValueConst this_val, \
      GumQuickCore * core); \
  \
  static JSValue \
  N (JSContext * ctx, \
     JSValueConst this_val) \
  { \
    GumQuickCore * core = JS_GetContextOpaque (ctx); \
    \
    return N##_impl (ctx, this_val, core); \
  } \
  \
  static JSValue \
  N##_impl (JSContext * ctx, \
            JSValueConst this_val, \
            GumQuickCore * core)
#define GUMJS_DEFINE_SETTER(N) \
  static JSValue N##_impl (JSContext * ctx, JSValueConst this_val, \
      JSValueConst val, GumQuickCore * core); \
  \
  static JSValue \
  N (JSContext * ctx, \
     JSValueConst this_val, \
     JSValueConst val) \
  { \
    GumQuickCore * core = JS_GetContextOpaque (ctx); \
    \
    return N##_impl (ctx, this_val, val, core); \
  } \
  \
  static JSValue \
  N##_impl (JSContext * ctx, \
            JSValueConst this_val, \
            JSValueConst val, \
            GumQuickCore * core)
#define GUMJS_DEFINE_CALL_HANDLER(N) \
  static JSValue N##_impl (JSContext * ctx, JSValueConst func_obj, \
      JSValueConst this_val, GumQuickArgs * args, int flags, \
      GumQuickCore * core); \
  \
  static JSValue \
  N (JSContext * ctx, \
     JSValueConst func_obj, \
     JSValueConst this_val, \
     int argc, \
     JSValueConst * argv, \
     int flags) \
  { \
    JSValue result; \
    GumQuickCore * core; \
    GumQuickArgs args; \
    \
    core = JS_GetContextOpaque (ctx); \
    _gum_quick_args_init (&args, ctx, argc, argv, core); \
    \
    result = N##_impl (ctx, func_obj, this_val, &args, flags, core); \
    \
    _gum_quick_args_destroy (&args); \
    \
    return result; \
  } \
  \
  static JSValue \
  N##_impl (JSContext * ctx, \
            JSValueConst func_obj, \
            JSValueConst this_val, \
            GumQuickArgs * args, \
            int flags, \
            GumQuickCore * core)

#endif
