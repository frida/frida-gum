/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_MACROS_H__
#define __GUM_JSCRIPT_MACROS_H__

#include "gumjscriptvalue.h"

#define GUMJS_DECLARE_CONSTRUCTOR(N) \
  static JSObjectRef N (JSContextRef ctx, JSObjectRef constructor, \
      size_t argument_count, const JSValueRef arguments[], \
      JSValueRef * exception);
#define GUMJS_DECLARE_FUNCTION(N) \
  static JSValueRef N (JSContextRef ctx, JSObjectRef function, \
      JSObjectRef this_object, size_t argument_count, \
      const JSValueRef arguments[], JSValueRef * exception);
#define GUMJS_DECLARE_GETTER(N) \
  static JSValueRef N (JSContextRef ctx, JSObjectRef object, \
      JSStringRef property_name, JSValueRef * exception);
#define GUMJS_DECLARE_SETTER(N) \
  static bool N (JSContextRef ctx, JSObjectRef object, \
      JSStringRef property_name, JSValueRef value, JSValueRef * exception);

#define GUMJS_DEFINE_CONSTRUCTOR(N) \
  static JSObjectRef N##_impl (JSContextRef ctx, JSObjectRef constructor, \
      const GumScriptArgs * args, JSValueRef * exception); \
  \
  static JSObjectRef \
  N (JSContextRef ctx, \
     JSObjectRef constructor, \
     size_t argument_count, \
     const JSValueRef arguments[], \
     JSValueRef * exception) \
  { \
    GumScriptArgs args; \
    \
    args.count = argument_count; \
    args.values = arguments; \
    args.exception = exception; \
    \
    args.ctx = ctx; \
    args.core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx)); \
    \
    return N##_impl (ctx, constructor, &args, exception); \
  } \
  \
  static JSObjectRef \
  N##_impl (JSContextRef ctx, \
            JSObjectRef constructor, \
            const GumScriptArgs * args, \
            JSValueRef * exception)
#define GUMJS_DEFINE_FUNCTION(N) \
  static JSValueRef N##_impl (JSContextRef ctx, JSObjectRef function, \
      JSObjectRef this_object, const GumScriptArgs * args, \
      JSValueRef * exception); \
  \
  static JSValueRef \
  N (JSContextRef ctx, \
     JSObjectRef function, \
     JSObjectRef this_object, \
     size_t argument_count, \
     const JSValueRef arguments[], \
     JSValueRef * exception) \
  { \
    GumScriptArgs args; \
    \
    args.count = argument_count; \
    args.values = arguments; \
    args.exception = exception; \
    \
    args.ctx = ctx; \
    args.core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx)); \
    \
    return N##_impl (ctx, function, this_object, &args, exception); \
  } \
  \
  static JSValueRef \
  N##_impl (JSContextRef ctx, \
           JSObjectRef function, \
           JSObjectRef this_object, \
           const GumScriptArgs * args, \
           JSValueRef * exception)
#define GUMJS_DEFINE_GETTER(N) \
  static JSValueRef N##_impl (JSContextRef ctx, JSObjectRef object, \
      JSStringRef property_name, const GumScriptArgs * args, \
      JSValueRef * exception); \
  \
  static JSValueRef \
  N (JSContextRef ctx, \
     JSObjectRef object, \
     JSStringRef property_name, \
     JSValueRef * exception) \
  { \
    GumScriptArgs args; \
    \
    args.count = 0; \
    args.values = NULL; \
    args.exception = exception; \
    \
    args.ctx = ctx; \
    args.core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx)); \
    \
    return N##_impl (ctx, object, property_name, &args, exception); \
  } \
  \
  static JSValueRef \
  N##_impl (JSContextRef ctx, \
            JSObjectRef object, \
            JSStringRef property_name, \
            const GumScriptArgs * args, \
            JSValueRef * exception)
#define GUMJS_DEFINE_SETTER(N) \
  static bool N##_impl (JSContextRef ctx, JSObjectRef object, \
      JSStringRef property_name, const GumScriptArgs * args, \
      JSValueRef * exception); \
  \
  static bool \
  N (JSContextRef ctx, \
     JSObjectRef object, \
     JSStringRef property_name, \
     JSValueRef value, \
     JSValueRef * exception) \
  { \
    GumScriptArgs args; \
    \
    args.count = 1; \
    args.values = &value; \
    args.exception = exception; \
    \
    args.ctx = ctx; \
    args.core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx)); \
    \
    return N##_impl (ctx, object, property_name, &args, exception); \
  } \
  \
  static bool \
  N##_impl (JSContextRef ctx, \
            JSObjectRef object, \
            JSStringRef property_name, \
            const GumScriptArgs * args, \
            JSValueRef * exception)

#endif
