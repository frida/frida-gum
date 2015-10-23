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
  static JSValueRef \
  N (JSContextRef ctx, \
     JSObjectRef object, \
     JSStringRef property_name, \
     JSValueRef * exception)

#endif
