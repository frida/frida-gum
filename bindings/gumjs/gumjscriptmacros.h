/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_MACROS_H__
#define __GUM_JSCRIPT_MACROS_H__

#include <JavaScriptCore/JavaScriptCore.h>

#define GUM_DECLARE_JSC_CONSTRUCTOR(N) \
  static JSObjectRef N (JSContextRef ctx, JSObjectRef constructor, \
      size_t num_args, const JSValueRef args[], JSValueRef * ex)
#define GUM_DECLARE_JSC_FUNCTION(N) \
  static JSValueRef N (JSContextRef ctx, JSObjectRef function, \
      JSObjectRef this_object, size_t num_args, const JSValueRef args[], \
      JSValueRef * ex)
#define GUM_DECLARE_JSC_GETTER(N) \
  static JSValueRef N (JSContextRef ctx, JSObjectRef object, \
      JSStringRef property_name, JSValueRef * ex)

#define GUM_DEFINE_JSC_CONSTRUCTOR(N) \
  static JSObjectRef \
  N (JSContextRef ctx, \
     JSObjectRef constructor, \
     size_t num_args, \
     const JSValueRef args[], \
     JSValueRef * ex)
#define GUM_DEFINE_JSC_FUNCTION(N) \
  static JSValueRef \
  N (JSContextRef ctx, \
     JSObjectRef function, \
     JSObjectRef this_object, \
     size_t num_args, \
     const JSValueRef args[], \
     JSValueRef * ex)
#define GUM_DEFINE_JSC_GETTER(N) \
  static JSValueRef \
  N (JSContextRef ctx, \
     JSObjectRef object, \
     JSStringRef property_name, \
     JSValueRef * ex)

#endif
