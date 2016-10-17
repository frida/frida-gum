/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_MACROS_H__
#define __GUM_V8_MACROS_H__

#include "gumv8value.h"

#define GUMJS_MODULE_TYPE G_PASTE (GumV8, GUMJS_MODULE_NAME)

#define GUMJS_DECLARE_FUNCTION(N) \
  static void N (const FunctionCallbackInfo<Value> & info);

#define GUMJS_DEFINE_FUNCTION(N) \
  static void N##_impl (GUMJS_MODULE_TYPE * module, const GumV8Args * args); \
  \
  static void \
  N (const FunctionCallbackInfo<Value> & info) \
  { \
    GUMJS_MODULE_TYPE * module = (GUMJS_MODULE_TYPE *) \
        info.Data ().As<External> ()->Value (); \
    \
    GumV8Args args; \
    args.info = &info; \
    args.core = module->core; \
    \
    return N##_impl (module, &args); \
  } \
  \
  static void \
  N##_impl (GUMJS_MODULE_TYPE * module, \
            const GumV8Args * args)

#endif
