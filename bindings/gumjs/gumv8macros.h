/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_MACROS_H__
#define __GUM_V8_MACROS_H__

#include "gumv8value.h"

#define GUMJS_MODULE_TYPE G_PASTE (GumV8, GUMJS_MODULE_NAME)

#define GUMJS_DECLARE_CONSTRUCTOR GUMJS_DECLARE_FUNCTION
#define GUMJS_DECLARE_FUNCTION(N) \
  static void N (const FunctionCallbackInfo<Value> & info);

#define GUMJS_DEFINE_CONSTRUCTOR GUMJS_DEFINE_FUNCTION
#define GUMJS_DEFINE_FUNCTION(N) \
  static void N##_impl (GUMJS_MODULE_TYPE * module, const GumV8Args * args); \
  \
  static void \
  N (const FunctionCallbackInfo<Value> & info) \
  { \
    auto module = static_cast<GUMJS_MODULE_TYPE *> ( \
        info.Data ().As<External> ()->Value ()); \
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
#define GUMJS_DEFINE_METHOD(C, N) \
  static void N##_impl (G_PASTE (GumV8, C) * self, const GumV8Args * args); \
  \
  static void \
  N (const FunctionCallbackInfo<Value> & info) \
  { \
    auto self = static_cast<G_PASTE (GumV8, C) *> ( \
        info.Holder ()->GetAlignedPointerFromInternalField (0)); \
    \
    GumV8Args args; \
    args.info = &info; \
    args.core = self->module->core; \
    \
    return N##_impl (self, &args); \
  } \
  \
  static void \
  N##_impl (G_PASTE (GumV8, C) * self, \
            const GumV8Args * args)

#endif
