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

#define GUMJS_DEFINE_CONSTRUCTOR(N) \
  struct GumV8Closure_##N \
  { \
  public: \
    GumV8Closure_##N (const FunctionCallbackInfo<Value> & info) \
      : wrapper (info.Holder ()), \
        module (static_cast<GUMJS_MODULE_TYPE *> ( \
            info.Data ().As<External> ()->Value ())), \
        core (module->core), \
        args (&_args), \
        info (info), \
        isolate (core->isolate) \
    { \
      _args.info = &info; \
      _args.core = core; \
    } \
    \
    void invoke (); \
    \
  protected: \
    Local<Object> wrapper; \
    GUMJS_MODULE_TYPE * module; \
    GumV8Core * core; \
    const GumV8Args * args; \
    const FunctionCallbackInfo<Value> & info; \
    Isolate * isolate; \
    \
    GumV8Args _args; \
  }; \
  \
  static void \
  N (const FunctionCallbackInfo<Value> & info) \
  { \
    GumV8Closure_##N closure (info); \
    closure.invoke (); \
  } \
  \
  void \
  GumV8Closure_##N::invoke ()
#define GUMJS_DEFINE_FUNCTION(N) \
  class GumV8Closure_##N \
  { \
  public: \
    GumV8Closure_##N (const FunctionCallbackInfo<Value> & info) \
      : module (static_cast<GUMJS_MODULE_TYPE *> ( \
            info.Data ().As<External> ()->Value ())), \
        core (module->core), \
        args (&_args), \
        info (info), \
        isolate (core->isolate) \
    { \
      _args.info = &info; \
      _args.core = core; \
    } \
    \
    void invoke (); \
    \
  protected: \
    GUMJS_MODULE_TYPE * module; \
    GumV8Core * core; \
    const GumV8Args * args; \
    const FunctionCallbackInfo<Value> & info; \
    Isolate * isolate; \
    \
    GumV8Args _args; \
  }; \
  \
  static void \
  N (const FunctionCallbackInfo<Value> & info) \
  { \
    GumV8Closure_##N closure (info); \
    closure.invoke (); \
  } \
  \
  void \
  GumV8Closure_##N::invoke ()
#define GUMJS_DEFINE_METHOD(N, C) \
  struct GumV8Closure_##N \
  { \
  public: \
    GumV8Closure_##N (const FunctionCallbackInfo<Value> & info) \
      : wrapper (info.Holder ()), \
        self (static_cast<C *> ( \
            wrapper->GetAlignedPointerFromInternalField (0))), \
        module (static_cast<GUMJS_MODULE_TYPE *> ( \
            info.Data ().As<External> ()->Value ())), \
        core (module->core), \
        args (&_args), \
        info (info), \
        isolate (core->isolate) \
    { \
      _args.info = &info; \
      _args.core = core; \
    } \
    \
    void invoke (); \
    \
  protected: \
    Local<Object> wrapper; \
    C * self; \
    GUMJS_MODULE_TYPE * module; \
    GumV8Core * core; \
    const GumV8Args * args; \
    const FunctionCallbackInfo<Value> & info; \
    Isolate * isolate; \
    \
    GumV8Args _args; \
  }; \
  \
  static void \
  N (const FunctionCallbackInfo<Value> & info) \
  { \
    GumV8Closure_##N closure (info); \
    closure.invoke (); \
  } \
  \
  void \
  GumV8Closure_##N::invoke ()

#endif
