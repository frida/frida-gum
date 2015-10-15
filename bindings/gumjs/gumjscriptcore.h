/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_CORE_H__
#define __GUM_JSCRIPT_CORE_H__

#include "gumscript.h"

#include <gum/gumexceptor.h>

#import <JavaScriptCore/JavaScriptCore.h>

typedef void (* GumScriptCoreMessageEmitter) (GumScript * script,
    const gchar * message, GBytes * data);

@interface GumScriptCore : NSObject
{
  GumScript * script;
  GumScriptCoreMessageEmitter messageEmitter;
  GumExceptor * exceptor;
  JSContext * context;
}

- (instancetype)initWithScript:(GumScript *)aScript
                       emitter:(GumScriptCoreMessageEmitter)emitter
                       context:(JSContext *)context;

@end

#endif
