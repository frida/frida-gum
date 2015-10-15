/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#import "gumjscriptcore.h"

@interface GumScriptNativePointer : NSObject
{
}

@end

@implementation GumScriptCore

- (instancetype)initWithScript:(GumScript *)aScript
                       emitter:(GumScriptCoreMessageEmitter)anEmitter
                       context:(JSContext *)aContext
{
  self = [self init];
  if (self)
  {
    script = aScript;
    messageEmitter = anEmitter;
    exceptor = gum_exceptor_obtain ();
    context = aContext;

    JSValue * placeholder = [JSValue valueWithNewObjectInContext:context];

    context[@"Script"] = placeholder;
    context[@"NativePointer"] = [GumScriptNativePointer class];
    context[@"Kernel"] = placeholder;
    context[@"Memory"] = placeholder;
  }

  return self;
}

- (void)dealloc
{
  g_object_unref (self->exceptor);

  [super dealloc];
}

@end

@implementation GumScriptNativePointer
@end
