/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#import "gumjscriptbundle.h"

@implementation GumScriptBundle

+ (void)load:(const GumScriptSource *)sources intoContext:(JSContext *)context
{
  const GumScriptSource * cur;

  for (cur = sources; cur->name != NULL; cur++)
  {
    gchar * str = g_strjoinv (NULL, (gchar **) cur->chunks);
    NSString * source = [NSString stringWithUTF8String:str];
    g_free (str);

    NSString * filename = [[NSString stringWithUTF8String:cur->name]
                                  stringByAppendingString:@".js"];
    NSURL * url = [NSURL URLWithString:
        [@"file:///" stringByAppendingString:filename]];

    [context evaluateScript:source
              withSourceURL:url];
    g_assert (context.exception == nil);
  }
}

@end
