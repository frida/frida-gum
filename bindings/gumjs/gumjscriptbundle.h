/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_BUNDLE_H__
#define __GUM_JSCRIPT_BUNDLE_H__

#include <glib.h>
#import <JavaScriptCore/JavaScriptCore.h>

#define GUM_MAX_SCRIPT_SOURCE_CHUNKS 6

typedef struct _GumScriptSource GumScriptSource;

struct _GumScriptSource
{
  const gchar * name;
  const gchar * chunks[GUM_MAX_SCRIPT_SOURCE_CHUNKS];
};

@interface GumScriptBundle : NSObject
{
}

+ (void)load:(const GumScriptSource *)sources intoContext:(JSContext *)context;

@end

#endif
