/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSC_SCRIPT_PRIV_H__
#define __GUM_JSC_SCRIPT_PRIV_H__

#include <glib.h>
#include <JavaScriptCore/JavaScriptCore.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gumjs_panic (JSContextRef ctx, JSValueRef exception);

G_END_DECLS

#endif
