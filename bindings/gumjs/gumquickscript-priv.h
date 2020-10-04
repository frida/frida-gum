/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_SCRIPT_PRIV_H__
#define __GUM_QUICK_SCRIPT_PRIV_H__

#include <glib.h>
#include <quickjs.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_quick_panic (JSContext * ctx, const gchar * prefix);

G_END_DECLS

#endif
