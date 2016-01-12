/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_SCRIPT_PRIV_H__
#define __GUM_DUK_SCRIPT_PRIV_H__

#include "duktape.h"

#include <glib.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_duk_panic (duk_context * ctx,
    const char * error_message);

G_END_DECLS

#endif
