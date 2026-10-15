/*
 * Copyright (C) 2026 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SWIFT_API_RESOLVER_PRIV_H__
#define __GUM_SWIFT_API_RESOLVER_PRIV_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

GUM_API gint _gum_swift_api_resolver_find_vtable_index_in_thunk (
    gconstpointer thunk);

G_END_DECLS

#endif
