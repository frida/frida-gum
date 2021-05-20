/*
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_OBJC_API_RESOLVER_PRIV_H__
#define __GUM_OBJC_API_RESOLVER_PRIV_H__

#include <gum/gumapiresolver.h>

#include <glib.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_objc_api_resolver_selector_from_address (GumApiResolver * self,
    GumAddress address, gchar ** result, GError ** error);

G_END_DECLS

#endif
