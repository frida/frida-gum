/*
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_OBJC_API_RESOLVER_PRIV_H__
#define __GUM_OBJC_API_RESOLVER_PRIV_H__

#include <gum/gumapiresolver.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL gchar * gum_objc_api_resolver_find_method_by_address (
    GumApiResolver * resolver, GumAddress address);

G_END_DECLS

#endif
