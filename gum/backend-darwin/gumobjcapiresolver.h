/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_OBJC_API_RESOLVER_H__
#define __GUM_OBJC_API_RESOLVER_H__

#include <glib-object.h>
#include <gum/gumapiresolver.h>

G_BEGIN_DECLS

#define GUM_TYPE_OBJC_API_RESOLVER (gum_objc_api_resolver_get_type ())
G_DECLARE_FINAL_TYPE (GumObjcApiResolver, gum_objc_api_resolver, GUM,
    OBJC_API_RESOLVER, GObject)

GumApiResolver * gum_objc_api_resolver_new (void);

G_END_DECLS

#endif
