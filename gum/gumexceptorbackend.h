/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_EXCEPTOR_BACKEND_H__
#define __GUM_EXCEPTOR_BACKEND_H__

#include "gumexceptor.h"

#include <glib-object.h>

typedef gboolean (* GumExceptionHandler) (GumExceptionDetails * details,
    gpointer user_data);

G_BEGIN_DECLS

#define GUM_TYPE_EXCEPTOR_BACKEND (gum_exceptor_backend_get_type ())
G_DECLARE_FINAL_TYPE (GumExceptorBackend, gum_exceptor_backend, GUM,
    EXCEPTOR_BACKEND, GObject)

GumExceptorBackend * gum_exceptor_backend_new (GumExceptionHandler handler,
    gpointer user_data);

G_END_DECLS

#endif
