/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_SOCKET_H__
#define __GUM_JSCRIPT_SOCKET_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscSocket GumJscSocket;

struct _GumJscSocket
{
  GumJscCore * core;
};

G_GNUC_INTERNAL void _gum_jsc_socket_init (GumJscSocket * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_socket_dispose (GumJscSocket * self);
G_GNUC_INTERNAL void _gum_jsc_socket_finalize (GumJscSocket * self);

G_END_DECLS

#endif
