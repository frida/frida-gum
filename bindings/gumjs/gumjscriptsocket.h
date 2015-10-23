/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_SOCKET_H__
#define __GUM_JSCRIPT_SOCKET_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptSocket GumScriptSocket;

struct _GumScriptSocket
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_socket_init (GumScriptSocket * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_socket_dispose (GumScriptSocket * self);
G_GNUC_INTERNAL void _gum_script_socket_finalize (GumScriptSocket * self);

G_END_DECLS

#endif
