/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SOCKET_H__
#define __GUM_SCRIPT_SOCKET_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptSocket GumScriptSocket;

struct _GumScriptSocket
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_socket_init (GumScriptSocket * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_socket_realize (GumScriptSocket * self);
G_GNUC_INTERNAL void _gum_script_socket_dispose (GumScriptSocket * self);
G_GNUC_INTERNAL void _gum_script_socket_finalize (GumScriptSocket * self);

#endif
