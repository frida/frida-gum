/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SOCKET_H__
#define __GUM_SCRIPT_SOCKET_H__

#include "gumv8core.h"

#include <v8.h>

typedef struct _GumV8Socket GumV8Socket;

struct _GumV8Socket
{
  GumV8Core * core;
};

G_GNUC_INTERNAL void _gum_v8_socket_init (GumV8Socket * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_socket_realize (GumV8Socket * self);
G_GNUC_INTERNAL void _gum_v8_socket_dispose (GumV8Socket * self);
G_GNUC_INTERNAL void _gum_v8_socket_finalize (GumV8Socket * self);

#endif
