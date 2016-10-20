/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_SOCKET_H__
#define __GUM_V8_SOCKET_H__

#include "gumv8object.h"

struct GumV8Socket
{
  GumV8Core * core;

  GumV8ObjectManager objects;

  GumPersistent<v8::FunctionTemplate>::type * listener;
  GumPersistent<v8::FunctionTemplate>::type * connection;
};

typedef GumV8Object<GSocketListener, GumV8Socket> GumV8SocketListener;

G_GNUC_INTERNAL void _gum_v8_socket_init (GumV8Socket * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_socket_realize (GumV8Socket * self);
G_GNUC_INTERNAL void _gum_v8_socket_flush (GumV8Socket * self);
G_GNUC_INTERNAL void _gum_v8_socket_dispose (GumV8Socket * self);
G_GNUC_INTERNAL void _gum_v8_socket_finalize (GumV8Socket * self);

#endif
