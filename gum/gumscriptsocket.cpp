/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumscriptsocket.h"

#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# include <winsock2.h>
# include <ws2tcpip.h>
# define GUM_SOCKOPT_OPTVAL(v) reinterpret_cast<char *> (v)
  typedef int gum_socklen_t;
#else
# include <errno.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/un.h>
# define GUM_SOCKOPT_OPTVAL(v) (v)
  typedef socklen_t gum_socklen_t;
#endif

using namespace v8;

static void gum_script_socket_on_type (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_socket_on_local_address (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_socket_on_peer_address (
    const FunctionCallbackInfo<Value> & info);
static Local<Value> gum_script_socket_address_to_value (
    struct sockaddr * addr, Isolate * isolate);

void
_gum_script_socket_init (GumScriptSocket * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Handle<ObjectTemplate> socket = ObjectTemplate::New (isolate);
  socket->Set (String::NewFromUtf8 (isolate, "type"),
      FunctionTemplate::New (isolate, gum_script_socket_on_type));
  socket->Set (String::NewFromUtf8 (isolate, "localAddress"),
      FunctionTemplate::New (isolate, gum_script_socket_on_local_address));
  socket->Set (String::NewFromUtf8 (isolate, "peerAddress"),
      FunctionTemplate::New (isolate, gum_script_socket_on_peer_address));
  scope->Set (String::NewFromUtf8 (isolate, "Socket"), socket);
}

void
_gum_script_socket_realize (GumScriptSocket * self)
{
  (void) self;
}

void
_gum_script_socket_dispose (GumScriptSocket * self)
{
  (void) self;
}

void
_gum_script_socket_finalize (GumScriptSocket * self)
{
  (void) self;
}

static void
gum_script_socket_on_type (const FunctionCallbackInfo<Value> & info)
{
  const gchar * res = NULL;

  int32_t socket = info[0]->ToInteger ()->Value ();

  int type;
  gum_socklen_t len = sizeof (int);
  if (getsockopt (socket, SOL_SOCKET, SO_TYPE, GUM_SOCKOPT_OPTVAL (&type),
      &len) == 0)
  {
    int family;

    struct sockaddr_in6 addr;
    len = sizeof (addr);
    if (getsockname (socket,
        reinterpret_cast<struct sockaddr *> (&addr), &len) == 0)
    {
      family = addr.sin6_family;
    }
    else
    {
      struct sockaddr_in invalid_sockaddr;
      invalid_sockaddr.sin_family = AF_INET;
      invalid_sockaddr.sin_port = htons (0);
      invalid_sockaddr.sin_addr.s_addr = htonl (0xffffffff);
      bind (socket,
          reinterpret_cast<struct sockaddr *> (&invalid_sockaddr),
          sizeof (invalid_sockaddr));
#ifdef G_OS_WIN32
      family = (WSAGetLastError () == WSAEADDRNOTAVAIL) ? AF_INET : AF_INET6;
#else
      family = (errno == EADDRNOTAVAIL) ? AF_INET : AF_INET6;
#endif
    }

    switch (family)
    {
      case AF_INET:
        switch (type)
        {
          case SOCK_STREAM: res = "tcp"; break;
          case  SOCK_DGRAM: res = "udp"; break;
        }
        break;
      case AF_INET6:
        switch (type)
        {
          case SOCK_STREAM: res = "tcp6"; break;
          case  SOCK_DGRAM: res = "udp6"; break;
        }
        break;
#ifndef G_OS_WIN32
      case AF_UNIX:
        switch (type)
        {
          case SOCK_STREAM: res = "unix:stream"; break;
          case  SOCK_DGRAM: res = "unix:dgram";  break;
        }
        break;
#endif
    }
  }

  if (res != NULL)
    info.GetReturnValue ().Set (String::NewFromUtf8 (info.GetIsolate (), res));
  else
    info.GetReturnValue ().SetNull ();
}

static void
gum_script_socket_on_local_address (const FunctionCallbackInfo<Value> & info)
{
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = reinterpret_cast<struct sockaddr *> (&large_addr);
  gum_socklen_t len = sizeof (large_addr);
  if (getsockname (info[0]->ToInteger ()->Value (), addr, &len) == 0)
  {
    info.GetReturnValue ().Set (
        gum_script_socket_address_to_value (addr, info.GetIsolate ()));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static void
gum_script_socket_on_peer_address (const FunctionCallbackInfo<Value> & info)
{
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = reinterpret_cast<struct sockaddr *> (&large_addr);
  gum_socklen_t len = sizeof (large_addr);
  if (getpeername (info[0]->ToInteger ()->Value (), addr, &len) == 0)
  {
    info.GetReturnValue ().Set (
        gum_script_socket_address_to_value (addr, info.GetIsolate ()));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static Local<Value>
gum_script_socket_address_to_value (struct sockaddr * addr,
                                    Isolate * isolate)
{
  switch (addr->sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in * inet_addr =
          reinterpret_cast<struct sockaddr_in *> (addr);
#ifdef G_OS_WIN32
      gchar ip[15 + 1 + 5 + 1];
      DWORD len = sizeof (ip);
      WSAAddressToStringA (addr, sizeof (struct sockaddr_in), NULL, ip, &len);
      gchar * p = strchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET_ADDRSTRLEN];
      inet_ntop (AF_INET, &inet_addr->sin_addr, ip, sizeof (ip));
#endif
      Local<Object> result (Object::New (isolate));
      result->Set (String::NewFromUtf8 (isolate, "ip"),
          String::NewFromUtf8 (isolate, ip), ReadOnly);
      result->Set (String::NewFromUtf8 (isolate, "port"),
          Int32::New (isolate, ntohs (inet_addr->sin_port)), ReadOnly);
      return result;
    }
    case AF_INET6:
    {
      struct sockaddr_in6 * inet_addr =
          reinterpret_cast<struct sockaddr_in6 *> (addr);
#ifdef G_OS_WIN32
      gchar ip[45 + 1 + 5 + 1];
      DWORD len = sizeof (ip);
      WSAAddressToStringA (addr, sizeof (struct sockaddr_in6), NULL, ip, &len);
      gchar * p = strrchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, &inet_addr->sin6_addr, ip, sizeof (ip));
#endif
      Local<Object> result (Object::New (isolate));
      result->Set (String::NewFromUtf8 (isolate, "ip"),
          String::NewFromUtf8 (isolate, ip), ReadOnly);
      result->Set (String::NewFromUtf8 (isolate, "port"),
          Int32::New (isolate, ntohs (inet_addr->sin6_port)), ReadOnly);
      return result;
    }
    case AF_UNIX:
    {
      Local<Object> result (Object::New (isolate));
      result->Set (String::NewFromUtf8 (isolate, "path"),
          String::NewFromUtf8 (isolate, "") /* FIXME */,
          ReadOnly);
      return result;
    }
  }

  return Null (isolate);
}

