/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscsocket.h"

#include "gumjscmacros.h"

#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# include <winsock2.h>
# include <ws2tcpip.h>
# define GUM_SOCKOPT_OPTVAL(v) (gchar *) (v)
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

GUMJS_DECLARE_FUNCTION (gumjs_socket_get_type)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_local_address)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_peer_address)

static JSValueRef gumjs_socket_address_to_value (JSContextRef ctx,
    struct sockaddr * addr, GumJscCore * core);

static const JSStaticFunction gumjs_socket_functions[] =
{
  { "type", gumjs_socket_get_type, GUMJS_RO },
  { "localAddress", gumjs_socket_get_local_address, GUMJS_RO },
  { "peerAddress", gumjs_socket_get_peer_address, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_jsc_socket_init (GumJscSocket * self,
                      GumJscCore * core,
                      JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef socket;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Socket";
  def.staticFunctions = gumjs_socket_functions;
  klass = JSClassCreate (&def);
  socket = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, socket);
}

void
_gum_jsc_socket_dispose (GumJscSocket * self)
{
  (void) self;
}

void
_gum_jsc_socket_finalize (GumJscSocket * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_type)
{
  const gchar * result = NULL;
  gint sock, type;
  gum_socklen_t len;

  if (!_gumjs_args_parse (args, "i", &sock))
    return NULL;

  len = sizeof (gint);
  if (getsockopt (sock, SOL_SOCKET, SO_TYPE, GUM_SOCKOPT_OPTVAL (&type),
      &len) == 0)
  {
    gint family;
    struct sockaddr_in6 addr;

    len = sizeof (addr);
    if (getsockname (sock, (struct sockaddr *) &addr, &len) == 0)
    {
      family = addr.sin6_family;
    }
    else
    {
      struct sockaddr_in invalid_sockaddr;

      invalid_sockaddr.sin_family = AF_INET;
      invalid_sockaddr.sin_port = GUINT16_TO_BE (0);
      invalid_sockaddr.sin_addr.s_addr = GUINT32_TO_BE (0xffffffff);

      bind (sock,
          (struct sockaddr *) &invalid_sockaddr,
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
          case SOCK_STREAM: result = "tcp"; break;
          case  SOCK_DGRAM: result = "udp"; break;
        }
        break;
      case AF_INET6:
        switch (type)
        {
          case SOCK_STREAM: result = "tcp6"; break;
          case  SOCK_DGRAM: result = "udp6"; break;
        }
        break;
#ifndef G_OS_WIN32
      case AF_UNIX:
        switch (type)
        {
          case SOCK_STREAM: result = "unix:stream"; break;
          case  SOCK_DGRAM: result = "unix:dgram";  break;
        }
        break;
#endif
    }
  }

  if (result != NULL)
    return _gumjs_string_to_value (ctx, result);
  else
    return JSValueMakeNull (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_local_address)
{
  gint sock;
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = (struct sockaddr *) &large_addr;
  gum_socklen_t len = sizeof (large_addr);

  if (!_gumjs_args_parse (args, "i", &sock))
    return NULL;

  if (getsockname (sock, addr, &len) == 0)
    return gumjs_socket_address_to_value (ctx, addr, args->core);
  else
    return JSValueMakeNull (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_peer_address)
{
  gint sock;
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = (struct sockaddr *) &large_addr;
  gum_socklen_t len = sizeof (large_addr);

  if (!_gumjs_args_parse (args, "i", &sock))
    return NULL;

  if (getpeername (sock, addr, &len) == 0)
    return gumjs_socket_address_to_value (ctx, addr, args->core);
  else
    return JSValueMakeNull (ctx);
}

static JSValueRef
gumjs_socket_address_to_value (JSContextRef ctx,
                               struct sockaddr * addr,
                               GumJscCore * core)
{
  switch (addr->sa_family)
  {
    case AF_INET:
    {
      JSObjectRef result;
      struct sockaddr_in * inet_addr = (struct sockaddr_in *) addr;
#ifdef G_OS_WIN32
      gunichar2 ip_utf16[15 + 1 + 5 + 1];
      gchar ip[15 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      gchar * p;

      WSAAddressToStringW (addr, sizeof (struct sockaddr_in), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      p = strchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET_ADDRSTRLEN];

      inet_ntop (AF_INET, &inet_addr->sin_addr, ip, sizeof (ip));
#endif

      result = JSObjectMake (ctx, NULL, NULL);
      _gumjs_object_set_string (ctx, result, "ip", ip);
      _gumjs_object_set_uint (ctx, result, "port",
          GUINT16_FROM_BE (inet_addr->sin_port));
      return result;
    }
    case AF_INET6:
    {
      JSObjectRef result;
      struct sockaddr_in6 * inet_addr = (struct sockaddr_in6 *) addr;
#ifdef G_OS_WIN32
      gunichar2 ip_utf16[45 + 1 + 5 + 1];
      gchar ip[45 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      gchar * p;

      WSAAddressToStringW (addr, sizeof (struct sockaddr_in6), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      p = strrchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET6_ADDRSTRLEN];

      inet_ntop (AF_INET6, &inet_addr->sin6_addr, ip, sizeof (ip));
#endif

      result = JSObjectMake (ctx, NULL, NULL);
      _gumjs_object_set_string (ctx, result, "ip", ip);
      _gumjs_object_set_uint (ctx, result, "port",
          GUINT16_FROM_BE (inet_addr->sin6_port));
      return result;
    }
    case AF_UNIX:
    {
      JSObjectRef result = JSObjectMake (ctx, NULL, NULL);
      _gumjs_object_set_string (ctx, result, "path", ""); /* FIXME */
      return result;
    }
  }

  return JSValueMakeNull (ctx);
}
