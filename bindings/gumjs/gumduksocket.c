/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumduksocket.h"

#include "gumdukmacros.h"

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

GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_type)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_local_address)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_peer_address)

static GumDukHeapPtr gumjs_socket_address_to_value (duk_context * ctx,
    struct sockaddr * addr, GumDukCore * core);

static const duk_function_list_entry gumjs_socket_functions[] =
{
  { "type", gumjs_socket_get_type, 1 },
  { "localAddress", gumjs_socket_get_local_address, 1 },
  { "peerAddress", gumjs_socket_get_peer_address, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_socket_init (GumDukSocket * self,
                      GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_socket_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_socket_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, self);
  duk_put_global_string (ctx, "Socket");
}

void
_gum_duk_socket_dispose (GumDukSocket * self)
{
  (void) self;
}

void
_gum_duk_socket_finalize (GumDukSocket * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_construct)
{
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_type)
{
  const gchar * result = NULL;
  gint sock, type;
  gum_socklen_t len;

  _gum_duk_args_parse (args, "i", &sock);

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
    duk_push_string (ctx, result);
  else
    duk_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_local_address)
{
  gint sock;
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = (struct sockaddr *) &large_addr;
  gum_socklen_t len = sizeof (large_addr);
  GumDukHeapPtr result;

  _gum_duk_args_parse (args, "i", &sock);

  if (getsockname (sock, addr, &len) == 0)
  {
    result = gumjs_socket_address_to_value (ctx, addr, args->core);
    duk_push_heapptr (ctx, result);
    _gum_duk_release_heapptr (ctx, result);
  }
  else
  {
    duk_push_null (ctx);
  }

  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_peer_address)
{
  gint sock;
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = (struct sockaddr *) &large_addr;
  gum_socklen_t len = sizeof (large_addr);
  GumDukHeapPtr result;

  _gum_duk_args_parse (args, "i", &sock);

  if (getpeername (sock, addr, &len) == 0)
  {
    result = gumjs_socket_address_to_value (ctx, addr, args->core);
    duk_push_heapptr (ctx, result);
    _gum_duk_release_heapptr (ctx, result);
  }
  else
  {
    duk_push_null (ctx);
  }

  return 1;
}

static GumDukHeapPtr
gumjs_socket_address_to_value (duk_context * ctx,
                               struct sockaddr * addr,
                               GumDukCore * core)
{
  GumDukHeapPtr result;
  switch (addr->sa_family)
  {
    case AF_INET:
    {
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

      duk_push_object (ctx);
      duk_push_string (ctx, ip);
      duk_put_prop_string (ctx, -2, "ip");
      duk_push_uint (ctx, GUINT16_FROM_BE (inet_addr->sin_port));
      duk_put_prop_string (ctx, -2, "port");
      result = _gum_duk_require_heapptr (ctx, -1);
      duk_pop (ctx);
      return result;
    }
    case AF_INET6:
    {
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

      duk_push_object (ctx);
      duk_push_string (ctx, ip);
      duk_put_prop_string (ctx, -2, "ip");
      duk_push_uint (ctx, GUINT16_FROM_BE (inet_addr->sin6_port));
      duk_put_prop_string (ctx, -2, "port");
      result = _gum_duk_require_heapptr (ctx, -1);
      duk_pop (ctx);
      return result;
    }
    case AF_UNIX:
    {
      gchar * path = ""; /* FIXME */
      duk_push_object (ctx);
      duk_push_string (ctx, path);
      duk_put_prop_string (ctx, -2, "path");
      result = _gum_duk_require_heapptr (ctx, -1);
      duk_pop (ctx);
      return result;
    }
  }

  return NULL;
}
