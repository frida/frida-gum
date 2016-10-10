/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumduksocket.h"

#include "gumdukmacros.h"

#include <gio/gnetworking.h>
#ifdef G_OS_WIN32
# define GUM_SOCKOPT_OPTVAL(v) (gchar *) (v)
  typedef int gum_socklen_t;
#else
# include <errno.h>
# define GUM_SOCKOPT_OPTVAL(v) (v)
  typedef socklen_t gum_socklen_t;
#endif

typedef struct _GumDukConnectOperation GumDukConnectOperation;
typedef struct _GumDukSetNoDelayOperation GumDukSetNoDelayOperation;

struct _GumDukConnectOperation
{
  GSocketClient * client;
  gchar * host;
  guint16 port;
  GumDukHeapPtr callback;
  GumScriptJob * job;

  GumDukSocket * module;
};

struct _GumDukSetNoDelayOperation
{
  GSocketConnection * connection;
  gboolean no_delay;
  GumDukHeapPtr callback;
  GumScriptJob * job;

  GumDukSocket * module;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_connect)
static void gum_duk_connect_operation_free (GumDukConnectOperation * op);
static void gum_duk_connect_operation_start (GumDukConnectOperation * self);
static void gum_duk_connect_operation_finish (GSocketClient * client,
    GAsyncResult * result, GumDukConnectOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_type)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_local_address)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_peer_address)

static void gum_duk_push_socket_connection (duk_context * ctx,
    GSocketConnection * connection, GumDukSocket * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_connection_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_connection_set_no_delay)
static void gum_duk_set_no_delay_operation_free (
    GumDukSetNoDelayOperation * op);
static void gum_duk_set_no_delay_operation_perform (
    GumDukSetNoDelayOperation * self);

static GumDukHeapPtr gumjs_socket_address_to_value (duk_context * ctx,
    struct sockaddr * addr, GumDukCore * core);

static const duk_function_list_entry gumjs_socket_functions[] =
{
  { "_connect", gumjs_socket_connect, 4 },
  { "type", gumjs_socket_get_type, 1 },
  { "localAddress", gumjs_socket_get_local_address, 1 },
  { "peerAddress", gumjs_socket_get_peer_address, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_socket_connection_functions[] =
{
  { "_setNoDelay", gumjs_socket_connection_set_no_delay, 2 },

  { NULL, NULL, 0 }
};

void
_gum_duk_socket_init (GumDukSocket * self,
                      GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  _gum_duk_store_module_data (ctx, "socket", self);

  duk_push_c_function (ctx, gumjs_socket_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_socket_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, self);
  duk_put_global_string (ctx, "Socket");

  duk_get_global_string (ctx, "IOStream");
  self->io_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  _gum_duk_create_subclass (ctx, "IOStream", "SocketConnection",
      gumjs_socket_connection_construct, 2, NULL);
  duk_get_global_string (ctx, "SocketConnection");
  duk_get_prop_string (ctx, -1, "prototype");
  duk_put_function_list (ctx, -1, gumjs_socket_connection_functions);
  duk_pop (ctx);
  self->connection = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  self->cancellable = g_cancellable_new ();
}

void
_gum_duk_socket_flush (GumDukSocket * self)
{
  g_cancellable_cancel (self->cancellable);
}

void
_gum_duk_socket_dispose (GumDukSocket * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);
  duk_context * ctx = scope.ctx;

  _gum_duk_release_heapptr (ctx, self->io_stream);
  _gum_duk_release_heapptr (ctx, self->connection);
}

void
_gum_duk_socket_finalize (GumDukSocket * self)
{
  g_clear_object (&self->cancellable);
}

static GumDukSocket *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "socket");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_construct)
{
  (void) ctx;
  (void) args;

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_connect)
{
  GumDukSocket * module;
  GumDukCore * core;
  guint family_value;
  GSocketFamily family;
  const gchar * host;
  guint port;
  GumDukHeapPtr callback;
  GSocketClient * client;
  GumDukConnectOperation * op;

  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "usuF", &family_value, &host, &port, &callback);

  switch (family_value)
  {
    case 4:
      family = G_SOCKET_FAMILY_IPV4;
      break;
    case 6:
      family = G_SOCKET_FAMILY_IPV6;
      break;
    default:
      family = G_SOCKET_FAMILY_INVALID;
      _gum_duk_throw (ctx, "invalid address family");
  }

  client = G_SOCKET_CLIENT (g_object_new (G_TYPE_SOCKET_CLIENT,
      "family", family,
      NULL));

  duk_push_heapptr (ctx, callback);

  op = g_slice_new (GumDukConnectOperation);
  op->client = client;
  op->host = g_strdup (host);
  op->port = port;
  op->callback = _gum_duk_require_heapptr (ctx, -1);
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_duk_connect_operation_start, op,
      (GDestroyNotify) gum_duk_connect_operation_free);

  op->module = module;

  _gum_duk_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);

  duk_pop (ctx);

  return 0;
}

static void
gum_duk_connect_operation_free (GumDukConnectOperation * op)
{
  GumDukCore * core = op->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_release_heapptr (ctx, op->callback);
  _gum_duk_scope_leave (&scope);

  g_free (op->host);
  g_object_unref (op->client);

  g_slice_free (GumDukConnectOperation, op);
}

static void
gum_duk_connect_operation_start (GumDukConnectOperation * self)
{
  g_socket_client_connect_to_host_async (self->client, self->host, self->port,
      self->module->cancellable,
      (GAsyncReadyCallback) gum_duk_connect_operation_finish, self);
}

static void
gum_duk_connect_operation_finish (GSocketClient * client,
                                  GAsyncResult * result,
                                  GumDukConnectOperation * self)
{
  GumDukSocket * module = self->module;
  GError * error = NULL;
  GSocketConnection * connection;
  GumDukScope scope;
  duk_context * ctx;

  connection = g_socket_client_connect_to_host_finish (client, result, &error);

  ctx = _gum_duk_scope_enter (&scope, module->core);

  duk_push_heapptr (ctx, self->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);
    gum_duk_push_socket_connection (ctx, connection, module);
  }
  else
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
    duk_push_null (ctx);
  }
  _gum_duk_scope_call (&scope, 2);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  gum_script_job_free (self->job);
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

static GSocketConnection *
gumjs_connection_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GSocketConnection * connection;

  duk_push_this (ctx);
  connection = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return connection;
}

static void
gum_duk_push_socket_connection (duk_context * ctx,
                                GSocketConnection * connection,
                                GumDukSocket * module)
{
  duk_push_heapptr (ctx, module->connection);
  duk_push_pointer (ctx, connection);
  duk_new (ctx, 1);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_connection_construct)
{
  GSocketConnection * connection;
  GumDukSocket * module;

  connection = G_SOCKET_CONNECTION (duk_require_pointer (ctx, 0));

  module = gumjs_module_from_args (args);

  duk_push_heapptr (ctx, module->io_stream);
  duk_push_this (ctx);
  duk_push_pointer (ctx, connection);
  duk_call_method (ctx, 1);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_connection_set_no_delay)
{
  GSocketConnection * connection;
  GumDukSocket * module;
  GumDukCore * core;
  gboolean no_delay;
  GumDukHeapPtr callback;
  GumDukSetNoDelayOperation * op;

  connection = gumjs_connection_from_args (args);
  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "tF", &no_delay, &callback);

  duk_push_heapptr (ctx, callback);

  op = g_slice_new (GumDukSetNoDelayOperation);
  op->connection = connection;
  g_object_ref (connection);
  op->no_delay = no_delay;
  op->callback = _gum_duk_require_heapptr (ctx, -1);
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_duk_set_no_delay_operation_perform, op,
      (GDestroyNotify) gum_duk_set_no_delay_operation_free);

  op->module = module;

  _gum_duk_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);

  duk_pop (ctx);

  return 0;
}

static void
gum_duk_set_no_delay_operation_free (GumDukSetNoDelayOperation * op)
{
  GumDukCore * core = op->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_release_heapptr (ctx, op->callback);
  _gum_duk_scope_leave (&scope);

  g_object_unref (op->connection);

  g_slice_free (GumDukSetNoDelayOperation, op);
}

static void
gum_duk_set_no_delay_operation_perform (GumDukSetNoDelayOperation * self)
{
  GSocket * socket;
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  socket = g_socket_connection_get_socket (self->connection);

  success = g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY,
      self->no_delay, &error);

  ctx = _gum_duk_scope_enter (&scope, self->module->core);

  duk_push_heapptr (ctx, self->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);
  }
  else
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
  }
  duk_push_boolean (ctx, success);
  _gum_duk_scope_call (&scope, 2);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  gum_script_job_free (self->job);
}

static GumDukHeapPtr
gumjs_socket_address_to_value (duk_context * ctx,
                               struct sockaddr * addr,
                               GumDukCore * core)
{
  GumDukHeapPtr result;

  (void) core;

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
