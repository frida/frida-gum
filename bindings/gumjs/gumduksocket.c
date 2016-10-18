/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumduksocket.h"

#include "gumdukmacros.h"

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4214)
#endif
#include <gio/gnetworking.h>
#ifdef _MSC_VER
# pragma warning (pop)
#endif
#ifdef G_OS_WIN32
# define GUM_SOCKOPT_OPTVAL(v) (gchar *) (v)
  typedef int gum_socklen_t;
#else
# include <errno.h>
# define GUM_SOCKOPT_OPTVAL(v) (v)
  typedef socklen_t gum_socklen_t;
#endif
#ifdef G_OS_UNIX
# include <gio/gunixsocketaddress.h>
#endif

typedef struct _GumDukListenOperation GumDukListenOperation;
typedef struct _GumDukConnectOperation GumDukConnectOperation;

typedef struct _GumDukCloseListenerOperation GumDukCloseListenerOperation;
typedef struct _GumDukAcceptOperation GumDukAcceptOperation;

typedef struct _GumDukSetNoDelayOperation GumDukSetNoDelayOperation;

struct _GumDukListenOperation
{
  GumDukModuleOperation parent;

  guint16 port;

  gchar * path;

  GSocketAddress * address;
  gint backlog;
};

struct _GumDukConnectOperation
{
  GumDukModuleOperation parent;

  GSocketClient * client;
  GSocketFamily family;

  gchar * host;
  guint16 port;

  GSocketConnectable * connectable;
};

struct _GumDukCloseListenerOperation
{
  GumDukObjectOperation parent;
};

struct _GumDukAcceptOperation
{
  GumDukObjectOperation parent;
};

struct _GumDukSetNoDelayOperation
{
  GumDukObjectOperation parent;
  gboolean no_delay;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_listen)
static void gum_duk_listen_operation_dispose (GumDukListenOperation * self);
static void gum_duk_listen_operation_perform (GumDukListenOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_connect)
static void gum_duk_connect_operation_dispose (GumDukConnectOperation * self);
static void gum_duk_connect_operation_start (GumDukConnectOperation * self);
static void gum_duk_connect_operation_finish (GSocketClient * client,
    GAsyncResult * result, GumDukConnectOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_type)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_local_address)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_peer_address)

static void gum_duk_push_socket_listener (duk_context * ctx,
    GSocketListener * listener, GumDukSocket * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_listener_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_listener_close)
static void gum_duk_close_listener_operation_perform (
    GumDukCloseListenerOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_listener_accept)
static void gum_duk_accept_operation_start (GumDukAcceptOperation * self);
static void gum_duk_accept_operation_finish (GSocketListener * listener,
    GAsyncResult * result, GumDukAcceptOperation * self);

static void gum_duk_push_socket_connection (duk_context * ctx,
    GSocketConnection * connection, GumDukSocket * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_connection_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_connection_set_no_delay)
static void gum_duk_set_no_delay_operation_perform (
    GumDukSetNoDelayOperation * self);

static void gum_duk_get_socket_family (duk_context * ctx, GumDukHeapPtr value,
    GSocketFamily * family);
static void gum_duk_get_unix_socket_address_type (duk_context * ctx,
    GumDukHeapPtr value, GUnixSocketAddressType * type);
static GumDukHeapPtr gumjs_socket_address_to_value (duk_context * ctx,
    struct sockaddr * addr, GumDukCore * core);

static const duk_function_list_entry gumjs_socket_functions[] =
{
  { "_listen", gumjs_socket_listen, 7 },
  { "_connect", gumjs_socket_connect, 6 },
  { "type", gumjs_socket_get_type, 1 },
  { "localAddress", gumjs_socket_get_local_address, 1 },
  { "peerAddress", gumjs_socket_get_peer_address, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_socket_listener_functions[] =
{
  { "_close", gumjs_socket_listener_close, 1 },
  { "_accept", gumjs_socket_listener_accept, 1 },

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

  duk_push_c_function (ctx, gumjs_socket_listener_construct, 1);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_socket_listener_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->listener = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "SocketListener");

  _gum_duk_create_subclass (ctx, "IOStream", "SocketConnection",
      gumjs_socket_connection_construct, 2, NULL);
  duk_get_global_string (ctx, "SocketConnection");
  duk_get_prop_string (ctx, -1, "prototype");
  duk_put_function_list (ctx, -1, gumjs_socket_connection_functions);
  duk_pop (ctx);
  self->connection = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  duk_get_global_string (ctx, "IOStream");
  self->io_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  _gum_duk_object_manager_init (&self->objects, self, core);
}

void
_gum_duk_socket_flush (GumDukSocket * self)
{
  _gum_duk_object_manager_flush (&self->objects);
}

void
_gum_duk_socket_dispose (GumDukSocket * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);
  duk_context * ctx = scope.ctx;

  _gum_duk_object_manager_free (&self->objects);

  _gum_duk_release_heapptr (ctx, self->listener);
  _gum_duk_release_heapptr (ctx, self->connection);

  _gum_duk_release_heapptr (ctx, self->io_stream);
}

void
_gum_duk_socket_finalize (GumDukSocket * self)
{
  (void) self;
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

GUMJS_DEFINE_FUNCTION (gumjs_socket_listen)
{
  GumDukSocket * module;
  GSocketFamily family;
  GumDukHeapPtr family_value;
  const gchar * host;
  guint port;
  GUnixSocketAddressType type;
  GumDukHeapPtr type_value;
  const gchar * path;
  guint backlog;
  GumDukHeapPtr callback;
  GSocketAddress * address = NULL;
  GumDukListenOperation * op;

  module = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "V?s?uV?s?uF", &family_value, &host, &port,
      &type_value, &path, &backlog, &callback);
  gum_duk_get_socket_family (ctx, family_value, &family);
  gum_duk_get_unix_socket_address_type (ctx, type_value, &type);

  if (host != NULL)
  {
    address = g_inet_socket_address_new_from_string (host, port);
    if (address == NULL)
      _gum_duk_throw (ctx, "invalid host");
  }
  else if (path != NULL)
  {
#ifdef G_OS_UNIX
    address = g_unix_socket_address_new_with_type (path, -1, type);
    g_assert (address != NULL);
#else
    _gum_duk_throw (ctx, "UNIX sockets not available");
#endif
  }
  else if (family != G_SOCKET_FAMILY_INVALID)
  {
    address = g_inet_socket_address_new_from_string (
        (family == G_SOCKET_FAMILY_IPV4) ? "0.0.0.0" : "::",
        port);
    g_assert (address != NULL);
  }

  op = _gum_duk_module_operation_new (GumDukListenOperation, module, callback,
      gum_duk_listen_operation_perform, gum_duk_listen_operation_dispose);
  op->port = port;
  op->path = g_strdup (path);
  op->address = address;
  op->backlog = backlog;
  _gum_duk_module_operation_schedule (op);

  return 0;
}

static void
gum_duk_listen_operation_dispose (GumDukListenOperation * self)
{
  g_clear_object (&self->address);
  g_free (self->path);
}

static void
gum_duk_listen_operation_perform (GumDukListenOperation * self)
{
  GumDukModuleOperation * op = GUM_DUK_MODULE_OPERATION (self);
  GSocketListener * listener;
  GSocketAddress * effective_address = NULL;
  GError * error = NULL;
  GumDukScope scope;
  duk_context * ctx;

  listener = G_SOCKET_LISTENER (g_object_new (G_TYPE_SOCKET_LISTENER,
      "listen-backlog", self->backlog,
      NULL));

  if (self->address != NULL)
  {
    g_socket_listener_add_address (listener, self->address,
        G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, NULL,
        &effective_address, &error);
  }
  else
  {
    if (self->port != 0)
    {
      g_socket_listener_add_inet_port (listener, self->port, NULL, &error);
    }
    else
    {
      self->port =
          g_socket_listener_add_any_inet_port (listener, NULL, &error);
    }
  }

  if (error != NULL)
    g_clear_object (&listener);

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);

    gum_duk_push_socket_listener (ctx, listener, op->module);
    if (self->path != NULL)
    {
      duk_push_string (ctx, self->path);
      duk_put_prop_string (ctx, -2, "path");
    }
    else
    {
      if (effective_address != NULL)
      {
        duk_push_uint (ctx, g_inet_socket_address_get_port (
            G_INET_SOCKET_ADDRESS (effective_address)));
        g_clear_object (&effective_address);
      }
      else
      {
        duk_push_uint (ctx, self->port);
      }
      duk_put_prop_string (ctx, -2, "port");
    }
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

  _gum_duk_module_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_connect)
{
  GumDukSocket * module;
  GSocketFamily family;
  GumDukHeapPtr family_value;
  const gchar * host;
  guint port;
  GUnixSocketAddressType type;
  GumDukHeapPtr type_value;
  const gchar * path;
  GumDukHeapPtr callback;
  GSocketConnectable * connectable = NULL;
  GumDukConnectOperation * op;

  module = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "V?s?uV?s?F", &family_value, &host, &port,
      &type_value, &path, &callback);
  gum_duk_get_socket_family (ctx, family_value, &family);
  gum_duk_get_unix_socket_address_type (ctx, type_value, &type);

  if (path != NULL)
  {
#ifdef G_OS_UNIX
    family = G_SOCKET_FAMILY_UNIX;
    connectable = G_SOCKET_CONNECTABLE (g_unix_socket_address_new_with_type (
        path, -1, type));
    g_assert (connectable != NULL);
#else
    _gum_duk_throw (ctx, "UNIX sockets not available");
#endif
  }

  op = _gum_duk_module_operation_new (GumDukConnectOperation, module, callback,
      gum_duk_connect_operation_start, gum_duk_connect_operation_dispose);
  op->client = NULL;
  op->family = family;
  op->host = g_strdup (host);
  op->port = port;
  op->connectable = connectable;
  _gum_duk_module_operation_schedule (op);

  return 0;
}

static void
gum_duk_connect_operation_dispose (GumDukConnectOperation * self)
{
  g_clear_object (&self->connectable);
  g_free (self->host);
  g_object_unref (self->client);
}

static void
gum_duk_connect_operation_start (GumDukConnectOperation * self)
{
  GumDukModuleOperation * op = GUM_DUK_MODULE_OPERATION (self);

  self->client = G_SOCKET_CLIENT (g_object_new (G_TYPE_SOCKET_CLIENT,
      "family", self->family,
      NULL));

  if (self->connectable != NULL)
  {
    g_socket_client_connect_async (self->client, self->connectable,
        op->cancellable, (GAsyncReadyCallback) gum_duk_connect_operation_finish,
        self);
  }
  else
  {
    g_socket_client_connect_to_host_async (self->client, self->host, self->port,
        op->cancellable, (GAsyncReadyCallback) gum_duk_connect_operation_finish,
        self);
  }
}

static void
gum_duk_connect_operation_finish (GSocketClient * client,
                                  GAsyncResult * result,
                                  GumDukConnectOperation * self)
{
  GumDukModuleOperation * op = GUM_DUK_MODULE_OPERATION (self);
  GError * error = NULL;
  GSocketConnection * connection;
  GumDukScope scope;
  duk_context * ctx;

  if (self->connectable != NULL)
  {
    connection = g_socket_client_connect_finish (client, result, &error);
  }
  else
  {
    connection = g_socket_client_connect_to_host_finish (client, result,
        &error);
  }

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);
    gum_duk_push_socket_connection (ctx, connection, op->module);
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

  _gum_duk_module_operation_finish (op);
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

static void
gum_duk_push_socket_listener (duk_context * ctx,
                              GSocketListener * listener,
                              GumDukSocket * module)
{
  duk_push_heapptr (ctx, module->listener);
  duk_push_pointer (ctx, listener);
  duk_new (ctx, 1);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_listener_construct)
{
  GSocketListener * listener;
  GumDukSocket * module;

  listener = G_SOCKET_LISTENER (duk_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  duk_push_this (ctx);
  _gum_duk_object_manager_add (&module->objects, ctx, -1, listener);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_listener_close)
{
  GumDukObject * self;
  GumDukHeapPtr callback;
  GumDukCloseListenerOperation * op;

  (void) ctx;

  self = _gum_duk_object_get (args);

  _gum_duk_args_parse (args, "F", &callback);

  g_cancellable_cancel (self->cancellable);

  op = _gum_duk_object_operation_new (GumDukCloseListenerOperation, self,
      callback, gum_duk_close_listener_operation_perform, NULL);
  _gum_duk_object_operation_schedule_when_idle (op, NULL);

  return 0;
}

static void
gum_duk_close_listener_operation_perform (GumDukCloseListenerOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GumDukScope scope;
  duk_context * ctx;

  g_socket_listener_close (op->object->handle);

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
  _gum_duk_scope_call (&scope, 0);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  _gum_duk_object_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_listener_accept)
{
  GumDukObject * self;
  GumDukHeapPtr callback;
  GumDukAcceptOperation * op;

  (void) ctx;

  self = _gum_duk_object_get (args);

  _gum_duk_args_parse (args, "F", &callback);

  op = _gum_duk_object_operation_new (GumDukAcceptOperation, self, callback,
      gum_duk_accept_operation_start, NULL);
  _gum_duk_object_operation_schedule (op);

  return 0;
}

static void
gum_duk_accept_operation_start (GumDukAcceptOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GumDukObject * listener = op->object;

  g_socket_listener_accept_async (listener->handle, listener->cancellable,
      (GAsyncReadyCallback) gum_duk_accept_operation_finish, self);
}

static void
gum_duk_accept_operation_finish (GSocketListener * listener,
                                 GAsyncResult * result,
                                 GumDukAcceptOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GError * error = NULL;
  GSocketConnection * connection;
  GumDukScope scope;
  duk_context * ctx;

  connection = g_socket_listener_accept_finish (listener, result, NULL, &error);

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);
    gum_duk_push_socket_connection (ctx, connection, op->object->module);
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

  _gum_duk_object_operation_finish (op);
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
  GumDukObject * self;
  gboolean no_delay;
  GumDukHeapPtr callback;
  GumDukSetNoDelayOperation * op;

  (void) ctx;

  self = _gum_duk_object_get (args);

  _gum_duk_args_parse (args, "tF", &no_delay, &callback);

  op = _gum_duk_object_operation_new (GumDukSetNoDelayOperation, self, callback,
      gum_duk_set_no_delay_operation_perform, NULL);
  op->no_delay = no_delay;
  _gum_duk_object_operation_schedule (op);

  return 0;
}

static void
gum_duk_set_no_delay_operation_perform (GumDukSetNoDelayOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GSocket * socket;
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  socket = g_socket_connection_get_socket (op->object->handle);

  success = g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY,
      self->no_delay, &error);

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
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

  _gum_duk_object_operation_finish (op);
}

static void
gum_duk_get_socket_family (duk_context * ctx,
                           GumDukHeapPtr value,
                           GSocketFamily * family)
{
  const gchar * value_str;

  if (value == NULL)
  {
    *family = G_SOCKET_FAMILY_INVALID;
    return;
  }

  duk_push_heapptr (ctx, value);

  if (!duk_is_string (ctx, -1))
    _gum_duk_throw (ctx, "invalid socket address family");
  value_str = duk_require_string (ctx, -1);

  if (strcmp (value_str, "unix") == 0)
    *family = G_SOCKET_FAMILY_UNIX;
  else if (strcmp (value_str, "ipv4") == 0)
    *family = G_SOCKET_FAMILY_IPV4;
  else if (strcmp (value_str, "ipv6") == 0)
    *family = G_SOCKET_FAMILY_IPV6;
  else
    _gum_duk_throw (ctx, "invalid socket address family");

  duk_pop (ctx);
}

static void
gum_duk_get_unix_socket_address_type (duk_context * ctx,
                                      GumDukHeapPtr value,
                                      GUnixSocketAddressType * type)
{
  const gchar * value_str;

  if (value == NULL)
  {
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
    return;
  }

  duk_push_heapptr (ctx, value);

  if (!duk_is_string (ctx, -1))
    _gum_duk_throw (ctx, "invalid UNIX socket address type");
  value_str = duk_require_string (ctx, -1);

  if (strcmp (value_str, "anonymous") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_ANONYMOUS;
  else if (strcmp (value_str, "path") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
  else if (strcmp (value_str, "abstract") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT;
  else if (strcmp (value_str, "abstract-padded") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT_PADDED;
  else
    _gum_duk_throw (ctx, "invalid UNIX socket address type");

  duk_pop (ctx);
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
