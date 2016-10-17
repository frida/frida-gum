/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8socket.h"

#include "gumv8macros.h"
#include "gumv8scope.h"
#include "gumv8script-priv.h"

#include <gio/gnetworking.h>
#ifdef G_OS_WIN32
# define GUM_SOCKOPT_OPTVAL(v) reinterpret_cast<char *> (v)
  typedef int gum_socklen_t;
#else
# include <errno.h>
# define GUM_SOCKOPT_OPTVAL(v) (v)
  typedef socklen_t gum_socklen_t;
#endif
#ifdef G_OS_UNIX
# include <gio/gunixsocketaddress.h>
#endif

#define GUMJS_MODULE_NAME Socket

using namespace v8;

struct GumV8ListenOperation : public GumV8ModuleOperation<GumV8Socket>
{
  guint16 port;

  gchar * path;

  GSocketAddress * address;
  gint backlog;
};

struct GumV8ConnectOperation : public GumV8ModuleOperation<GumV8Socket>
{
  GSocketClient * client;
  GSocketFamily family;

  gchar * host;
  guint16 port;

  GSocketConnectable * connectable;
};

struct GumV8CloseListenerOperation
    : public GumV8ObjectOperation<GSocketListener, GumV8Socket>
{
};

struct GumV8AcceptOperation
    : public GumV8ObjectOperation<GSocketListener, GumV8Socket>
{
};

struct GumV8SetNoDelayOperation
    : public GumV8ObjectOperation<GSocketConnection, GumV8Stream>
{
  gboolean no_delay;
};

GUMJS_DECLARE_FUNCTION (gumjs_socket_listen)
static void gum_v8_listen_operation_dispose (GumV8ListenOperation * self);
static void gum_v8_listen_operation_perform (GumV8ListenOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_connect)
static void gum_v8_connect_operation_dispose (GumV8ConnectOperation * self);
static void gum_v8_connect_operation_start (GumV8ConnectOperation * self);
static void gum_v8_connect_operation_finish (GSocketClient * client,
    GAsyncResult * result, GumV8ConnectOperation * self);
static void gum_v8_socket_on_type (const FunctionCallbackInfo<Value> & info);
static void gum_v8_socket_on_local_address (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_socket_on_peer_address (
    const FunctionCallbackInfo<Value> & info);

static Local<Object> gum_v8_socket_listener_new (GSocketListener * listener,
    GumV8Socket * module);
static void gum_v8_socket_listener_on_new (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_socket_listener_on_close (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_close_listener_operation_perform (
    GumV8CloseListenerOperation * self);
static void gum_v8_socket_listener_on_accept (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_accept_operation_start (GumV8AcceptOperation * self);
static void gum_v8_accept_operation_finish (GSocketListener * listener,
    GAsyncResult * result, GumV8AcceptOperation * self);

static Local<Object> gum_v8_socket_connection_new (
    GSocketConnection * connection, GumV8Socket * module);
static void gum_v8_socket_connection_on_new (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_socket_connection_on_set_no_delay (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_set_no_delay_operation_perform (
    GumV8SetNoDelayOperation * self);

static gboolean gum_v8_socket_family_get (Handle<Value> value,
    GSocketFamily * family, GumV8Core * core);
static gboolean gum_v8_unix_socket_address_type_get (Handle<Value> value,
    GUnixSocketAddressType * type, GumV8Core * core);

static Local<Value> gum_v8_socket_address_to_value (
    struct sockaddr * addr, GumV8Core * core);

void
_gum_v8_socket_init (GumV8Socket * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> socket = ObjectTemplate::New (isolate);
  socket->Set (String::NewFromUtf8 (isolate, "_listen"),
      FunctionTemplate::New (isolate, gumjs_socket_listen, data));
  socket->Set (String::NewFromUtf8 (isolate, "_connect"),
      FunctionTemplate::New (isolate, gumjs_socket_connect, data));
  socket->Set (String::NewFromUtf8 (isolate, "type"),
      FunctionTemplate::New (isolate, gum_v8_socket_on_type));
  socket->Set (String::NewFromUtf8 (isolate, "localAddress"),
      FunctionTemplate::New (isolate, gum_v8_socket_on_local_address,
      data));
  socket->Set (String::NewFromUtf8 (isolate, "peerAddress"),
      FunctionTemplate::New (isolate, gum_v8_socket_on_peer_address,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Socket"), socket);

  Local<FunctionTemplate> listener = FunctionTemplate::New (isolate,
      gum_v8_socket_listener_on_new, data);
  listener->SetClassName (String::NewFromUtf8 (isolate, "SocketListener"));
  Local<ObjectTemplate> listener_proto = listener->PrototypeTemplate ();
  listener_proto->Set (String::NewFromUtf8 (isolate, "_close"),
      FunctionTemplate::New (isolate, gum_v8_socket_listener_on_close));
  listener_proto->Set (String::NewFromUtf8 (isolate, "_accept"),
      FunctionTemplate::New (isolate, gum_v8_socket_listener_on_accept));
  listener->InstanceTemplate ()->SetInternalFieldCount (2);
  scope->Set (String::NewFromUtf8 (isolate, "SocketListener"), listener);
  self->listener =
      new GumPersistent<FunctionTemplate>::type (isolate, listener);

  Local<FunctionTemplate> connection = FunctionTemplate::New (isolate,
      gum_v8_socket_connection_on_new, data);
  connection->SetClassName (String::NewFromUtf8 (isolate,
      "SocketConnection"));
  Local<ObjectTemplate> connection_proto = connection->PrototypeTemplate ();
  connection_proto->Set (String::NewFromUtf8 (isolate, "_setNoDelay"),
      FunctionTemplate::New (isolate,
          gum_v8_socket_connection_on_set_no_delay));
  Local<FunctionTemplate> io_stream (Local<FunctionTemplate>::New (isolate,
      *core->script->priv->stream.io_stream));
  connection->Inherit (io_stream);
  connection->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "SocketConnection"), connection);
  self->connection =
      new GumPersistent<FunctionTemplate>::type (isolate, connection);
}

void
_gum_v8_socket_realize (GumV8Socket * self)
{
  gum_v8_object_manager_init (&self->objects);
}

void
_gum_v8_socket_flush (GumV8Socket * self)
{
  gum_v8_object_manager_flush (&self->objects);
}

void
_gum_v8_socket_dispose (GumV8Socket * self)
{
  gum_v8_object_manager_free (&self->objects);
}

void
_gum_v8_socket_finalize (GumV8Socket * self)
{
  delete self->listener;
  delete self->connection;
  self->listener = nullptr;
  self->connection = nullptr;
}

/*
 * Prototype:
 * Socket.listen()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_socket_listen)
{
  GumV8Core * core = args->core;

  Local<Value> family_value;
  gchar * host;
  guint port;
  Local<Value> type_value;
  gchar * path;
  guint backlog;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "Vs?uVs?uF", &family_value, &host, &port,
      &type_value, &path, &backlog, &callback))
    return;

  GSocketFamily family;
  GUnixSocketAddressType type;
  if (!gum_v8_socket_family_get (family_value, &family, core) ||
      !gum_v8_unix_socket_address_type_get (type_value, &type, core))
  {
    g_free (host);
    g_free (path);
    return;
  }

  GSocketAddress * address = NULL;
  if (host != NULL)
  {
    address = g_inet_socket_address_new_from_string (host, port);
    g_clear_pointer (&host, g_free);
    if (address == NULL)
    {
      g_free (path);
      _gum_v8_throw_ascii_literal (core->isolate, "invalid host");
      return;
    }
  }
  else if (path != NULL)
  {
#ifdef G_OS_UNIX
    address = g_unix_socket_address_new_with_type (path, -1, type);
    g_assert (address != NULL);
#else
    g_free (path);
    _gum_v8_throw_ascii_literal (core->isolate, "UNIX sockets not available");
    return;
#endif
  }
  else if (family != G_SOCKET_FAMILY_INVALID)
  {
    address = g_inet_socket_address_new_from_string (
        (family == G_SOCKET_FAMILY_IPV4) ? "0.0.0.0" : "::",
        port);
    g_assert (address != NULL);
  }

  GumV8ListenOperation * op = gum_v8_module_operation_new (module, callback,
      gum_v8_listen_operation_perform, gum_v8_listen_operation_dispose);
  op->port = port;
  op->path = path;
  op->address = address;
  op->backlog = backlog;
  gum_v8_module_operation_schedule (op);
}

static void
gum_v8_listen_operation_dispose (GumV8ListenOperation * self)
{
  g_clear_object (&self->address);
  g_free (self->path);
}

static void
gum_v8_listen_operation_perform (GumV8ListenOperation * self)
{
  GSocketListener * listener;
  GSocketAddress * effective_address = NULL;
  GError * error = NULL;

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

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> listener_value;
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
      listener_value = gum_v8_socket_listener_new (listener, self->module);

      Local<Object> listener_object = listener_value.As<Object> ();
      if (self->path != NULL)
      {
        _gum_v8_object_set_utf8 (listener_object, "path", self->path, core);
      }
      else
      {
        if (effective_address != NULL)
        {
          self->port = g_inet_socket_address_get_port (
              G_INET_SOCKET_ADDRESS (effective_address));
          g_clear_object (&effective_address);
        }

        _gum_v8_object_set_uint (listener_object, "port", self->port, core);
      }
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      g_error_free (error);
      listener_value = null_value;
    }

    Handle<Value> argv[] = { error_value, listener_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_module_operation_finish (self);
}

/*
 * Prototype:
 * Socket.connect()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_socket_connect)
{
  GumV8Core * core = args->core;

  Local<Value> family_value;
  gchar * host;
  guint port;
  Local<Value> type_value;
  gchar * path;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "Vs?uVs?F", &family_value, &host, &port,
      &type_value, &path, &callback))
    return;

  GSocketFamily family;
  GUnixSocketAddressType type;
  if (!gum_v8_socket_family_get (family_value, &family, core) ||
      !gum_v8_unix_socket_address_type_get (type_value, &type, core))
  {
    g_free (host);
    g_free (path);
    return;
  }

  GSocketConnectable * connectable = NULL;
  if (path != NULL)
  {
#ifdef G_OS_UNIX
    family = G_SOCKET_FAMILY_UNIX;
    connectable = G_SOCKET_CONNECTABLE (g_unix_socket_address_new_with_type (
        path, -1, type));
    g_assert (connectable != NULL);
    g_clear_pointer (&path, g_free);
#else
    g_free (host);
    g_free (path);
    _gum_v8_throw_ascii_literal (core->isolate, "UNIX sockets not available");
    return;
#endif
  }

  GumV8ConnectOperation * op = gum_v8_module_operation_new (module, callback,
      gum_v8_connect_operation_start, gum_v8_connect_operation_dispose);
  op->client = NULL;
  op->family = family;
  op->host = host;
  op->port = port;
  op->connectable = connectable;
  gum_v8_module_operation_schedule (op);
}

static void
gum_v8_connect_operation_dispose (GumV8ConnectOperation * self)
{
  g_clear_object (&self->connectable);
  g_free (self->host);
  g_object_unref (self->client);
}

static void
gum_v8_connect_operation_start (GumV8ConnectOperation * self)
{
  self->client = G_SOCKET_CLIENT (g_object_new (G_TYPE_SOCKET_CLIENT,
      "family", self->family,
      NULL));

  if (self->connectable != NULL)
  {
    g_socket_client_connect_async (self->client, self->connectable,
        self->cancellable,
        (GAsyncReadyCallback) gum_v8_connect_operation_finish, self);
  }
  else
  {
    g_socket_client_connect_to_host_async (self->client, self->host, self->port,
        self->cancellable,
        (GAsyncReadyCallback) gum_v8_connect_operation_finish, self);
  }
}

static void
gum_v8_connect_operation_finish (GSocketClient * client,
                                 GAsyncResult * result,
                                 GumV8ConnectOperation * self)
{
  GError * error = NULL;
  GSocketConnection * connection;

  if (self->connectable != NULL)
  {
    connection = g_socket_client_connect_finish (client, result, &error);
  }
  else
  {
    connection = g_socket_client_connect_to_host_finish (client, result,
        &error);
  }

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> connection_value;
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
      connection_value =
          gum_v8_socket_connection_new (connection, self->module);
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      g_error_free (error);
      connection_value = null_value;
    }

    Handle<Value> argv[] = { error_value, connection_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_module_operation_finish (self);
}

/*
 * Prototype:
 * Socket.type(socket_ptr)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_socket_on_type (const FunctionCallbackInfo<Value> & info)
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
      invalid_sockaddr.sin_port = GUINT16_TO_BE (0);
      invalid_sockaddr.sin_addr.s_addr = GUINT32_TO_BE (0xffffffff);
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

/*
 * Prototype:
 * Socket.localAddress(socket_ptr)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_socket_on_local_address (const FunctionCallbackInfo<Value> & info)
{
  GumV8Socket * self = static_cast<GumV8Socket *> (
      info.Data ().As<External> ()->Value ());

  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = reinterpret_cast<struct sockaddr *> (&large_addr);
  gum_socklen_t len = sizeof (large_addr);
  if (getsockname (info[0]->ToInteger ()->Value (), addr, &len) == 0)
  {
    info.GetReturnValue ().Set (
        gum_v8_socket_address_to_value (addr, self->core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

/*
 * Prototype:
 * Socket.peerAddress(socket_ptr)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_socket_on_peer_address (const FunctionCallbackInfo<Value> & info)
{
  GumV8Socket * self = static_cast<GumV8Socket *> (
      info.Data ().As<External> ()->Value ());

  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = reinterpret_cast<struct sockaddr *> (&large_addr);
  gum_socklen_t len = sizeof (large_addr);
  if (getpeername (info[0]->ToInteger ()->Value (), addr, &len) == 0)
  {
    info.GetReturnValue ().Set (
        gum_v8_socket_address_to_value (addr, self->core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static Local<Object>
gum_v8_socket_listener_new (GSocketListener * listener,
                            GumV8Socket * module)
{
  Isolate * isolate = module->core->isolate;
  Local<Context> context = isolate->GetCurrentContext ();

  Local<FunctionTemplate> ctor (
      Local<FunctionTemplate>::New (isolate, *module->listener));
  Handle<Value> argv[] = { External::New (isolate, listener) };
  return ctor->GetFunction ()->NewInstance (context, G_N_ELEMENTS (argv),
      argv).ToLocalChecked ();
}

static void
gum_v8_socket_listener_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Socket * module = static_cast<GumV8Socket *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected a native SocketListener handle")));
    return;
  }
  Local<Value> listener_value = info[0];
  if (!listener_value->IsExternal ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid SocketListener handle")));
    return;
  }
  GSocketListener * listener = G_SOCKET_LISTENER (
      listener_value.As<External> ()->Value ());

  gum_v8_object_manager_add (&module->objects, info.Holder (), listener,
      module);
}

static void
gum_v8_socket_listener_on_close (const FunctionCallbackInfo<Value> & info)
{
  GumV8SocketListener * self = gum_v8_object_get<GumV8SocketListener> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected callback")));
    return;
  }

  Local<Value> callback_value = info[0];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  g_cancellable_cancel (self->cancellable);

  GumV8CloseListenerOperation * op = gum_v8_object_operation_new (self,
      callback_value, gum_v8_close_listener_operation_perform);
  gum_v8_object_operation_schedule_when_idle (op);
}

static void
gum_v8_close_listener_operation_perform (GumV8CloseListenerOperation * self)
{
  g_socket_listener_close (self->object->handle);

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (Null (isolate), 0, nullptr);
  }

  gum_v8_object_operation_finish (self);
}

static void
gum_v8_socket_listener_on_accept (const FunctionCallbackInfo<Value> & info)
{
  GumV8SocketListener * self = gum_v8_object_get<GumV8SocketListener> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected callback")));
    return;
  }

  Local<Value> callback_value = info[0];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  GumV8AcceptOperation * op = gum_v8_object_operation_new (self, callback_value,
      gum_v8_accept_operation_start);
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_accept_operation_start (GumV8AcceptOperation * self)
{
  GumV8SocketListener * listener = self->object;

  g_socket_listener_accept_async (listener->handle, listener->cancellable,
      (GAsyncReadyCallback) gum_v8_accept_operation_finish, self);
}

static void
gum_v8_accept_operation_finish (GSocketListener * listener,
                                GAsyncResult * result,
                                GumV8AcceptOperation * self)
{
  GError * error = NULL;
  GSocketConnection * connection;

  connection = g_socket_listener_accept_finish (listener, result, NULL, &error);

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> connection_value;
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
      connection_value =
          gum_v8_socket_connection_new (connection, self->object->module);
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      g_error_free (error);
      connection_value = null_value;
    }

    Handle<Value> argv[] = { error_value, connection_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_object_operation_finish (self);
}

static Local<Object>
gum_v8_socket_connection_new (GSocketConnection * connection,
                              GumV8Socket * module)
{
  Isolate * isolate = module->core->isolate;
  Local<Context> context = isolate->GetCurrentContext ();

  Local<FunctionTemplate> ctor (
      Local<FunctionTemplate>::New (isolate, *module->connection));
  Handle<Value> argv[] = { External::New (isolate, connection) };
  return ctor->GetFunction ()->NewInstance (context, G_N_ELEMENTS (argv),
      argv).ToLocalChecked ();
}

static void
gum_v8_socket_connection_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Socket * module = static_cast<GumV8Socket *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();
  Local<Context> context = isolate->GetCurrentContext ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected a native SocketConnection handle")));
    return;
  }
  Local<Value> connection_value = info[0];
  if (!connection_value->IsExternal ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid SocketConnection handle")));
    return;
  }
  GSocketConnection * connection = G_SOCKET_CONNECTION (
      connection_value.As<External> ()->Value ());

  Local<FunctionTemplate> base_ctor (Local<FunctionTemplate>::New (isolate,
      *module->core->script->priv->stream.io_stream));
  Handle<Value> argv[] = { External::New (isolate, connection) };
  base_ctor->GetFunction ()->Call (context, info.Holder (), G_N_ELEMENTS (argv),
      argv).ToLocalChecked ();
}

static void
gum_v8_socket_connection_on_set_no_delay (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8IOStream * self = gum_v8_object_get<GumV8IOStream> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 2)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected boolean and callback")));
    return;
  }

  Local<Value> no_delay_value = info[0];
  if (!no_delay_value->IsBoolean ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected a boolean")));
    return;
  }
  gboolean no_delay = no_delay_value.As<Boolean> ()->Value ();

  Local<Value> callback_value = info[1];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  GumV8SetNoDelayOperation * op = gum_v8_object_operation_new (self,
      callback_value, gum_v8_set_no_delay_operation_perform);
  op->no_delay = no_delay;
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_set_no_delay_operation_perform (GumV8SetNoDelayOperation * self)
{
  GSocket * socket = g_socket_connection_get_socket (self->object->handle);

  GError * error = NULL;
  gboolean success = g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY,
      self->no_delay, &error);

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> success_value = success ? True (isolate) : False (isolate);
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      g_error_free (error);
    }

    Handle<Value> argv[] = { error_value, success_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_object_operation_finish (self);
}

static gboolean
gum_v8_socket_family_get (Handle<Value> value,
                          GSocketFamily * family,
                          GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNull ())
  {
    *family = G_SOCKET_FAMILY_INVALID;
    return TRUE;
  }

  if (!value->IsString ())
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid socket address family");
    return FALSE;
  }
  String::Utf8Value value_utf8 (value.As<String> ());
  const gchar * value_str = *value_utf8;

  if (strcmp (value_str, "unix") == 0)
  {
    *family = G_SOCKET_FAMILY_UNIX;
    return TRUE;
  }

  if (strcmp (value_str, "ipv4") == 0)
  {
    *family = G_SOCKET_FAMILY_IPV4;
    return TRUE;
  }

  if (strcmp (value_str, "ipv6") == 0)
  {
    *family = G_SOCKET_FAMILY_IPV6;
    return TRUE;
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid socket address family");
  return FALSE;
}

static gboolean
gum_v8_unix_socket_address_type_get (Handle<Value> value,
                                     GUnixSocketAddressType * type,
                                     GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNull ())
  {
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
    return TRUE;
  }

#ifdef G_OS_UNIX
  if (!value->IsString ())
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid UNIX socket address type");
    return FALSE;
  }
  String::Utf8Value value_utf8 (value.As<String> ());
  const gchar * value_str = *value_utf8;

  if (strcmp (value_str, "anonymous") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_ANONYMOUS;
    return TRUE;
  }

  if (strcmp (value_str, "path") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
    return TRUE;
  }

  if (strcmp (value_str, "abstract") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT;
    return TRUE;
  }

  if (strcmp (value_str, "abstract-padded") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT_PADDED;
    return TRUE;
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid UNIX socket address type");
  return FALSE;
#else
  _gum_v8_throw_ascii_literal (isolate, "UNIX sockets not available");
  return FALSE;
#endif
}

static Local<Value>
gum_v8_socket_address_to_value (struct sockaddr * addr,
                                GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  switch (addr->sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in * inet_addr =
          reinterpret_cast<struct sockaddr_in *> (addr);
#ifdef G_OS_WIN32
      gunichar2 ip_utf16[15 + 1 + 5 + 1];
      gchar ip[15 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      WSAAddressToStringW (addr, sizeof (struct sockaddr_in), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      gchar * p = strchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET_ADDRSTRLEN];
      inet_ntop (AF_INET, &inet_addr->sin_addr, ip, sizeof (ip));
#endif
      Local<Object> result (Object::New (isolate));
      _gum_v8_object_set_ascii (result, "ip", ip, core);
      _gum_v8_object_set_uint (result, "port",
          GUINT16_FROM_BE (inet_addr->sin_port), core);
      return result;
    }
    case AF_INET6:
    {
      struct sockaddr_in6 * inet_addr =
          reinterpret_cast<struct sockaddr_in6 *> (addr);
#ifdef G_OS_WIN32
      gunichar2 ip_utf16[45 + 1 + 5 + 1];
      gchar ip[45 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      WSAAddressToStringW (addr, sizeof (struct sockaddr_in6), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      gchar * p = strrchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, &inet_addr->sin6_addr, ip, sizeof (ip));
#endif
      Local<Object> result (Object::New (isolate));
      _gum_v8_object_set_ascii (result, "ip", ip, core);
      _gum_v8_object_set_uint (result, "port",
          GUINT16_FROM_BE (inet_addr->sin6_port), core);
      return result;
    }
    case AF_UNIX:
    {
      Local<Object> result (Object::New (isolate));
      _gum_v8_object_set_ascii (result, "path", "", core); /* FIXME */
      return result;
    }
  }

  return Null (isolate);
}
