/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8socket.h"

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

using namespace v8;

typedef struct _GumV8ListenOperation GumV8ListenOperation;
typedef struct _GumV8ConnectOperation GumV8ConnectOperation;

typedef struct _GumV8CloseListenerOperation GumV8CloseListenerOperation;
typedef struct _GumV8AcceptOperation GumV8AcceptOperation;

typedef struct _GumV8SetNoDelayOperation GumV8SetNoDelayOperation;

struct _GumV8ListenOperation
{
  guint16 port;
  gint backlog;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Socket * module;
};

struct _GumV8ConnectOperation
{
  GSocketClient * client;
  GSocketFamily family;
  gchar * host;
  guint16 port;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Socket * module;
};

struct _GumV8CloseListenerOperation
{
  GSocketListener * listener;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Socket * module;
};

struct _GumV8AcceptOperation
{
  GSocketListener * listener;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Socket * module;
};

struct _GumV8SetNoDelayOperation
{
  GSocketConnection * connection;
  gboolean no_delay;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Socket * module;
};

static void gum_v8_socket_on_listen (const FunctionCallbackInfo<Value> & info);
static void gum_v8_listen_operation_free (GumV8ListenOperation * op);
static void gum_v8_listen_operation_perform (GumV8ListenOperation * self);
static void gum_v8_socket_on_connect (const FunctionCallbackInfo<Value> & info);
static void gum_v8_connect_operation_free (GumV8ConnectOperation * op);
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
static void gum_v8_close_listener_operation_free (
    GumV8CloseListenerOperation * op);
static void gum_v8_close_listener_operation_perform (
    GumV8CloseListenerOperation * self);
static void gum_v8_socket_listener_on_accept (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_accept_operation_free (GumV8AcceptOperation * op);
static void gum_v8_accept_operation_start (GumV8AcceptOperation * self);
static void gum_v8_accept_operation_finish (GSocketListener * listener,
    GAsyncResult * result, GumV8AcceptOperation * self);

static Local<Object> gum_v8_socket_connection_new (
    GSocketConnection * connection, GumV8Socket * module);
static void gum_v8_socket_connection_on_new (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_socket_connection_on_set_no_delay (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_set_no_delay_operation_free (GumV8SetNoDelayOperation * op);
static void gum_v8_set_no_delay_operation_perform (
    GumV8SetNoDelayOperation * self);

static void gum_v8_listener_on_weak_notify (
    const WeakCallbackInfo<GumV8Socket> & info);
static void gum_v8_listener_handle_free (gpointer data);

static gboolean gum_v8_socket_family_get (Handle<Value> value,
    GSocketFamily * family, GumV8Core * core);

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
      FunctionTemplate::New (isolate, gum_v8_socket_on_listen, data));
  socket->Set (String::NewFromUtf8 (isolate, "_connect"),
      FunctionTemplate::New (isolate, gum_v8_socket_on_connect, data));
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
  connection->InstanceTemplate ()->SetInternalFieldCount (2);
  scope->Set (String::NewFromUtf8 (isolate, "SocketConnection"), connection);
  self->connection =
      new GumPersistent<FunctionTemplate>::type (isolate, connection);

  self->listeners = g_hash_table_new_full (NULL, NULL, g_object_unref,
      gum_v8_listener_handle_free);
  self->cancellable = g_cancellable_new ();
}

void
_gum_v8_socket_realize (GumV8Socket * self)
{
  (void) self;
}

void
_gum_v8_socket_flush (GumV8Socket * self)
{
  g_cancellable_cancel (self->cancellable);
}

void
_gum_v8_socket_dispose (GumV8Socket * self)
{
  g_hash_table_remove_all (self->listeners);
}

void
_gum_v8_socket_finalize (GumV8Socket * self)
{
  delete self->listener;
  delete self->connection;
  self->listener = nullptr;
  self->connection = nullptr;

  g_clear_object (&self->cancellable);
  g_clear_pointer (&self->listeners, g_hash_table_unref);
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
static void
gum_v8_socket_on_listen (const FunctionCallbackInfo<Value> & info)
{
  GumV8Socket * module = static_cast<GumV8Socket *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 3)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected port, backlog, and callback")));
    return;
  }

  Local<Value> port_value = info[0];
  if (!port_value->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid port")));
    return;
  }
  guint16 port = port_value->ToInteger ()->Value ();

  Local<Value> backlog_value = info[1];
  if (!backlog_value->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid backlog")));
    return;
  }
  gint backlog = backlog_value->ToInteger ()->Value ();

  Local<Value> callback_value = info[2];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  GumV8ListenOperation * op = g_slice_new (GumV8ListenOperation);
  op->port = port;
  op->backlog = backlog;
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_listen_operation_perform, op,
      (GDestroyNotify) gum_v8_listen_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_listen_operation_free (GumV8ListenOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_slice_free (GumV8ListenOperation, op);
}

static void
gum_v8_listen_operation_perform (GumV8ListenOperation * self)
{
  GSocketListener * listener;
  GError * error = NULL;

  listener = G_SOCKET_LISTENER (g_object_new (G_TYPE_SOCKET_LISTENER,
      "listen-backlog", self->backlog,
      NULL));

  if (self->port != 0)
  {
    g_socket_listener_add_inet_port (listener, self->port, NULL, &error);
  }
  else
  {
    self->port = g_socket_listener_add_any_inet_port (listener, NULL, &error);
  }

  if (error != NULL)
    g_clear_object (&listener);

  {
    GumV8Core * core = self->module->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> listener_value;
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
      listener_value = gum_v8_socket_listener_new (listener, self->module);
      _gum_v8_object_set_uint (listener_value.As<Object> (), "port", self->port,
          core);
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

  gum_script_job_free (self->job);
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
static void
gum_v8_socket_on_connect (const FunctionCallbackInfo<Value> & info)
{
  GumV8Socket * module = static_cast<GumV8Socket *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 4)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected family, host, port, and callback")));
    return;
  }

  GSocketFamily family;
  if (!gum_v8_socket_family_get (info[0], &family, core))
    return;

  Local<Value> host_value = info[1];
  if (!host_value->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid host")));
    return;
  }
  String::Utf8Value host_utf8 (host_value);
  const gchar * host = *host_utf8;

  Local<Value> port_value = info[2];
  if (!port_value->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid port")));
    return;
  }
  guint16 port = port_value->ToInteger ()->Value ();

  Local<Value> callback_value = info[3];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  GumV8ConnectOperation * op = g_slice_new (GumV8ConnectOperation);
  op->client = NULL;
  op->family = family;
  op->host = g_strdup (host);
  op->port = port;
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_connect_operation_start, op,
      (GDestroyNotify) gum_v8_connect_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_connect_operation_free (GumV8ConnectOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_free (op->host);
  g_object_unref (op->client);

  g_slice_free (GumV8ConnectOperation, op);
}

static void
gum_v8_connect_operation_start (GumV8ConnectOperation * self)
{
  self->client = G_SOCKET_CLIENT (g_object_new (G_TYPE_SOCKET_CLIENT,
      "family", self->family,
      NULL));

  g_socket_client_connect_to_host_async (self->client, self->host, self->port,
      self->module->cancellable,
      (GAsyncReadyCallback) gum_v8_connect_operation_finish, self);
}

static void
gum_v8_connect_operation_finish (GSocketClient * client,
                                 GAsyncResult * result,
                                 GumV8ConnectOperation * self)
{
  GError * error = NULL;
  GSocketConnection * connection;

  connection = g_socket_client_connect_to_host_finish (client, result, &error);

  {
    GumV8Core * core = self->module->core;
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

  gum_script_job_free (self->job);
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

template<typename T>
static void
gum_v8_socket_object_get (const FunctionCallbackInfo<Value> & info,
                          T ** object,
                          GumV8Socket ** module,
                          GumV8Core ** core)
{
  Local<Object> instance = info.Holder ();

  *object = static_cast<T *> (
      instance->GetAlignedPointerFromInternalField (0));
  *module = static_cast<GumV8Socket *> (
      instance->GetAlignedPointerFromInternalField (1));
  *core = (*module)->core;
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

  Local<Object> instance (info.Holder ());
  instance->SetAlignedPointerInInternalField (0, listener);
  instance->SetAlignedPointerInInternalField (1, module);

  GumPersistent<Object>::type * instance_handle =
      new GumPersistent<Object>::type (isolate, instance);
  instance_handle->MarkIndependent ();
  instance_handle->SetWeak (module, gum_v8_listener_on_weak_notify,
      WeakCallbackType::kInternalFields);

  g_hash_table_insert (module->listeners, listener, instance_handle);
}

static void
gum_v8_socket_listener_on_close (const FunctionCallbackInfo<Value> & info)
{
  Isolate * isolate = info.GetIsolate ();
  GSocketListener * listener;
  GumV8Socket * module;
  GumV8Core * core;

  gum_v8_socket_object_get (info, &listener, &module, &core);

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

  GumV8CloseListenerOperation * op = g_slice_new (GumV8CloseListenerOperation);
  op->listener = listener;
  g_object_ref (listener);
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_close_listener_operation_perform, op,
      (GDestroyNotify) gum_v8_close_listener_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_close_listener_operation_free (GumV8CloseListenerOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_object_unref (op->listener);

  g_slice_free (GumV8CloseListenerOperation, op);
}

static void
gum_v8_close_listener_operation_perform (GumV8CloseListenerOperation * self)
{
  g_socket_listener_close (self->listener);

  {
    GumV8Core * core = self->module->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (Null (isolate), 0, nullptr);
  }

  gum_script_job_free (self->job);
}

static void
gum_v8_socket_listener_on_accept (const FunctionCallbackInfo<Value> & info)
{
  Isolate * isolate = info.GetIsolate ();
  GSocketListener * listener;
  GumV8Socket * module;
  GumV8Core * core;

  gum_v8_socket_object_get (info, &listener, &module, &core);

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

  GumV8AcceptOperation * op = g_slice_new (GumV8AcceptOperation);
  op->listener = listener;
  g_object_ref (listener);
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_accept_operation_start, op,
      (GDestroyNotify) gum_v8_accept_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_accept_operation_free (GumV8AcceptOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_object_unref (op->listener);

  g_slice_free (GumV8AcceptOperation, op);
}

static void
gum_v8_accept_operation_start (GumV8AcceptOperation * self)
{
  g_socket_listener_accept_async (self->listener, self->module->cancellable,
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
    GumV8Core * core = self->module->core;
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

  gum_script_job_free (self->job);
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
  Isolate * isolate = info.GetIsolate ();
  GSocketConnection * connection;
  GumV8Socket * module;
  GumV8Core * core;

  gum_v8_socket_object_get (info, &connection, &module, &core);

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

  GumV8SetNoDelayOperation * op = g_slice_new (GumV8SetNoDelayOperation);
  op->connection = connection;
  g_object_ref (connection);
  op->no_delay = no_delay;
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_set_no_delay_operation_perform, op,
      (GDestroyNotify) gum_v8_set_no_delay_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_set_no_delay_operation_free (GumV8SetNoDelayOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_object_unref (op->connection);

  g_slice_free (GumV8SetNoDelayOperation, op);
}

static void
gum_v8_set_no_delay_operation_perform (GumV8SetNoDelayOperation * self)
{
  GSocket * socket = g_socket_connection_get_socket (self->connection);

  GError * error = NULL;
  gboolean success = g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY,
      self->no_delay, &error);

  {
    GumV8Core * core = self->module->core;
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

  gum_script_job_free (self->job);
}

static void
gum_v8_listener_on_weak_notify (const WeakCallbackInfo<GumV8Socket> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GSocketListener * listener = G_SOCKET_LISTENER (info.GetInternalField (0));
  GumV8Socket * module = static_cast<GumV8Socket *> (info.GetInternalField (1));
  g_hash_table_remove (module->listeners, listener);
}

static void
gum_v8_listener_handle_free (gpointer data)
{
  GumPersistent<Object>::type * instance_handle =
      static_cast<GumPersistent<Object>::type *> (data);
  delete instance_handle;
}

static gboolean
gum_v8_socket_family_get (Handle<Value> value,
                          GSocketFamily * family,
                          GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (!value->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid address family")));
    return FALSE;
  }

  switch (value->ToInteger ()->Value ())
  {
    case 4:
      *family = G_SOCKET_FAMILY_IPV4;
      break;
    case 6:
      *family = G_SOCKET_FAMILY_IPV6;
      break;
    default:
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "invalid address family")));
      return FALSE;
  }

  return TRUE;
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
