/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8socket.h"

#include "gumv8scope.h"
#include "gumv8script-priv.h"

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

typedef struct _GumV8ConnectOperation GumV8ConnectOperation;

struct _GumV8ConnectOperation
{
  GSocketClient * client;
  gchar * host;
  guint16 port;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Socket * module;
};

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
  (void) self;
}

void
_gum_v8_socket_finalize (GumV8Socket * self)
{
  g_clear_object (&self->cancellable);
}

/*
 * Prototype:
 * Socket._connect()
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

  Local<Value> family_value = info[0];
  if (!family_value->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid address family")));
    return;
  }
  GSocketFamily family;
  switch (family_value->ToInteger ()->Value ())
  {
    case 4:
      family = G_SOCKET_FAMILY_IPV4;
      break;
    case 6:
      family = G_SOCKET_FAMILY_IPV6;
      break;
    default:
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "invalid address family")));
      return;
  }

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

  GSocketClient * client = G_SOCKET_CLIENT (g_object_new (G_TYPE_SOCKET_CLIENT,
      "family", family,
      NULL));

  GumV8ConnectOperation * op = g_slice_new (GumV8ConnectOperation);
  op->client = client;
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
    Local<Value> stream_value;
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
      stream_value = _gum_v8_io_stream_new (G_IO_STREAM (connection),
          &core->script->priv->stream);
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      stream_value = null_value;
    }

    g_clear_error (&error);

    Handle<Value> argv[] = { error_value, stream_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);

    gum_script_job_free (self->job);
  }
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

