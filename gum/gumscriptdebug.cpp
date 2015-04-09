/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptdebug.h"

#include <gio/gio.h>
#include <string.h>
#include <v8-debug.h>

#define GUM_MAX_DEBUG_MESSAGE_SIZE (1024 * 1024)
#define GUM_CHUNK_SIZE 10

#define GUM_DEBUG_SESSION(obj) (reinterpret_cast<GumDebugSession *> (obj))

using namespace v8;

typedef struct _GumDebugSession GumDebugSession;

struct _GumDebugSession
{
  GIOStream * stream;
  GInputStream * input;
  GOutputStream * output;

  gchar * buffer;
  gsize length;
  gsize capacity;
  gsize message_length;
  gsize header_length;

  GQueue * outgoing;
};

static gboolean gum_script_debug_on_incoming_connection (
    GSocketService * service, GSocketConnection * connection,
    GObject * source_object, gpointer user_data);
static void gum_script_debug_on_message (const Debug::Message & message);

static GumDebugSession * gum_debug_session_new (GIOStream * stream);
static void gum_debug_session_free (GumDebugSession * self);

static void gum_debug_session_open (GumDebugSession * self);
static void gum_debug_session_read_next_chunk (GumDebugSession * self);
static void gum_debug_session_send (GumDebugSession * self, guint n_headers,
    ...);

static void gum_debug_session_on_read_ready (GObject * source_object,
    GAsyncResult * res, gpointer user_data);
static void gum_debug_session_on_write_all_ready (GObject * source_object,
    GAsyncResult * res, gpointer user_data);

static Isolate * gum_isolate = nullptr;
static GumPersistent<Context>::type * gum_context = nullptr;
static GSocketService * gum_service = NULL;
static GSList * gum_sessions = NULL;

gboolean
_gum_script_debug_enable_remote_debugger (Isolate * isolate,
                                          guint16 port,
                                          GError ** error)
{
  GSocketService * service = NULL;

  if (gum_service != NULL)
    goto error_already_enabled;

  service = g_socket_service_new ();
  if (!g_socket_listener_add_inet_port (G_SOCKET_LISTENER (service), port, NULL,
      error))
    goto error;
  g_signal_connect (service, "incoming",
      G_CALLBACK (gum_script_debug_on_incoming_connection),
      NULL);
  g_socket_service_start (service);

  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    Debug::SetMessageHandler (gum_script_debug_on_message);

    gum_isolate = isolate;
    gum_context = new GumPersistent<Context>::type (isolate,
        Debug::GetDebugContext ());
    gum_service = service;
  }

  return TRUE;

error_already_enabled:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "already enabled");
    goto error;
  }

error:
  {
    if (service != NULL)
      g_object_unref (service);
    return FALSE;
  }
}

void
_gum_script_debug_disable_remote_debugger (void)
{
  if (gum_service == NULL)
    return;

  delete gum_context;
  gum_context = nullptr;

  gum_isolate = nullptr;

  Debug::SetMessageHandler (nullptr);

  while (gum_sessions != NULL)
    gum_debug_session_free (GUM_DEBUG_SESSION (gum_sessions->data));

  g_socket_service_stop (gum_service);
  g_object_unref (gum_service);
  gum_service = NULL;
}

static gboolean
gum_script_debug_on_incoming_connection (GSocketService * service,
                                         GSocketConnection * connection,
                                         GObject * source_object,
                                         gpointer user_data)
{
  GumDebugSession * session;

  session = gum_debug_session_new (G_IO_STREAM (connection));

  gum_debug_session_open (session);

  return TRUE;
}

static void
gum_script_debug_on_message (const Debug::Message & message)
{
  Isolate * isolate = message.GetIsolate ();

  HandleScope scope (isolate);
  Local<String> json = message.GetJSON ();
  String::Utf8Value json_str (json);
  for (GSList * cur = gum_sessions; cur != NULL; cur = cur->next)
  {
    GumDebugSession * session = GUM_DEBUG_SESSION (cur->data);
    gum_debug_session_send (session, 0, *json_str);
  }
}

static GumDebugSession *
gum_debug_session_new (GIOStream * stream)
{
  GumDebugSession * session;

  session = g_slice_new (GumDebugSession);
  session->stream = stream;
  g_object_ref (stream);
  session->input = g_io_stream_get_input_stream (stream);
  session->output = g_io_stream_get_output_stream (stream);

  session->buffer = NULL;
  session->length = 0;
  session->capacity = 0;
  session->message_length = 0;
  session->header_length = 0;

  session->outgoing = g_queue_new ();

  gum_sessions = g_slist_prepend (gum_sessions, session);

  return session;
}

static void
gum_debug_session_free (GumDebugSession * session)
{
  gum_sessions = g_slist_remove (gum_sessions, session);

  g_queue_free_full (session->outgoing,
      reinterpret_cast<GDestroyNotify> (g_bytes_unref));

  g_free (session->buffer);

  g_io_stream_close_async (session->stream, G_PRIORITY_LOW, NULL, NULL, NULL);
  g_object_unref (session->stream);

  g_slice_free (GumDebugSession, session);
}

static void
gum_debug_session_open (GumDebugSession * self)
{
  gum_debug_session_send (self, 4,
      "Type", "connect",
      "V8-Version", V8::GetVersion (),
      "Protocol-Version", "1",
      "Embedding-Host", "Frida",
      "");

  gum_debug_session_read_next_chunk (self);
}

static void
gum_debug_session_read_next_chunk (GumDebugSession * self)
{
  gssize available = self->capacity - self->length;
  if (available < GUM_CHUNK_SIZE)
  {
    self->capacity = MIN (self->capacity + (GUM_CHUNK_SIZE - available),
        GUM_MAX_DEBUG_MESSAGE_SIZE);
    self->buffer =
        static_cast<char *> (g_realloc (self->buffer, self->capacity));

    available = self->capacity - self->length;
  }

  if (available > 0)
  {
    g_input_stream_read_async (self->input,
        self->buffer + self->length,
        available,
        G_PRIORITY_DEFAULT,
        NULL,
        gum_debug_session_on_read_ready,
        self);
  }
  else
  {
    gum_debug_session_free (self);
  }
}

static void
gum_debug_session_send (GumDebugSession * self,
                        guint n_headers,
                        ...)
{
  GString * m;
  va_list vl;
  guint i;
  const gchar * content;
  GBytes * message;
  gboolean write_now;

  m = g_string_new ("");

  va_start (vl, n_headers);

  for (i = 0; i != n_headers; i++)
  {
    const gchar * key, * value;

    key = va_arg (vl, const gchar *);
    value = va_arg (vl, const gchar *);

    g_string_append_printf (m, "%s: %s\r\n", key, value);
  }

  content = va_arg (vl, const gchar *);
  g_string_append_printf (m, "Content-Length: %" G_GSIZE_MODIFIER "u\r\n\r\n%s",
      static_cast<gsize> (strlen (content)), content);

  va_end (vl);

  message = g_string_free_to_bytes (m);
  write_now = g_queue_is_empty (self->outgoing);
  g_queue_push_tail (self->outgoing, message);

  if (write_now)
  {
    g_output_stream_write_all_async (self->output,
        g_bytes_get_data (message, NULL),
        g_bytes_get_size (message),
        G_PRIORITY_DEFAULT,
        NULL,
        gum_debug_session_on_write_all_ready,
        self);
  }
}

static void
gum_debug_session_on_read_ready (GObject * source_object,
                                 GAsyncResult * res,
                                 gpointer user_data)
{
  GumDebugSession * self = GUM_DEBUG_SESSION (user_data);
  gssize n;
  gboolean more_data;

  n = g_input_stream_read_finish (self->input, res, NULL);
  if (n <= 0)
    goto error_gone;
  self->length += n;

  do
  {
    more_data = FALSE;

    if (self->message_length == 0)
    {
      gchar * p;

      p = g_strstr_len (self->buffer, self->length, "\r\n\r\n");
      if (p != NULL)
      {
        gchar * headers;
        gchar ** lines;
        guint i;

        self->header_length = (p + 4) - self->buffer;

        headers = g_strndup (self->buffer, p - self->buffer);
        lines = g_strsplit (headers, "\r\n", -1);
        g_free (headers);
        for (i = 0; lines[i] != NULL; i++)
        {
          gchar ** tokens;

          tokens = g_strsplit (lines[i], ": ", 2);
          if (g_strv_length (tokens) == 2)
          {
            const gchar * key, * value;

            key = tokens[0];
            value = tokens[1];

            if (strcmp (key, "Content-Length") == 0)
            {
              gchar * end = NULL;
              gssize content_length;

              content_length = g_ascii_strtoull (value, &end, 10);
              if (end == value + strlen (value))
                self->message_length = self->header_length + content_length;
            }
          }
          g_strfreev (tokens);
        }
        g_strfreev (lines);

        if (self->message_length == 0)
          goto error_protocol;

        more_data = TRUE;
      }
    }
    else if (self->length >= self->message_length)
    {
      gboolean pending_error = FALSE;

      {
        Locker locker (gum_isolate);
        Isolate::Scope isolate_scope (gum_isolate);
        HandleScope handle_scope (gum_isolate);
        Local<Context> context (Local<Context>::New (gum_isolate, *gum_context));
        Context::Scope context_scope (context);

        glong command_length;
        uint16_t * command = g_utf8_to_utf16 (self->buffer + self->header_length,
            self->message_length - self->header_length, NULL, &command_length, NULL);
        if (command != NULL)
        {
          Debug::SendCommand (gum_isolate, command, command_length);
          Debug::ProcessDebugMessages ();
        }
        else
        {
          pending_error = TRUE;
        }
      }

      if (pending_error)
        goto error_protocol;

      self->length -= self->message_length;
      if (self->length > 0)
      {
        memmove (self->buffer, self->buffer + self->message_length,
            self->length);
        more_data = TRUE;
      }
      self->message_length = 0;
      self->header_length = 0;
    }
  }
  while (more_data);

  gum_debug_session_read_next_chunk (self);

  return;

error_gone:
error_protocol:
  {
    gum_debug_session_free (self);
  }
}

static void
gum_debug_session_on_write_all_ready (GObject * source_object,
                                      GAsyncResult * res,
                                      gpointer user_data)
{
  GumDebugSession * self = GUM_DEBUG_SESSION (user_data);
  GBytes * message;

  if (!g_output_stream_write_all_finish (self->output, res, NULL, NULL))
    return; /* read will fail */

  g_bytes_unref (static_cast<GBytes *> (g_queue_pop_head (self->outgoing)));

  message = static_cast<GBytes *> (g_queue_peek_head (self->outgoing));
  if (message != NULL)
  {
    g_output_stream_write_all_async (self->output,
        g_bytes_get_data (message, NULL),
        g_bytes_get_size (message),
        G_PRIORITY_DEFAULT,
        NULL,
        gum_debug_session_on_write_all_ready,
        self);
  }
}

void
_gum_script_debug_init (GumScriptDebug * self,
                        GumScriptCore * core,
                        Handle<ObjectTemplate> scope)
{
}

void
_gum_script_debug_realize (GumScriptDebug * self)
{
  (void) self;
}

void
_gum_script_debug_dispose (GumScriptDebug * self)
{
  (void) self;
}

void
_gum_script_debug_finalize (GumScriptDebug * self)
{
}

