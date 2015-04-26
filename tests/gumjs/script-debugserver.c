/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <gio/gio.h>
#include <string.h>

#define GUM_MAX_DEBUG_MESSAGE_SIZE 2048
#define GUM_CHUNK_SIZE 512

#define GUM_DEBUG_SERVER(obj) ((GumDebugServer *) (obj))
#define GUM_DEBUG_SESSION(obj) ((GumDebugSession *) (obj))

typedef struct _GumDebugServer  GumDebugServer;
typedef struct _GumDebugSession GumDebugSession;

struct _GumDebugServer
{
  GSocketService * service;
  GSList * sessions;
};

struct _GumDebugSession
{
  GumDebugServer * server;

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

static void gum_debug_server_remove_session (GumDebugServer * self,
    GumDebugSession * session);
static gboolean gum_debug_server_on_incoming_connection (
    GSocketService * service, GSocketConnection * connection,
    GObject * source_object, gpointer user_data);
static void gum_debug_server_on_message (const gchar * message,
    gpointer user_data);

static GumDebugSession * gum_debug_session_new (GumDebugServer * server,
    GIOStream * stream);
static void gum_debug_session_free (GumDebugSession * self);

static void gum_debug_session_open (GumDebugSession * self);
static void gum_debug_session_read_next_chunk (GumDebugSession * self);
static void gum_debug_session_send (GumDebugSession * self, guint n_headers,
    ...);

static void gum_debug_session_on_read_ready (GObject * source_object,
    GAsyncResult * res, gpointer user_data);
static void gum_debug_session_on_write_all_ready (GObject * source_object,
    GAsyncResult * res, gpointer user_data);

GumDebugServer *
gum_debug_server_new (guint16 port)
{
  GumDebugServer * server;
  GSocketService * service;
  gboolean port_available;

  server = g_slice_new (GumDebugServer);

  service = g_socket_service_new ();
  port_available = g_socket_listener_add_inet_port (G_SOCKET_LISTENER (service),
      port, NULL, NULL);
  g_assert (port_available);
  g_signal_connect (service, "incoming",
      G_CALLBACK (gum_debug_server_on_incoming_connection), server);
  server->service = service;

  server->sessions = NULL;

  g_socket_service_start (service);

  gum_script_set_debug_message_handler (gum_debug_server_on_message, server,
      NULL);

  return server;
}

void
gum_debug_server_free (GumDebugServer * server)
{
  gum_script_set_debug_message_handler (NULL, NULL, NULL);

  while (server->sessions != NULL)
  {
    gum_debug_server_remove_session (server,
        GUM_DEBUG_SESSION (server->sessions->data));
  }

  g_socket_service_stop (server->service);
  g_object_unref (server->service);

  g_slice_free (GumDebugServer, server);
}

static void
gum_debug_server_remove_session (GumDebugServer * self,
                                 GumDebugSession * session)
{
  self->sessions = g_slist_remove (self->sessions, session);

  gum_debug_session_free (session);
}

static gboolean
gum_debug_server_on_incoming_connection (GSocketService * service,
                                         GSocketConnection * connection,
                                         GObject * source_object,
                                         gpointer user_data)
{
  GumDebugServer * server = GUM_DEBUG_SERVER (user_data);
  GumDebugSession * session;

  session = gum_debug_session_new (server, G_IO_STREAM (connection));
  server->sessions = g_slist_prepend (server->sessions, session);

  gum_debug_session_open (session);

  return TRUE;
}

static void
gum_debug_server_on_message (const gchar * message,
                             gpointer user_data)
{
  GumDebugServer * server = GUM_DEBUG_SERVER (user_data);

  for (GSList * cur = server->sessions; cur != NULL; cur = cur->next)
  {
    GumDebugSession * session = GUM_DEBUG_SESSION (cur->data);

    gum_debug_session_send (session, 0, message);
  }
}

static GumDebugSession *
gum_debug_session_new (GumDebugServer * server,
                       GIOStream * stream)
{
  GumDebugSession * session;

  session = g_slice_new (GumDebugSession);
  session->server = server;
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

  return session;
}

static void
gum_debug_session_free (GumDebugSession * session)
{
  g_queue_free_full (session->outgoing, (GDestroyNotify) g_bytes_unref);

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
      "V8-Version", "4.3.62",
      "Protocol-Version", "1",
      "Embedding-Host", "Frida v4.0.0",
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
    self->buffer = g_realloc (self->buffer, self->capacity);

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
    gum_debug_server_remove_session (self->server, self);
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
      (gsize) strlen (content), content);

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
      gchar * message;

      message = g_strndup (self->buffer + self->header_length,
          self->message_length - self->header_length);
      gum_script_post_debug_message (message);
      g_free (message);

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
    gum_debug_server_remove_session (self->server, self);
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

  g_bytes_unref (g_queue_pop_head (self->outgoing));

  message = g_queue_peek_head (self->outgoing);
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

