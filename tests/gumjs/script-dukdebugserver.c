/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <gio/gio.h>
#include <string.h>

#define GUM_DUK_DEBUG_BUFFER_SIZE 512

#define GUM_DUK_DEBUG_SERVER(obj) ((GumDukDebugServer *) (obj))
#define GUM_DUK_TYPE_DEBUG_CHANNEL (gum_duk_debug_channel_get_type ())
#define GUM_DUK_DEBUG_SESSION(obj) ((GumDukDebugSession *) (obj))

typedef struct _GumDukDebugServer  GumDukDebugServer;
G_DECLARE_FINAL_TYPE (GumDukDebugChannel, gum_duk_debug_channel, GUM_DUK,
    DEBUG_CHANNEL, GObject)
typedef struct _GumDukDebugSession GumDukDebugSession;

struct _GumDukDebugServer
{
  GumScriptBackend * backend;
  GSocketService * service;
  guint16 base_port;
  GHashTable * channels;
};

struct _GumDukDebugChannel
{
  GObject parent;

  guint id;
  gchar * name;
  GSList * sessions;
  gboolean attached;

  GumDukDebugServer * server;
};

struct _GumDukDebugSession
{
  GIOStream * stream;
  GInputStream * input;
  GOutputStream * output;

  GQueue * outgoing;

  GCancellable * cancellable;

  GumDukDebugChannel * channel;
};

static gboolean gum_duk_debug_server_on_incoming_connection (
    GSocketService * service, GSocketConnection * connection,
    GumDukDebugChannel * channel, gpointer user_data);
static void gum_duk_debug_server_on_message (const gchar * message,
    GumDukDebugServer * self);

static void gum_duk_debug_channel_finalize (GObject * object);
static void gum_duk_debug_channel_add_session (GumDukDebugChannel * self,
    GSocketConnection * connection);
static void gum_duk_debug_channel_remove_all_sessions (
    GumDukDebugChannel * self);
static void gum_duk_debug_channel_broadcast (GumDukDebugChannel * self,
    GBytes * bytes);
static void gum_duk_debug_channel_attach (GumDukDebugChannel * self);
static void gum_duk_debug_channel_detach (GumDukDebugChannel * self);

static GumDukDebugSession * gum_duk_debug_session_new (
    GumDukDebugChannel * channel, GIOStream * stream);
static void gum_duk_debug_session_free (GumDukDebugSession * self);
static void gum_duk_debug_session_weak_notify (GumDukDebugSession * self,
    GObject * where_the_object_was);
static void gum_duk_debug_session_open (GumDukDebugSession * self);
static void gum_duk_debug_session_read_next_chunk (GumDukDebugSession * self);
static void gum_duk_debug_session_send (GumDukDebugSession * self,
    GBytes * bytes);

static void gum_duk_debug_session_on_read_ready (GObject * source_object,
    GAsyncResult * res, GumDukDebugSession * self);
static void gum_duk_debug_session_on_write_all_ready (GObject * source_object,
    GAsyncResult * res, GumDukDebugSession * self);

G_DEFINE_TYPE (GumDukDebugChannel, gum_duk_debug_channel, G_TYPE_OBJECT)

GumDukDebugServer *
gum_duk_debug_server_new (GumScriptBackend * backend,
                          guint16 base_port)
{
  GumDukDebugServer * server;
  GSocketService * service;

  server = g_slice_new (GumDukDebugServer);
  server->backend = backend;

  service = g_socket_service_new ();
  g_signal_connect (service, "incoming",
      G_CALLBACK (gum_duk_debug_server_on_incoming_connection), server);
  server->service = service;
  server->base_port = base_port;

  server->channels = g_hash_table_new_full (NULL, NULL, NULL, g_object_unref);

  g_socket_service_start (service);

  gum_script_backend_set_debug_message_handler (backend,
      (GumScriptBackendDebugMessageHandler) gum_duk_debug_server_on_message,
      server, NULL);

  return server;
}

void
gum_duk_debug_server_free (GumDukDebugServer * self)
{
  gum_script_backend_set_debug_message_handler (self->backend, NULL, NULL,
      NULL);

  g_hash_table_unref (self->channels);

  g_socket_service_stop (self->service);
  g_object_unref (self->service);

  g_slice_free (GumDukDebugServer, self);
}

static gboolean
gum_duk_debug_server_on_incoming_connection (GSocketService * service,
                                             GSocketConnection * connection,
                                             GumDukDebugChannel * channel,
                                             gpointer user_data)
{
  g_print ("NEW CONNECTION FOR %s\n", channel->name);

  gum_duk_debug_channel_add_session (channel, connection);

  return TRUE;
}

static void
gum_duk_debug_server_on_message (const gchar * message,
                                 GumDukDebugServer * self)
{
  g_print ("<<< %s\n", message);

  if (g_str_has_prefix (message, "EMIT "))
  {
    guint id;
    gchar * end;
    GumDukDebugChannel * channel;
    guchar * data;
    gsize size;
    GBytes * bytes;

    id = (guint) g_ascii_strtoull (message + 5, &end, 10);
    g_assert (end != message + 5);

    channel = g_hash_table_lookup (self->channels, GSIZE_TO_POINTER (id));
    if (channel == NULL)
      return;

    data = g_base64_decode (end + 1, &size);
    bytes = g_bytes_new_take (data, size);

    gum_duk_debug_channel_broadcast (channel, bytes);

    g_bytes_unref (bytes);
  }
  else if (g_str_has_prefix (message, "SYNC\n"))
  {
    guint script_index;
    gchar ** tokens, ** token;

    script_index = 0;
    tokens = g_strsplit (message + 5, "\n", -1);
    for (token = tokens; *token != NULL; token++)
    {
      gchar * line = *token;
      GumDukDebugChannel * channel;
      gchar * end;
      gboolean port_available;

      channel = g_object_new (GUM_DUK_TYPE_DEBUG_CHANNEL, NULL);

      channel->id = (guint) g_ascii_strtoull (line, &end, 10);
      g_assert (end != line);
      channel->name = g_strdup (end + 1);

      channel->server = self;

      g_hash_table_insert (self->channels, GSIZE_TO_POINTER (channel->id),
          channel);

      port_available = g_socket_listener_add_inet_port (
          G_SOCKET_LISTENER (self->service), self->base_port + script_index,
          G_OBJECT (channel), NULL);
      g_assert (port_available);

      script_index++;
    }

    g_strfreev (tokens);
  }
  else if (g_str_has_prefix (message, "ADD "))
  {
    /* TODO: once our test exposes this */
  }
  else if (g_str_has_prefix (message, "REMOVE "))
  {
    /* TODO: once our test exposes this */
  }
  else if (g_str_has_prefix (message, "DETACH "))
  {
    guint id;
    gchar * end;
    GumDukDebugChannel * channel;

    id = (guint) g_ascii_strtoull (message + 7, &end, 10);
    g_assert (end != message + 7);

    channel = g_hash_table_lookup (self->channels, GSIZE_TO_POINTER (id));
    if (channel == NULL)
      return;

    channel->attached = FALSE;

    gum_duk_debug_channel_remove_all_sessions (channel);
  }
  else
  {
    g_assert_not_reached ();
  }
}

static void
gum_duk_debug_channel_class_init (GumDukDebugChannelClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_duk_debug_channel_finalize;
}

static void
gum_duk_debug_channel_init (GumDukDebugChannel * self)
{
  self->attached = FALSE;
}

static void
gum_duk_debug_channel_finalize (GObject * object)
{
  GumDukDebugChannel * self = GUM_DUK_DEBUG_CHANNEL (object);

  g_free (self->name);

  G_OBJECT_CLASS (gum_duk_debug_channel_parent_class)->finalize (object);
}

static void
gum_duk_debug_channel_add_session (GumDukDebugChannel * self,
                                   GSocketConnection * connection)
{
  gboolean is_first_session;
  GumDukDebugSession * session;

  is_first_session = self->sessions == NULL;

  session = gum_duk_debug_session_new (self, G_IO_STREAM (connection));
  self->sessions = g_slist_prepend (self->sessions, session);

  gum_duk_debug_session_open (session);

  if (is_first_session)
    gum_duk_debug_channel_attach (self);
}

static void
gum_duk_debug_channel_remove_all_sessions (GumDukDebugChannel * self)
{
  if (self->sessions == NULL)
    return;

  gum_duk_debug_channel_detach (self);

  g_slist_free_full (self->sessions,
      (GDestroyNotify) gum_duk_debug_session_free);
  self->sessions = NULL;
}

static void
gum_duk_debug_channel_remove_session (GumDukDebugChannel * self,
                                      GumDukDebugSession * session)
{
  gboolean is_last_session;

  self->sessions = g_slist_remove (self->sessions, session);

  is_last_session = self->sessions == NULL;

  if (is_last_session)
    gum_duk_debug_channel_detach (self);

  gum_duk_debug_session_free (session);
}

static void
gum_duk_debug_channel_broadcast (GumDukDebugChannel * self,
                                 GBytes * bytes)
{
  g_slist_foreach (self->sessions, (GFunc) gum_duk_debug_session_send, bytes);
}

static void
gum_duk_debug_channel_post (GumDukDebugChannel * self,
                            GBytes * bytes)
{
  gconstpointer data;
  gsize size;
  gchar * bytes_encoded;
  gchar * message;

  data = g_bytes_get_data (bytes, &size);
  bytes_encoded = g_base64_encode (data, size);
  message = g_strdup_printf ("POST %u %s", self->id, bytes_encoded);

  g_print (">>> %s\n", message);

  gum_script_backend_post_debug_message (self->server->backend, message);

  g_free (message);
  g_free (bytes_encoded);
}

static void
gum_duk_debug_channel_attach (GumDukDebugChannel * self)
{
  gchar * message;

  if (self->attached)
    return;
  self->attached = TRUE;

  message = g_strdup_printf ("ATTACH %u", self->id);

  g_print (">>> %s\n", message);

  gum_script_backend_post_debug_message (self->server->backend, message);

  g_free (message);
}

static void
gum_duk_debug_channel_detach (GumDukDebugChannel * self)
{
  gchar * message;

  if (!self->attached)
    return;
  self->attached = FALSE;

  message = g_strdup_printf ("DETACH %u", self->id);

  g_print (">>> %s\n", message);

  gum_script_backend_post_debug_message (self->server->backend, message);

  g_free (message);
}

static GumDukDebugSession *
gum_duk_debug_session_new (GumDukDebugChannel * channel,
                           GIOStream * stream)
{
  GumDukDebugSession * session;

  session = g_slice_new (GumDukDebugSession);

  session->stream = g_object_ref (stream);
  session->input = g_io_stream_get_input_stream (stream);
  session->output = g_io_stream_get_output_stream (stream);

  session->outgoing = g_queue_new ();

  session->cancellable = g_cancellable_new ();

  session->channel = g_object_ref (channel);

  return session;
}

static void
gum_duk_debug_session_free (GumDukDebugSession * self)
{
  GCancellable * cancellable;

  cancellable = self->cancellable;
  self->cancellable = NULL;

  g_cancellable_cancel (cancellable);
  g_object_weak_ref (G_OBJECT (cancellable),
      (GWeakNotify) gum_duk_debug_session_weak_notify, self);
  g_object_unref (cancellable);
}

static void
gum_duk_debug_session_weak_notify (GumDukDebugSession * self,
                                   GObject * where_the_object_was)
{
  g_object_unref (self->channel);

  g_queue_free_full (self->outgoing, (GDestroyNotify) g_bytes_unref);

  g_io_stream_close_async (self->stream, G_PRIORITY_LOW, NULL, NULL, NULL);
  g_object_unref (self->stream);

  g_slice_free (GumDukDebugSession, self);
}

static void
gum_duk_debug_session_open (GumDukDebugSession * self)
{
  gum_duk_debug_session_read_next_chunk (self);
}

static void
gum_duk_debug_session_read_next_chunk (GumDukDebugSession * self)
{
  g_input_stream_read_bytes_async (self->input,
      GUM_DUK_DEBUG_BUFFER_SIZE,
      G_PRIORITY_DEFAULT,
      self->cancellable,
      (GAsyncReadyCallback) gum_duk_debug_session_on_read_ready,
      self);
}

static void
gum_duk_debug_session_send (GumDukDebugSession * self,
                            GBytes * bytes)
{
  gboolean write_now;

  write_now = g_queue_is_empty (self->outgoing);

  g_queue_push_tail (self->outgoing, g_bytes_ref (bytes));

  if (write_now)
  {
    g_output_stream_write_all_async (self->output,
        g_bytes_get_data (bytes, NULL),
        g_bytes_get_size (bytes),
        G_PRIORITY_DEFAULT,
        self->cancellable,
        (GAsyncReadyCallback) gum_duk_debug_session_on_write_all_ready,
        self);
  }
}

static void
gum_duk_debug_session_on_read_ready (GObject * source_object,
                                     GAsyncResult * res,
                                     GumDukDebugSession * self)
{
  GBytes * bytes;

  bytes = g_input_stream_read_bytes_finish (self->input, res, NULL);
  if (bytes == NULL || g_bytes_get_size (bytes) == 0)
    goto error_gone;

  gum_duk_debug_channel_post (self->channel, bytes);

  g_bytes_unref (bytes);

  gum_duk_debug_session_read_next_chunk (self);

  return;

error_gone:
  if (self->cancellable != NULL)
    gum_duk_debug_channel_remove_session (self->channel, self);
}

static void
gum_duk_debug_session_on_write_all_ready (GObject * source_object,
                                          GAsyncResult * res,
                                          GumDukDebugSession * self)
{
  GBytes * bytes;

  if (!g_output_stream_write_all_finish (self->output, res, NULL, NULL))
    return; /* read will fail */

  g_bytes_unref (g_queue_pop_head (self->outgoing));

  bytes = g_queue_peek_head (self->outgoing);
  if (bytes != NULL)
  {
    g_output_stream_write_all_async (self->output,
        g_bytes_get_data (bytes, NULL),
        g_bytes_get_size (bytes),
        G_PRIORITY_DEFAULT,
        self->cancellable,
        (GAsyncReadyCallback) gum_duk_debug_session_on_write_all_ready,
        self);
  }
}
