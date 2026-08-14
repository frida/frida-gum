#include "gumpharo.h"

#include <string.h>

typedef struct _GumPharoMessage GumPharoMessage;

struct _GumPharoMessage
{
  gchar * payload;
  GBytes * data;
};

static GumPharoMessage * gum_pharo_message_new (const gchar * payload,
    GBytes * data);
static void gum_pharo_message_free (GumPharoMessage * message);

static GumPharoMessageHandler gum_pharo_handler;
static gpointer gum_pharo_handler_data;
static GAsyncQueue * gum_pharo_incoming;
static sqInt gum_pharo_semaphore_index = -1;

void
gum_pharo_set_message_handler (GumPharoMessageHandler handler,
                               gpointer user_data)
{
  gum_pharo_handler = handler;
  gum_pharo_handler_data = user_data;
}

void
gum_pharo_post (const gchar * payload,
                GBytes * data)
{
  if (gum_pharo_incoming == NULL)
  {
    gum_pharo_incoming =
        g_async_queue_new_full ((GDestroyNotify) gum_pharo_message_free);
  }

  g_async_queue_push (gum_pharo_incoming,
      gum_pharo_message_new (payload, data));

  if (gum_pharo_semaphore_index != -1)
    gum_pharo_signal_semaphore (gum_pharo_semaphore_index);
}

sqInt
prim_gum_pharo_post (void)
{
  gsize payload_size, data_size;
  const gchar * payload;
  gconstpointer data;
  gchar * payload_utf8;
  GBytes * bytes;

  payload = gum_pharo_bytes_at (1, &payload_size);
  data = gum_pharo_bytes_at (0, &data_size);

  if (gum_pharo_handler == NULL)
    return gum_pharo_return_self ();

  payload_utf8 = g_strndup (payload, payload_size);
  bytes = (data != NULL) ? g_bytes_new (data, data_size) : NULL;

  gum_pharo_handler (payload_utf8, bytes, gum_pharo_handler_data);

  g_free (payload_utf8);
  if (bytes != NULL)
    g_bytes_unref (bytes);

  return gum_pharo_return_self ();
}

sqInt
prim_gum_pharo_take_message (void)
{
  GumPharoMessage * message;

  message = (gum_pharo_incoming != NULL)
      ? g_async_queue_try_pop (gum_pharo_incoming)
      : NULL;

  return gum_pharo_return_pointer (message);
}

sqInt
prim_gum_pharo_message_payload (void)
{
  GumPharoMessage * message;

  message = gum_pharo_pointer_at (0);

  return gum_pharo_return_string (message->payload,
      strlen (message->payload));
}

sqInt
prim_gum_pharo_message_data (void)
{
  GumPharoMessage * message;
  gconstpointer data;
  gsize size;

  message = gum_pharo_pointer_at (0);
  if (message->data == NULL)
    return gum_pharo_return_nil ();

  data = g_bytes_get_data (message->data, &size);

  return gum_pharo_return_byte_array (data, size);
}

sqInt
prim_gum_pharo_release_message (void)
{
  gum_pharo_message_free (gum_pharo_pointer_at (0));

  return gum_pharo_return_self ();
}

sqInt
prim_gum_pharo_set_message_semaphore (void)
{
  gum_pharo_semaphore_index = gum_pharo_integer_at (0);

  return gum_pharo_return_self ();
}

static GumPharoMessage *
gum_pharo_message_new (const gchar * payload,
                       GBytes * data)
{
  GumPharoMessage * message;

  message = g_slice_new (GumPharoMessage);
  message->payload = g_strdup (payload);
  message->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  return message;
}

static void
gum_pharo_message_free (GumPharoMessage * message)
{
  g_free (message->payload);
  if (message->data != NULL)
    g_bytes_unref (message->data);

  g_slice_free (GumPharoMessage, message);
}
