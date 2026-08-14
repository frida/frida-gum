#include "gumpharo.h"

#include <gio/gio.h>
#include <pharovm/memoryImage.h>
#include <pharovm/parameters/parameters.h>
#include <pharovm/parameters/parameterVector.h>
#include <pharovm/pharoClient.h>
#include <string.h>

extern const guint8 gum_pharo_image_data[];
extern const gsize gum_pharo_image_size;

static const gchar * gum_pharo_startup_arguments[] =
    { "eval", "GumScript start. (Delay forSeconds: 86400) wait" };

static gpointer gum_pharo_run_interpreter (gpointer data);
static GBytes * gum_pharo_unpack_image (void);

static GThread * gum_pharo_thread;
static GMutex gum_pharo_mutex;
static GCond gum_pharo_cond;
static gboolean gum_pharo_ready;

void
gum_pharo_runtime_evaluate (const gchar * source)
{
  gchar * message, * escaped;

  gum_pharo_runtime_ensure_started ();

  escaped = g_strescape (source, NULL);
  message = g_strdup_printf ("{\"type\":\"gum:eval\",\"source\":\"%s\"}",
      escaped);

  gum_pharo_post (message, NULL);

  g_free (message);
  g_free (escaped);
}

void
gum_pharo_runtime_ensure_started (void)
{
  g_mutex_lock (&gum_pharo_mutex);

  if (gum_pharo_thread == NULL)
  {
    gum_pharo_thread = g_thread_new ("gum-pharo",
        gum_pharo_run_interpreter, NULL);

    while (!gum_pharo_ready)
      g_cond_wait (&gum_pharo_cond, &gum_pharo_mutex);
  }

  g_mutex_unlock (&gum_pharo_mutex);
}

static gpointer
gum_pharo_run_interpreter (gpointer data)
{
  GBytes * image;
  gconstpointer contents;
  gsize size;
  VMParameters parameters = { 0, };

  image = gum_pharo_unpack_image ();
  contents = g_bytes_get_data (image, &size);
  useImageInMemory (contents, size);

  vm_parameters_init (&parameters);
  parameters.imageFileName = g_strdup ("gum-pharo.image");
  parameters.isDefaultImage = FALSE;
  parameters.isInteractiveSession = FALSE;
  vm_parameter_vector_insert_from (&parameters.imageParameters, 2,
      gum_pharo_startup_arguments);

  g_mutex_lock (&gum_pharo_mutex);
  gum_pharo_ready = TRUE;
  g_cond_signal (&gum_pharo_cond);
  g_mutex_unlock (&gum_pharo_mutex);

  if (vm_init (&parameters))
    vm_run_interpreter ();

  g_bytes_unref (image);

  return NULL;
}

static GBytes *
gum_pharo_unpack_image (void)
{
  GBytes * packed, * unpacked;
  GConverter * decompressor;
  GInputStream * source, * unpacking;
  GOutputStream * sink;

  packed = g_bytes_new_static (gum_pharo_image_data, gum_pharo_image_size);
  decompressor =
      G_CONVERTER (g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP));

  source = g_memory_input_stream_new_from_bytes (packed);
  unpacking = g_converter_input_stream_new (source, decompressor);
  sink = g_memory_output_stream_new_resizable ();

  g_output_stream_splice (sink, unpacking, G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
      NULL, NULL);
  unpacked = g_memory_output_stream_steal_as_bytes (
      G_MEMORY_OUTPUT_STREAM (sink));

  g_object_unref (sink);
  g_object_unref (unpacking);
  g_object_unref (source);
  g_object_unref (decompressor);
  g_bytes_unref (packed);

  return unpacked;
}
