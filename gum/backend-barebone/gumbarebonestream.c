/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumbarebone.h"

#define GUM_TYPE_BAREBONE_INPUT_STREAM (gum_barebone_input_stream_get_type ())
#define GUM_TYPE_BAREBONE_OUTPUT_STREAM (gum_barebone_output_stream_get_type ())

G_DECLARE_FINAL_TYPE (GumBareboneInputStream, gum_barebone_input_stream, GUM,
    BAREBONE_INPUT_STREAM, GInputStream)
G_DECLARE_FINAL_TYPE (GumBareboneOutputStream, gum_barebone_output_stream,
    GUM, BAREBONE_OUTPUT_STREAM, GOutputStream)

typedef struct _GumBareboneHandleSource GumBareboneHandleSource;

struct _GumBareboneInputStream
{
  GInputStream parent;

  gpointer handle;
  gboolean close_handle;
};

struct _GumBareboneOutputStream
{
  GOutputStream parent;

  gpointer handle;
  gboolean close_handle;
};

struct _GumBareboneHandleSource
{
  GSource source;

  GPollFD handle;
};

static void gum_barebone_input_stream_pollable_iface_init (gpointer g_iface,
    gpointer iface_data);
static gssize gum_barebone_input_stream_read (GInputStream * stream,
    void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean gum_barebone_input_stream_close (GInputStream * stream,
    GCancellable * cancellable, GError ** error);
static gboolean gum_barebone_input_stream_is_readable (
    GPollableInputStream * stream);
static GSource * gum_barebone_input_stream_create_source (
    GPollableInputStream * stream, GCancellable * cancellable);

static void gum_barebone_output_stream_pollable_iface_init (gpointer g_iface,
    gpointer iface_data);
static gssize gum_barebone_output_stream_write (GOutputStream * stream,
    const void * buffer, gsize count, GCancellable * cancellable,
    GError ** error);
static gboolean gum_barebone_output_stream_close (GOutputStream * stream,
    GCancellable * cancellable, GError ** error);
static gboolean gum_barebone_output_stream_is_writable (
    GPollableOutputStream * stream);
static GSource * gum_barebone_output_stream_create_source (
    GPollableOutputStream * stream, GCancellable * cancellable);

static gboolean gum_barebone_handle_is_ready (gpointer handle,
    GIOCondition condition);
static GSource * gum_barebone_pollable_source_new (gpointer stream,
    gpointer handle, GIOCondition condition, GCancellable * cancellable);
static gboolean gum_barebone_keep_cancellable_source (
    GCancellable * cancellable, gpointer user_data);
static GSource * gum_barebone_handle_source_new (gpointer handle,
    GIOCondition condition);
static gboolean gum_barebone_handle_source_check (GSource * source);
static gboolean gum_barebone_handle_source_dispatch (GSource * source,
    GSourceFunc callback, gpointer user_data);

G_DEFINE_TYPE_EXTENDED (GumBareboneInputStream,
                        gum_barebone_input_stream,
                        G_TYPE_INPUT_STREAM,
                        0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
                            gum_barebone_input_stream_pollable_iface_init))

G_DEFINE_TYPE_EXTENDED (GumBareboneOutputStream,
                        gum_barebone_output_stream,
                        G_TYPE_OUTPUT_STREAM,
                        0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM,
                            gum_barebone_output_stream_pollable_iface_init))

static GSourceFuncs gum_barebone_handle_source_funcs =
{
  NULL,
  gum_barebone_handle_source_check,
  gum_barebone_handle_source_dispatch,
  NULL,
  NULL,
  NULL
};

GInputStream *
gum_barebone_input_stream_new (gpointer handle,
                               gboolean close_handle)
{
  GumBareboneInputStream * stream;

  stream = g_object_new (GUM_TYPE_BAREBONE_INPUT_STREAM, NULL);
  stream->handle = handle;
  stream->close_handle = close_handle;

  return G_INPUT_STREAM (stream);
}

static void
gum_barebone_input_stream_class_init (GumBareboneInputStreamClass * klass)
{
  GInputStreamClass * stream_class = G_INPUT_STREAM_CLASS (klass);

  stream_class->read_fn = gum_barebone_input_stream_read;
  stream_class->close_fn = gum_barebone_input_stream_close;
}

static void
gum_barebone_input_stream_pollable_iface_init (gpointer g_iface,
                                               gpointer iface_data)
{
  GPollableInputStreamInterface * iface = g_iface;

  iface->is_readable = gum_barebone_input_stream_is_readable;
  iface->create_source = gum_barebone_input_stream_create_source;
}

static void
gum_barebone_input_stream_init (GumBareboneInputStream * self)
{
}

static gssize
gum_barebone_input_stream_read (GInputStream * stream,
                                void * buffer,
                                gsize count,
                                GCancellable * cancellable,
                                GError ** error)
{
  GumBareboneInputStream * self = GUM_BAREBONE_INPUT_STREAM (stream);

  return gum_barebone_query_stream_ops ()->read (self->handle, buffer, count,
      error);
}

static gboolean
gum_barebone_input_stream_close (GInputStream * stream,
                                 GCancellable * cancellable,
                                 GError ** error)
{
  GumBareboneInputStream * self = GUM_BAREBONE_INPUT_STREAM (stream);

  if (!self->close_handle)
    return TRUE;

  return gum_barebone_query_stream_ops ()->close (self->handle, error);
}

static gboolean
gum_barebone_input_stream_is_readable (GPollableInputStream * stream)
{
  GumBareboneInputStream * self = GUM_BAREBONE_INPUT_STREAM (stream);

  return gum_barebone_handle_is_ready (self->handle, G_IO_IN);
}

static GSource *
gum_barebone_input_stream_create_source (GPollableInputStream * stream,
                                         GCancellable * cancellable)
{
  GumBareboneInputStream * self = GUM_BAREBONE_INPUT_STREAM (stream);

  return gum_barebone_pollable_source_new (stream, self->handle, G_IO_IN,
      cancellable);
}

GOutputStream *
gum_barebone_output_stream_new (gpointer handle,
                                gboolean close_handle)
{
  GumBareboneOutputStream * stream;

  stream = g_object_new (GUM_TYPE_BAREBONE_OUTPUT_STREAM, NULL);
  stream->handle = handle;
  stream->close_handle = close_handle;

  return G_OUTPUT_STREAM (stream);
}

static void
gum_barebone_output_stream_class_init (GumBareboneOutputStreamClass * klass)
{
  GOutputStreamClass * stream_class = G_OUTPUT_STREAM_CLASS (klass);

  stream_class->write_fn = gum_barebone_output_stream_write;
  stream_class->close_fn = gum_barebone_output_stream_close;
}

static void
gum_barebone_output_stream_pollable_iface_init (gpointer g_iface,
                                                gpointer iface_data)
{
  GPollableOutputStreamInterface * iface = g_iface;

  iface->is_writable = gum_barebone_output_stream_is_writable;
  iface->create_source = gum_barebone_output_stream_create_source;
}

static void
gum_barebone_output_stream_init (GumBareboneOutputStream * self)
{
}

static gssize
gum_barebone_output_stream_write (GOutputStream * stream,
                                  const void * buffer,
                                  gsize count,
                                  GCancellable * cancellable,
                                  GError ** error)
{
  GumBareboneOutputStream * self = GUM_BAREBONE_OUTPUT_STREAM (stream);

  return gum_barebone_query_stream_ops ()->write (self->handle, buffer, count,
      error);
}

static gboolean
gum_barebone_output_stream_close (GOutputStream * stream,
                                  GCancellable * cancellable,
                                  GError ** error)
{
  GumBareboneOutputStream * self = GUM_BAREBONE_OUTPUT_STREAM (stream);

  if (!self->close_handle)
    return TRUE;

  return gum_barebone_query_stream_ops ()->close (self->handle, error);
}

static gboolean
gum_barebone_output_stream_is_writable (GPollableOutputStream * stream)
{
  GumBareboneOutputStream * self = GUM_BAREBONE_OUTPUT_STREAM (stream);

  return gum_barebone_handle_is_ready (self->handle, G_IO_OUT);
}

static GSource *
gum_barebone_output_stream_create_source (GPollableOutputStream * stream,
                                          GCancellable * cancellable)
{
  GumBareboneOutputStream * self = GUM_BAREBONE_OUTPUT_STREAM (stream);

  return gum_barebone_pollable_source_new (stream, self->handle, G_IO_OUT,
      cancellable);
}

static gboolean
gum_barebone_handle_is_ready (gpointer handle,
                              GIOCondition condition)
{
  GPollFD fd = { .fd = GPOINTER_TO_INT (handle), .events = condition, };

  gum_barebone_query_stream_ops ()->poll (&fd, 1, 0);

  return fd.revents != 0;
}

static GSource *
gum_barebone_pollable_source_new (gpointer stream,
                                  gpointer handle,
                                  GIOCondition condition,
                                  GCancellable * cancellable)
{
  GSource * source, * handle_source, * cancellable_source;

  source = g_pollable_source_new (stream);

  handle_source = gum_barebone_handle_source_new (handle, condition);
  g_source_add_child_source (source, handle_source);
  g_source_unref (handle_source);

  if (cancellable != NULL)
  {
    cancellable_source = g_cancellable_source_new (cancellable);
    g_source_set_callback (cancellable_source,
        G_SOURCE_FUNC (gum_barebone_keep_cancellable_source), NULL, NULL);
    g_source_add_child_source (source, cancellable_source);
    g_source_unref (cancellable_source);
  }

  return source;
}

static gboolean
gum_barebone_keep_cancellable_source (GCancellable * cancellable,
                                      gpointer user_data)
{
  return G_SOURCE_CONTINUE;
}

static GSource *
gum_barebone_handle_source_new (gpointer handle,
                                GIOCondition condition)
{
  GSource * source;
  GumBareboneHandleSource * self;

  source = g_source_new (&gum_barebone_handle_source_funcs,
      sizeof (GumBareboneHandleSource));
  self = (GumBareboneHandleSource *) source;

  self->handle.fd = GPOINTER_TO_INT (handle);
  self->handle.events = condition;
  g_source_add_poll (source, &self->handle);

  return source;
}

static gboolean
gum_barebone_handle_source_check (GSource * source)
{
  GumBareboneHandleSource * self = (GumBareboneHandleSource *) source;

  return self->handle.revents != 0;
}

static gboolean
gum_barebone_handle_source_dispatch (GSource * source,
                                     GSourceFunc callback,
                                     gpointer user_data)
{
  return G_SOURCE_CONTINUE;
}

G_GNUC_WEAK const GumBareboneStreamOps *
gum_barebone_query_stream_ops (void)
{
  return NULL;
}
