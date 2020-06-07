/*
 * Copyright (C) 2017-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

struct _GumDefaultStalkerTransformer
{
  GObject parent;
};

struct _GumCallbackStalkerTransformer
{
  GObject parent;

  GumStalkerTransformerCallback callback;
  gpointer data;
  GDestroyNotify data_destroy;
};

static void gum_default_stalker_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer, GumStalkerIterator * iterator,
    GumStalkerOutput * output);

static void gum_callback_stalker_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_callback_stalker_transformer_finalize (GObject * object);
static void gum_callback_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer, GumStalkerIterator * iterator,
    GumStalkerOutput * output);

G_DEFINE_INTERFACE (GumStalkerTransformer, gum_stalker_transformer,
    G_TYPE_OBJECT)

G_DEFINE_TYPE_EXTENDED (GumDefaultStalkerTransformer,
                        gum_default_stalker_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_default_stalker_transformer_iface_init))

G_DEFINE_TYPE_EXTENDED (GumCallbackStalkerTransformer,
                        gum_callback_stalker_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_callback_stalker_transformer_iface_init))

static void
gum_stalker_transformer_default_init (GumStalkerTransformerInterface * iface)
{
}

GumStalkerTransformer *
gum_stalker_transformer_make_default (void)
{
  return g_object_new (GUM_TYPE_DEFAULT_STALKER_TRANSFORMER, NULL);
}

GumStalkerTransformer *
gum_stalker_transformer_make_from_callback (
    GumStalkerTransformerCallback callback,
    gpointer data,
    GDestroyNotify data_destroy)
{
  GumCallbackStalkerTransformer * transformer;

  transformer = g_object_new (GUM_TYPE_CALLBACK_STALKER_TRANSFORMER, NULL);
  transformer->callback = callback;
  transformer->data = data;
  transformer->data_destroy = data_destroy;

  return GUM_STALKER_TRANSFORMER (transformer);
}

void
gum_stalker_transformer_transform_block (GumStalkerTransformer * self,
                                         GumStalkerIterator * iterator,
                                         GumStalkerOutput * output)
{
  GumStalkerTransformerInterface * iface =
      GUM_STALKER_TRANSFORMER_GET_IFACE (self);

  g_assert (iface->transform_block != NULL);

  iface->transform_block (self, iterator, output);
}

static void
gum_default_stalker_transformer_class_init (
    GumDefaultStalkerTransformerClass * klass)
{
}

static void
gum_default_stalker_transformer_iface_init (gpointer g_iface,
                                            gpointer iface_data)
{
  GumStalkerTransformerInterface * iface =
      (GumStalkerTransformerInterface *) g_iface;

  iface->transform_block = gum_default_stalker_transformer_transform_block;
}

static void
gum_default_stalker_transformer_init (GumDefaultStalkerTransformer * self)
{
}

static void
gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  while (gum_stalker_iterator_next (iterator, NULL))
  {
    gum_stalker_iterator_keep (iterator);
  }
}

static void
gum_callback_stalker_transformer_class_init (
    GumCallbackStalkerTransformerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_callback_stalker_transformer_finalize;
}

static void
gum_callback_stalker_transformer_iface_init (gpointer g_iface,
                                             gpointer iface_data)
{
  GumStalkerTransformerInterface * iface =
      (GumStalkerTransformerInterface *) g_iface;

  iface->transform_block = gum_callback_stalker_transformer_transform_block;
}

static void
gum_callback_stalker_transformer_init (GumCallbackStalkerTransformer * self)
{
}

static void
gum_callback_stalker_transformer_finalize (GObject * object)
{
  GumCallbackStalkerTransformer * self =
      GUM_CALLBACK_STALKER_TRANSFORMER (object);

  if (self->data_destroy != NULL)
    self->data_destroy (self->data);

  G_OBJECT_CLASS (gum_callback_stalker_transformer_parent_class)->finalize (
      object);
}

static void
gum_callback_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  GumCallbackStalkerTransformer * self =
      (GumCallbackStalkerTransformer *) transformer;

  self->callback (iterator, output, self->data);
}
