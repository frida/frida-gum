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

struct _GumStalkerCoverageEntry {
  guint32 start;
  guint16 size;
  guint16 mod_id;
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
static void gum_stalker_coverage_clear_module (gpointer data);
static void gum_stalker_coverage_emit_header (GumStalkerCoverage * self,
    void * sink);
static gboolean gum_stakler_coverage_collect_modules (
    const GumModuleDetails * details, gpointer user_data);

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

void
gum_stalker_coverage_init (GumStalkerCoverage * coverage)
{
  coverage->modules = g_array_new (FALSE, FALSE, sizeof (GumModuleDetails));
  g_array_set_clear_func (coverage->modules, gum_stalker_coverage_clear_module);
}

static void
gum_stalker_coverage_clear_module (gpointer data)
{
  GumModuleDetails * details = (GumModuleDetails *) data;
  g_free ((gpointer) details->name);
  g_free ((gpointer) details->range);
  g_free ((gpointer) details->path);
}

void
gum_stalker_coverage_finalize (GumStalkerCoverage * coverage)
{
  g_array_free (coverage->modules, TRUE);
}


void
gum_stalker_coverage_emit_events (GumStalkerCoverage * self,
                                  void * sink,
                                  GumEvent * events,
                                  guint num_events)
{
  guint i, j;
  GumCompileEvent * event;
  GumModuleDetails * details;
  GumStalkerCoverageEntry entry;

  if (self->modules->len == 0)
  {
    gum_stalker_coverage_emit_header (self, sink);
  }

  for (i = 0; i < num_events; i++)
  {
    if (events[i].type != GUM_COMPILE)
      continue;

    event = (GumCompileEvent *) &events[i];

    for (j = 0; j < self->modules->len; j++)
    {
      details = &g_array_index (self->modules, GumModuleDetails, j);

      if (GUM_ADDRESS (event->begin) < details->range->base_address)
        continue;

      if (GUM_ADDRESS(event->end) > details->range->base_address +
          details->range->size)
      {
        continue;
      }

      entry.start = GUINT32_TO_LE (GPOINTER_TO_SIZE (event->begin -
          details->range->base_address));
      entry.size = GUINT16_TO_LE (event->end - event->begin);
      entry.mod_id = GUINT16_TO_LE (j);

      self->emit (sink, &entry, sizeof (GumStalkerCoverageEntry));

      break;
    }
  }
}

static void
gum_stalker_coverage_emit_header (GumStalkerCoverage * self,
                                  void * sink)
{
  char hdr[] = "DRCOV VERSION: 2\n";
  char flavour[] = "DRCOV FLAVOR: frida\n";
  char module_hdr[128] = {0};
  char columns[] = "Columns: id, base, end, entry, checksum, timestamp, path\n";
  char entry_hdr[128] = {0};
  int len;
  guint idx;
  char module_entry[128 + PATH_MAX] = {0};
  GumModuleDetails * details;

  gum_process_enumerate_modules (gum_stakler_coverage_collect_modules, self);

  self->emit (sink, hdr, sizeof(hdr) - 1);
  self->emit (sink, flavour, sizeof(flavour) - 1);

  len = snprintf(module_hdr, sizeof(module_hdr) - 1,
      "Module Table: version 2, count %d\n", self->modules->len);
  self->emit (sink, module_hdr, len);

  self->emit (sink, columns, sizeof(columns) - 1);

  for (idx = 0; idx < self->modules->len; idx++)
  {
    details = &g_array_index (self->modules, GumModuleDetails, idx);

    len = snprintf (module_entry, sizeof (module_entry) - 1,
        "%3d, %#016lx, %#016lx, %#016x, %#08x, %#08x, %s\n",
        idx, GPOINTER_TO_SIZE (details->range->base_address),
        details->range->base_address + details->range->size,
        0, 0, 0, details->path);
    self->emit (sink, module_entry, len);
  }

  len = snprintf (entry_hdr, sizeof (entry_hdr) - 1, "BB Table: %d bbs\n",
      -1);
  self->emit (sink, entry_hdr, len);
}

static gboolean
gum_stakler_coverage_collect_modules (const GumModuleDetails * details,
                                      gpointer user_data)
{
  GumStalkerCoverage * self = (GumStalkerCoverage *) user_data;
  GumModuleDetails copy;
  copy.name = g_strdup (details->name);
  copy.range = g_memdup (details->range, sizeof (GumMemoryRange));
  copy.path = g_strdup (details->path);
  g_array_append_val (self->modules, copy);
  return TRUE;
}
