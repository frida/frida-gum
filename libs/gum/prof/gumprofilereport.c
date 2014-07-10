/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprofilereport.h"
#include <string.h>

G_DEFINE_TYPE (GumProfileReport, gum_profile_report, G_TYPE_OBJECT);

struct _GumProfileReportPrivate
{
  GHashTable * thread_id_to_node_list;
  GPtrArray * thread_root_nodes;
};

static void gum_profile_report_finalize (GObject * object);

static void gum_profile_report_node_free (GumProfileReportNode * node);

static void append_node_to_xml_string (GumProfileReportNode * node,
    GString * xml);
static gint root_node_compare_func (gconstpointer a, gconstpointer b);
static gint thread_compare_func (gconstpointer a, gconstpointer b);

static void
gum_profile_report_class_init (GumProfileReportClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumProfileReportPrivate));

  object_class->finalize = gum_profile_report_finalize;
}

static void
gum_profile_report_init (GumProfileReport * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_PROFILE_REPORT,
      GumProfileReportPrivate);

  self->priv->thread_id_to_node_list = g_hash_table_new (g_direct_hash,
      g_direct_equal);
  self->priv->thread_root_nodes = g_ptr_array_new ();
}

static void
gum_profile_report_finalize (GObject * object)
{
  GumProfileReport * self = GUM_PROFILE_REPORT (object);
  GumProfileReportPrivate * priv = self->priv;
  guint thread_idx;

  g_hash_table_unref (priv->thread_id_to_node_list);

  for (thread_idx = 0; thread_idx < priv->thread_root_nodes->len; thread_idx++)
  {
    GPtrArray * root_nodes;
    guint node_idx;

    root_nodes = (GPtrArray *)
        g_ptr_array_index (priv->thread_root_nodes, thread_idx);

    for (node_idx = 0; node_idx < root_nodes->len; node_idx++)
    {
      GumProfileReportNode * root_node = (GumProfileReportNode *)
          g_ptr_array_index (root_nodes, node_idx);
      gum_profile_report_node_free (root_node);
    }

    g_ptr_array_free (root_nodes, TRUE);
  }

  g_ptr_array_free (priv->thread_root_nodes, TRUE);

  G_OBJECT_CLASS (gum_profile_report_parent_class)->finalize (object);
}

GumProfileReport *
gum_profile_report_new (void)
{
  return GUM_PROFILE_REPORT (g_object_new (GUM_TYPE_PROFILE_REPORT, NULL));
}

gchar *
gum_profile_report_emit_xml (GumProfileReport * self)
{
  GumProfileReportPrivate * priv = self->priv;
  GString * xml;
  guint thread_idx;

  xml = g_string_new ("<ProfileReport>");

  for (thread_idx = 0; thread_idx < priv->thread_root_nodes->len; thread_idx++)
  {
    GPtrArray * root_nodes;
    guint node_idx;

    root_nodes = (GPtrArray *)
        g_ptr_array_index (priv->thread_root_nodes, thread_idx);

    g_string_append (xml, "<Thread>");

    for (node_idx = 0; node_idx < root_nodes->len; node_idx++)
    {
      append_node_to_xml_string ((GumProfileReportNode *)
          g_ptr_array_index (root_nodes, node_idx), xml);
    }

    g_string_append (xml, "</Thread>");
  }

  g_string_append (xml, "</ProfileReport>");

  return g_string_free (xml, FALSE);
}

GPtrArray *
gum_profile_report_get_root_nodes_for_thread (GumProfileReport * self,
                                              guint thread_index)
{
  g_assert (thread_index < self->priv->thread_root_nodes->len);

  return (GPtrArray *)
      g_ptr_array_index (self->priv->thread_root_nodes, thread_index);
}

void
_gum_profile_report_append_thread_root_node (GumProfileReport * self,
                                             guint thread_id,
                                             GumProfileReportNode * root_node)
{
  GumProfileReportPrivate * priv = self->priv;
  GPtrArray * nodes;

  nodes = (GPtrArray *) g_hash_table_lookup (priv->thread_id_to_node_list,
      GUINT_TO_POINTER (thread_id));
  if (nodes == NULL)
  {
    nodes = g_ptr_array_new ();
    g_hash_table_insert (priv->thread_id_to_node_list,
        GUINT_TO_POINTER (thread_id), nodes);
    g_ptr_array_add (priv->thread_root_nodes, nodes);
  }

  g_ptr_array_add (nodes, root_node);
}

void
_gum_profile_report_sort (GumProfileReport * self)
{
  GumProfileReportPrivate * priv = self->priv;
  guint i;

  for (i = 0; i < priv->thread_root_nodes->len; i++)
  {
    GPtrArray * root_nodes = (GPtrArray *)
        g_ptr_array_index (priv->thread_root_nodes, i);

    g_ptr_array_sort (root_nodes, root_node_compare_func);
  }

  g_ptr_array_sort (priv->thread_root_nodes, thread_compare_func);
}

static void
gum_profile_report_node_free (GumProfileReportNode * node)
{
  if (node == NULL)
    return;

  g_free (node->name);
  g_free (node->worst_case_info);
  gum_profile_report_node_free (node->child);

  g_free (node);
}

static void
append_node_to_xml_string (GumProfileReportNode * node,
                           GString * xml)
{
  g_string_append_printf (xml, "<Node name=\"%s\" total_calls=\"%"
      G_GUINT64_FORMAT "\" total_duration=\"%" G_GUINT64_FORMAT "\">",
      node->name, node->total_calls, node->total_duration);

  g_string_append_printf (xml, "<WorstCase duration=\"%" G_GUINT64_FORMAT
      "\">%s</WorstCase>", node->worst_case_duration, node->worst_case_info);

  if (node->child != NULL)
    append_node_to_xml_string (node->child, xml);

  g_string_append (xml, "</Node>");
}

static gint
root_node_compare_func (gconstpointer a,
                        gconstpointer b)
{
  const GumProfileReportNode * node_a = *((GumProfileReportNode **) a);
  const GumProfileReportNode * node_b = *((GumProfileReportNode **) b);

  if (node_a->total_duration > node_b->total_duration)
    return -1;
  else if (node_a->total_duration < node_b->total_duration)
    return 1;
  else
    return strcmp (node_a->name, node_b->name);
}

#define FIRST_ROOT_NODE(t) \
    ((GumProfileReportNode *) g_ptr_array_index (t, 0))

static gint
thread_compare_func (gconstpointer a,
                     gconstpointer b)
{
  const GPtrArray * root_nodes_a = *((GPtrArray **) a);
  const GPtrArray * root_nodes_b = *((GPtrArray **) b);
  GumSample total_duration_a = 0;
  GumSample total_duration_b = 0;

  if (root_nodes_a->len >= 1)
    total_duration_a = FIRST_ROOT_NODE (root_nodes_a)->total_duration;

  if (root_nodes_b->len >= 1)
    total_duration_b = FIRST_ROOT_NODE (root_nodes_b)->total_duration;

  if (total_duration_a > total_duration_b)
    return -1;
  else if (total_duration_a < total_duration_b)
    return 1;
  else
    return 0;
}
