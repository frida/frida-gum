/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumsanitychecker.h"

#include "guminstancetracker.h"
#include "gumhash.h"
#include "gummemory.h"

struct _GumSanityCheckerPrivate
{
  GumSanityOutputFunc output;
  gpointer output_user_data;
};

static void gum_sanity_checker_print_instance_leaks_summary (
    GumSanityChecker * self, GumList * stale);
static GumHashTable * gum_sanity_checker_count_leaks_by_type (
    GumList * instances);

static gint gum_sanity_checker_compare_type_names (gconstpointer a,
    gconstpointer b, gpointer user_data);

static void gum_sanity_checker_printf (GumSanityChecker * self,
    const gchar * format, ...);
static void gum_sanity_checker_print (GumSanityChecker * self,
    const gchar * text);

GumSanityChecker *
gum_sanity_checker_new (GumSanityOutputFunc func,
                        gpointer user_data)
{
  GumSanityChecker * checker;
  GumSanityCheckerPrivate * priv;

  checker = (GumSanityChecker *) gum_malloc0 (sizeof (GumSanityChecker) +
      sizeof (GumSanityCheckerPrivate));
  checker->priv = (GumSanityCheckerPrivate *) (checker + 1);

  priv = checker->priv;
  priv->output = func;
  priv->output_user_data = user_data;

  return checker;
}

void
gum_sanity_checker_destroy (GumSanityChecker * checker)
{
  gum_free (checker);
}

gboolean
gum_sanity_checker_run (GumSanityChecker * self,
                        GumSanitySequenceFunc func,
                        gpointer user_data)
{
  GumInstanceTracker * instance_tracker;
  GumList * stale;

  instance_tracker = gum_instance_tracker_new ();
  func (user_data);
  stale = gum_instance_tracker_peek_stale (instance_tracker);
  g_object_unref (instance_tracker);

  if (stale != NULL)
  {
    gum_sanity_checker_printf (self, "Instance leaks detected:\n\n");
    gum_sanity_checker_print_instance_leaks_summary (self, stale);
    gum_list_free (stale);
  }

  return stale == NULL;
}

static void
gum_sanity_checker_print_instance_leaks_summary (GumSanityChecker * self,
                                                 GumList * stale)
{
  GumSanityCheckerPrivate * priv = self->priv;
  GumHashTable * count_by_type;
  GumList * walk, * keys;

  count_by_type = gum_sanity_checker_count_leaks_by_type (stale);

  keys = gum_hash_table_get_keys (count_by_type);
  keys = gum_list_sort_with_data (keys,
      gum_sanity_checker_compare_type_names, count_by_type);

  gum_sanity_checker_print (self, "\tGType\tCount\n");
  gum_sanity_checker_print (self, "\t-----\t-----\n");

  for (walk = keys; walk != NULL; walk = walk->next)
  {
    const gchar * type_name = (const gchar *) walk->data;
    guint count;

    count = GPOINTER_TO_UINT (gum_hash_table_lookup (count_by_type,
        type_name));
    gum_sanity_checker_printf (self, "\t%s\t%u\n", type_name, count);
  }

  gum_list_free (keys);

  gum_hash_table_unref (count_by_type);
}

static GumHashTable *
gum_sanity_checker_count_leaks_by_type (GumList * instances)
{
  GumHashTable * count_by_type;
  GumList * walk;

  count_by_type =
      gum_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

  for (walk = instances; walk != NULL; walk = walk->next)
  {
    const gchar * type_name;
    guint count;

    type_name = g_type_name (G_TYPE_FROM_INSTANCE (walk->data));
    count = GPOINTER_TO_UINT (gum_hash_table_lookup (count_by_type,
        type_name));
    count++;
    gum_hash_table_insert (count_by_type, (gpointer) type_name,
        GUINT_TO_POINTER (count));
  }

  return count_by_type;
}

static gint
gum_sanity_checker_compare_type_names (gconstpointer a,
                                       gconstpointer b,
                                       gpointer user_data)
{
  const gchar * name_a = (const gchar *) a;
  const gchar * name_b = (const gchar *) b;
  GumHashTable * count_by_type = (GumHashTable *) user_data;
  guint count_a, count_b;

  count_a = GPOINTER_TO_UINT (gum_hash_table_lookup (count_by_type, name_a));
  count_b = GPOINTER_TO_UINT (gum_hash_table_lookup (count_by_type, name_b));
  if (count_a > count_b)
    return -1;
  else if (count_a < count_b)
    return 1;
  else
    return g_ascii_strcasecmp (name_a, name_b);
}

static void
gum_sanity_checker_printf (GumSanityChecker * self,
                           const gchar * format,
                           ...)
{
  va_list args;
  gchar * text;

  va_start (args, format);

  text = g_strdup_vprintf (format, args);
  gum_sanity_checker_print (self, text);
  g_free (text);

  va_end (args);
}

static void
gum_sanity_checker_print (GumSanityChecker * self,
                          const gchar * text)
{
  self->priv->output (text, self->priv->output_user_data);
}
