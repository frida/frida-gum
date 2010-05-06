/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 */

#ifndef __GUM_HASH_H__
#define __GUM_HASH_H__

#include "gumlist.h"

G_BEGIN_DECLS

typedef struct _GumHashTable  GumHashTable;
typedef struct _GumHashTableIter GumHashTableIter;

struct _GumHashTableIter
{
  /*< private >*/
  gpointer	dummy1;
  gpointer	dummy2;
  gpointer	dummy3;
  int		dummy4;
  gboolean	dummy5;
  gpointer	dummy6;
};

/* Hash tables
 */
GumHashTable* gum_hash_table_new		   (GHashFunc	    hash_func,
					    GEqualFunc	    key_equal_func);
GumHashTable* gum_hash_table_new_full      	   (GHashFunc	    hash_func,
					    GEqualFunc	    key_equal_func,
					    GDestroyNotify  key_destroy_func,
					    GDestroyNotify  value_destroy_func);
void	    gum_hash_table_destroy	   (GumHashTable	   *hash_table);
void	    gum_hash_table_insert		   (GumHashTable	   *hash_table,
					    gpointer	    key,
					    gpointer	    value);
void        gum_hash_table_replace           (GumHashTable     *hash_table,
					    gpointer	    key,
					    gpointer	    value);
gboolean    gum_hash_table_remove		   (GumHashTable	   *hash_table,
					    gconstpointer   key);
void        gum_hash_table_remove_all        (GumHashTable     *hash_table);
gboolean    gum_hash_table_steal             (GumHashTable     *hash_table,
					    gconstpointer   key);
void        gum_hash_table_steal_all         (GumHashTable     *hash_table);
gpointer    gum_hash_table_lookup		   (GumHashTable	   *hash_table,
					    gconstpointer   key);
gboolean    gum_hash_table_lookup_extended   (GumHashTable	   *hash_table,
					    gconstpointer   lookup_key,
					    gpointer	   *orig_key,
					    gpointer	   *value);
void	    gum_hash_table_foreach	   (GumHashTable	   *hash_table,
					    GHFunc	    func,
					    gpointer	    user_data);
gpointer    gum_hash_table_find	           (GumHashTable	   *hash_table,
					    GHRFunc	    predicate,
					    gpointer	    user_data);
guint	    gum_hash_table_foreach_remove	   (GumHashTable	   *hash_table,
					    GHRFunc	    func,
					    gpointer	    user_data);
guint	    gum_hash_table_foreach_steal	   (GumHashTable	   *hash_table,
					    GHRFunc	    func,
					    gpointer	    user_data);
guint	    gum_hash_table_size		   (GumHashTable	   *hash_table);
GumList *   gum_hash_table_get_keys          (GumHashTable     *hash_table);
GumList *   gum_hash_table_get_values        (GumHashTable     *hash_table);

void        gum_hash_table_iter_init         (GumHashTableIter *iter,
					    GumHashTable     *hash_table);
gboolean    gum_hash_table_iter_next         (GumHashTableIter *iter,
					    gpointer       *key,
					    gpointer       *value);
GumHashTable* gum_hash_table_iter_get_hash_table (GumHashTableIter *iter);
void        gum_hash_table_iter_remove       (GumHashTableIter *iter);
void        gum_hash_table_iter_steal        (GumHashTableIter *iter);

/* keeping hash tables alive */
GumHashTable* gum_hash_table_ref   		   (GumHashTable 	   *hash_table);
void        gum_hash_table_unref             (GumHashTable     *hash_table);

G_END_DECLS

#endif /* __GUM_HASH_H__ */
