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

#ifndef __GUM_ARRAY_H__
#define __GUM_ARRAY_H__

#include <glib.h>

G_BEGIN_DECLS

typedef struct _GumArray		GumArray;

struct _GumArray
{
  gchar *data;
  guint len;
};

/* Resizable arrays. remove fills any cleared spot and shortens the
 * array, while preserving the order. remove_fast will distort the
 * order by moving the last element to the position of the removed.
 */

#define gum_array_append_val(a,v)	  gum_array_append_vals (a, &(v), 1)
#define gum_array_prepend_val(a,v)  gum_array_prepend_vals (a, &(v), 1)
#define gum_array_insert_val(a,i,v) gum_array_insert_vals (a, i, &(v), 1)
#define gum_array_index(a,t,i)      (((t*) (void *) (a)->data) [(i)])

GumArray * gum_array_new               (gboolean          zero_terminated,
				                                gboolean          clear_,
				                                guint             element_size);
GumArray * gum_array_sized_new         (gboolean          zero_terminated,
                                        gboolean          clear_,
				                                guint             element_size,
				                                guint             reserved_size);
gchar*  gum_array_free                 (GumArray           *array,
				                                gboolean          free_segment);
GumArray * gum_array_append_vals       (GumArray           *array,
				                                gconstpointer     data,
				                                guint             len);
GumArray * gum_array_prepend_vals      (GumArray           *array,
				                                gconstpointer     data,
				                                guint             len);
GumArray * gum_array_insert_vals       (GumArray           *array,
				                                guint             index_,
				                                gconstpointer     data,
				                                guint             len);
GumArray * gum_array_set_size          (GumArray           *array,
				                                guint             length);
GumArray * gum_array_remove_index      (GumArray           *array,
				                                guint             index_);
GumArray * gum_array_remove_index_fast (GumArray           *array,
				                                guint             index_);
GumArray * gum_array_remove_range      (GumArray           *array,
				                                guint             index_,
				                                guint             length);
void    gum_array_sort              (GumArray           *array,
				                             GCompareFunc      compare_func);
void    gum_array_sort_with_data    (GumArray           *array,
				                             GCompareDataFunc  compare_func,
				                             gpointer          user_data);

G_END_DECLS

#endif /* __GUM_ARRAY_H__ */
