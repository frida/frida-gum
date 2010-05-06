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

#ifndef __GUM_LIST_H__
#define __GUM_LIST_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef struct _GumList GumList;

struct _GumList
{
  gpointer data;
  GumList *next;
  GumList *prev;
};

/* Doubly linked lists
 */
GUM_API GumList *   gum_list_alloc                   (void) G_GNUC_WARN_UNUSED_RESULT;
GUM_API void        gum_list_free                    (GumList            *list);
GUM_API void        gum_list_free_1                  (GumList            *list);
#define  gum_list_free1                               gum_list_free_1
GUM_API GumList *   gum_list_append                  (GumList            *list,
					              gpointer          data) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_prepend                 (GumList            *list,
					              gpointer          data) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_insert                  (GumList            *list,
					              gpointer          data,
					              gint              position) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_insert_sorted           (GumList            *list,
					              gpointer          data,
					              GCompareFunc      func) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_insert_sorted_with_data (GumList            *list,
					              gpointer          data,
					              GCompareDataFunc  func,
					              gpointer          user_data) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_insert_before           (GumList            *list,
					              GumList            *sibling,
					              gpointer          data) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_concat                  (GumList            *list1,
					              GumList            *list2) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_remove                  (GumList            *list,
					              gconstpointer     data) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_remove_all              (GumList            *list,
					              gconstpointer     data) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_remove_link             (GumList            *list,
					              GumList            *llink) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_delete_link             (GumList            *list,
					              GumList            *link_) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_reverse                 (GumList            *list) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_copy                    (GumList            *list) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_nth                     (GumList            *list,
					              guint             n);
GUM_API GumList *   gum_list_nth_prev                (GumList            *list,
					              guint             n);
GUM_API GumList *   gum_list_find                    (GumList            *list,
					              gconstpointer     data);
GUM_API GumList *   gum_list_find_custom             (GumList            *list,
					              gconstpointer     data,
					              GCompareFunc      func);
GUM_API gint        gum_list_position                (GumList            *list,
					              GumList            *llink);
GUM_API gint        gum_list_index                   (GumList            *list,
					              gconstpointer     data);
GUM_API GumList *   gum_list_last                    (GumList            *list);
GUM_API GumList *   gum_list_first                   (GumList            *list);
GUM_API guint       gum_list_length                  (GumList            *list);
GUM_API void        gum_list_foreach                 (GumList            *list,
					              GFunc             func,
					              gpointer          user_data);
GUM_API GumList *   gum_list_sort                    (GumList            *list,
					              GCompareFunc      compare_func) G_GNUC_WARN_UNUSED_RESULT;
GUM_API GumList *   gum_list_sort_with_data          (GumList            *list,
					              GCompareDataFunc  compare_func,
					              gpointer          user_data)  G_GNUC_WARN_UNUSED_RESULT;
GUM_API gpointer    gum_list_nth_data                (GumList            *list,
					              guint             n);

#define gum_list_previous(list)	        ((list) ? (((GumList *)(list))->prev) : NULL)
#define gum_list_next(list)	        ((list) ? (((GumList *)(list))->next) : NULL)

G_END_DECLS

#endif /* __GUM_LIST_H__ */
