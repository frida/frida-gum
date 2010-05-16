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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
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

/*
 * MT safe
 */

#include <stdlib.h>
#include <string.h>
#include "gumarray.h"
#include "gummemory.h"

#define MIN_ARRAY_SIZE  16

typedef struct _GumRealArray  GumRealArray;

struct _GumRealArray
{
  guint8 * data;
  guint    len;
  guint    alloc;
  guint    elt_size;
  guint    zero_terminated : 1;
  guint    clear : 1;
};

#define gum_array_elt_len(array,i) ((array)->elt_size * (i))
#define gum_array_elt_pos(array,i) ((array)->data + gum_array_elt_len((array),(i)))
#define gum_array_elt_zero(array, pos, len)				\
  (memset (gum_array_elt_pos ((array), pos), 0,  gum_array_elt_len ((array), len)))
#define gum_array_zero_terminate(array) G_STMT_START{			\
  if ((array)->zero_terminated)						\
    gum_array_elt_zero ((array), (array)->len, 1);			\
}G_STMT_END

static gint g_nearest_pow        (gint num) G_GNUC_CONST;
static void gum_array_maybe_expand (GumRealArray * array, gint len);

GumArray *
gum_array_new (gboolean zero_terminated,
               gboolean clear,
               guint    elt_size)
{
  return (GumArray *) gum_array_sized_new (zero_terminated, clear, elt_size, 0);
}

GumArray *
gum_array_sized_new (gboolean zero_terminated,
                     gboolean clear,
                     guint    elt_size,
                     guint    reserved_size)
{
  GumRealArray * array = gum_malloc (sizeof (GumRealArray));

  array->data            = NULL;
  array->len             = 0;
  array->alloc           = 0;
  array->zero_terminated = (zero_terminated ? 1 : 0);
  array->clear           = (clear ? 1 : 0);
  array->elt_size        = elt_size;

  if (array->zero_terminated || reserved_size != 0)
  {
    gum_array_maybe_expand (array, reserved_size);
    gum_array_zero_terminate(array);
  }

  return (GumArray*) array;
}

gchar *
gum_array_free (GumArray * array,
                gboolean   free_segment)
{
  gchar * segment;

  if (free_segment)
  {
    gum_free (array->data);
    segment = NULL;
  }
  else
    segment = array->data;

  gum_free (array);

  return segment;
}

GumArray *
gum_array_append_vals (GumArray      * farray,
                       gconstpointer   data,
                       guint           len)
{
  GumRealArray * array = (GumRealArray *) farray;

  gum_array_maybe_expand (array, len);

  memcpy (gum_array_elt_pos (array, array->len), data,
	  gum_array_elt_len (array, len));

  array->len += len;

  gum_array_zero_terminate (array);

  return farray;
}

GumArray *
gum_array_prepend_vals (GumArray      * farray,
                        gconstpointer   data,
                        guint           len)
{
  GumRealArray * array = (GumRealArray *) farray;

  gum_array_maybe_expand (array, len);

  g_memmove (gum_array_elt_pos (array, len), gum_array_elt_pos (array, 0),
	     gum_array_elt_len (array, array->len));

  memcpy (gum_array_elt_pos (array, 0), data, gum_array_elt_len (array, len));

  array->len += len;

  gum_array_zero_terminate (array);

  return farray;
}

GumArray *
gum_array_insert_vals (GumArray      * farray,
                       guint           index,
                       gconstpointer   data,
                       guint           len)
{
  GumRealArray * array = (GumRealArray *) farray;

  gum_array_maybe_expand (array, len);

  g_memmove (gum_array_elt_pos (array, len + index),
	     gum_array_elt_pos (array, index),
	     gum_array_elt_len (array, array->len - index));

  memcpy (gum_array_elt_pos (array, index), data,
      gum_array_elt_len (array, len));

  array->len += len;

  gum_array_zero_terminate (array);

  return farray;
}

GumArray*
gum_array_set_size (GumArray * farray,
                    guint      length)
{
  GumRealArray * array = (GumRealArray *) farray;

  if (length > array->len)
  {
    gum_array_maybe_expand (array, length - array->len);

    if (array->clear)
      gum_array_elt_zero (array, array->len, length - array->len);
  }

  array->len = length;

  gum_array_zero_terminate (array);

  return farray;
}

GumArray *
gum_array_remove_index (GumArray * farray,
                        guint      index)
{
  GumRealArray * array = (GumRealArray *) farray;

  if (index != array->len - 1)
  {
    g_memmove (gum_array_elt_pos (array, index),
	       gum_array_elt_pos (array, index + 1),
	       gum_array_elt_len (array, array->len - index - 1));
  }

  array->len -= 1;

  gum_array_zero_terminate (array);

  return farray;
}

GumArray *
gum_array_remove_index_fast (GumArray * farray,
                             guint      index)
{
  GumRealArray * array = (GumRealArray *) farray;

  if (index != array->len - 1)
  {
    memcpy (gum_array_elt_pos (array, index),
	    gum_array_elt_pos (array, array->len - 1),
	    gum_array_elt_len (array, 1));
  }

  array->len -= 1;

  gum_array_zero_terminate (array);

  return farray;
}

GumArray *
gum_array_remove_range (GumArray * farray,
                        guint      index_,
                        guint      length)
{
  GumRealArray * array = (GumRealArray *) farray;

  if (index_ + length != array->len)
  {
    g_memmove (gum_array_elt_pos (array, index_),
               gum_array_elt_pos (array, index_ + length),
               (array->len - (index_ + length)) * array->elt_size);
  }

  array->len -= length;

  gum_array_zero_terminate (array);

  return farray;
}

void
gum_array_sort (GumArray     * farray,
	              GCompareFunc   compare_func)
{
  GumRealArray * array = (GumRealArray *) farray;

  g_return_if_fail (array != NULL);

  qsort (array->data, array->len, array->elt_size, compare_func);
}

void
gum_array_sort_with_data (GumArray         * farray,
                          GCompareDataFunc   compare_func,
                          gpointer           user_data)
{
  GumRealArray * array = (GumRealArray *) farray;

  g_return_if_fail (array != NULL);

  g_qsort_with_data (array->data,
		     array->len,
		     array->elt_size,
		     compare_func,
		     user_data);
}

static gint
g_nearest_pow (gint num)
{
  gint n = 1;

  while (n < num)
    n <<= 1;

  return n;
}

static void
gum_array_maybe_expand (GumRealArray * array,
                        gint           len)
{
  guint want_alloc = gum_array_elt_len (array, array->len + len +
				      array->zero_terminated);

  if (want_alloc > array->alloc)
  {
    want_alloc = g_nearest_pow (want_alloc);
    want_alloc = MAX (want_alloc, MIN_ARRAY_SIZE);

    array->data = gum_realloc (array->data, want_alloc);

    array->alloc = want_alloc;
  }
}

