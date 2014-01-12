/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_HEAP_API_H__
#define __GUM_HEAP_API_H__

#include <gum/gumdefs.h>

typedef struct _GumHeapApi GumHeapApi;
typedef GArray GumHeapApiList;

struct _GumHeapApi
{
  gpointer (* malloc) (gsize size);
  gpointer (* calloc) (gsize num, gsize size);
  gpointer (* realloc) (gpointer old_address, gsize new_size);
  void (* free) (gpointer address);

  /* for Microsoft's Debug CRT: */
  gpointer (* _malloc_dbg) (gsize size, gint block_type,
      const gchar * filename, gint linenumber);
  gpointer (* _calloc_dbg) (gsize num, gsize size, gint block_type,
      const gchar * filename, gint linenumber);
  gpointer (* _realloc_dbg) (gpointer old_address, gsize new_size,
      gint block_type, const gchar * filename, gint linenumber);
  void (* _free_dbg) (gpointer address, gint block_type);
};

G_BEGIN_DECLS

GUM_API GumHeapApiList * gum_process_find_heap_apis (void);

GUM_API GumHeapApiList * gum_heap_api_list_new (void);
GUM_API GumHeapApiList * gum_heap_api_list_copy (const GumHeapApiList * list);
GUM_API void gum_heap_api_list_free (GumHeapApiList * list);

GUM_API void gum_heap_api_list_add (GumHeapApiList * self,
    const GumHeapApi * api);
GUM_API const GumHeapApi * gum_heap_api_list_get_nth (
    const GumHeapApiList * self, guint n);

G_END_DECLS

#endif
