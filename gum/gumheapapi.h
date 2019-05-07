/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_HEAP_API_H__
#define __GUM_HEAP_API_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

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
  gint (* _CrtReportBlockType) (gpointer block);
};

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
