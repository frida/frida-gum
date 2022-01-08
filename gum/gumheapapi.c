/*
 * Copyright (C) 2010-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumheapapi.h"

#include "gumprocess.h"

#include <string.h>

/**
 * GumHeapApiList: (skip)
 */

static gboolean gum_collect_heap_api_if_crt_module (
    const GumModuleDetails * details, gpointer user_data);

GumHeapApiList *
gum_process_find_heap_apis (void)
{
  GumHeapApiList * list;

  list = gum_heap_api_list_new ();
  gum_process_enumerate_modules (gum_collect_heap_api_if_crt_module, list);

  return list;
}

static gboolean
gum_collect_heap_api_if_crt_module (const GumModuleDetails * details,
                                    gpointer user_data)
{
  const gchar * name = details->name;
  GumHeapApiList * list = (GumHeapApiList *) user_data;
  gboolean is_libc_module;

#if defined (HAVE_WINDOWS)
  is_libc_module = g_ascii_strncasecmp (name, "msvcr", 5) == 0;
#elif defined (HAVE_DARWIN)
  is_libc_module = g_ascii_strncasecmp (name, "libSystem.B", 11) == 0;
#else
  is_libc_module = strcmp (name, "libc.so") == 0;
#endif

  if (is_libc_module)
  {
    GumHeapApi api = { 0, };

#define GUM_ASSIGN(type, name) \
    api.name = GUM_POINTER_TO_FUNCPTR (type, gum_module_find_export_by_name ( \
        details->path, G_STRINGIFY (name)))

    GUM_ASSIGN (GumMallocFunc, malloc);
    GUM_ASSIGN (GumCallocFunc, calloc);
    GUM_ASSIGN (GumReallocFunc, realloc);
    GUM_ASSIGN (GumFreeFunc, free);

#ifdef HAVE_WINDOWS
    if (g_str_has_suffix (name, "d.dll"))
    {
      GUM_ASSIGN (GumMallocDbgFunc, _malloc_dbg);
      GUM_ASSIGN (GumCallocDbgFunc, _calloc_dbg);
      GUM_ASSIGN (GumReallocDbgFunc, _realloc_dbg);
      GUM_ASSIGN (GumFreeDbgFunc, _free_dbg);
      GUM_ASSIGN (GumCrtReportBlockTypeFunc, _CrtReportBlockType);
    }
#endif

#undef GUM_ASSIGN

    gum_heap_api_list_add (list, &api);
  }

  return TRUE;
}

GumHeapApiList *
gum_heap_api_list_new (void)
{
  return g_array_new (FALSE, FALSE, sizeof (GumHeapApi));
}

GumHeapApiList *
gum_heap_api_list_copy (const GumHeapApiList * list)
{
  GumHeapApiList * copy;

  copy = g_array_sized_new (FALSE, FALSE, sizeof (GumHeapApi), list->len);
  g_array_append_vals (copy, list->data, list->len);

  return copy;
}

void
gum_heap_api_list_free (GumHeapApiList * list)
{
  g_array_free (list, TRUE);
}

void
gum_heap_api_list_add (GumHeapApiList * self,
                       const GumHeapApi * api)
{
  GumHeapApi api_copy = *api;

  g_array_append_val (self, api_copy);
}

const GumHeapApi *
gum_heap_api_list_get_nth (const GumHeapApiList * self,
                           guint n)
{
  return &g_array_index (self, GumHeapApi, n);
}
