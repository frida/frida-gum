/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumheapapi.h"

#include "gumprocess.h"

#include <gmodule.h>
#include <string.h>

static gboolean gum_collect_heap_api_if_crt_module (
    const GumModuleDetails * details, gpointer user_data);
static void gum_init_field_from_module_symbol (gpointer * field,
    GModule * module, const gchar * name);

GumHeapApiList *
gum_process_find_heap_apis (void)
{
  GumHeapApiList * list;

  list = gum_heap_api_list_new ();
  gum_process_enumerate_modules (gum_collect_heap_api_if_crt_module, list);

  return list;
}

#define GUM_API_INIT_FIELD(name) \
    gum_init_field_from_module_symbol ((gpointer *) &api.name, module, \
        G_STRINGIFY (name))

static gboolean
gum_collect_heap_api_if_crt_module (const GumModuleDetails * details,
                                    gpointer user_data)
{
  const gchar * name = details->name;
  GumHeapApiList * list = (GumHeapApiList *) user_data;
  gboolean is_libc_module;

#if defined (G_OS_WIN32)
  is_libc_module = g_ascii_strncasecmp (name, "msvcr", 5) == 0;
#elif defined (HAVE_DARWIN)
  is_libc_module = g_ascii_strncasecmp (name, "libSystem.B", 11) == 0;
#else
  is_libc_module = strcmp (name, "libc.so") == 0;
#endif

  if (is_libc_module)
  {
    GumHeapApi api = { 0, };
    GModule * module;

    module = g_module_open (details->path, (GModuleFlags) 0);

    GUM_API_INIT_FIELD (malloc);
    GUM_API_INIT_FIELD (calloc);
    GUM_API_INIT_FIELD (realloc);
    GUM_API_INIT_FIELD (free);

#ifdef G_OS_WIN32
    if (g_str_has_suffix (name, "d.dll"))
    {
      GUM_API_INIT_FIELD (_malloc_dbg);
      GUM_API_INIT_FIELD (_calloc_dbg);
      GUM_API_INIT_FIELD (_realloc_dbg);
      GUM_API_INIT_FIELD (_free_dbg);
      GUM_API_INIT_FIELD (_CrtReportBlockType);
    }
#endif

    g_module_close (module);

    gum_heap_api_list_add (list, &api);
  }

  return TRUE;
}

static void
gum_init_field_from_module_symbol (gpointer * field,
                                   GModule * module,
                                   const gchar * name)
{
  g_module_symbol (module, name, field);
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
