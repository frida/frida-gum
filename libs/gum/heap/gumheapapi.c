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

#include "gumheapapi.h"

#include "gumprocess.h"

#include <gmodule.h>
#include <string.h>

static gboolean gum_collect_heap_api_if_crt_module (const gchar * name,
    const GumMemoryRange * range, const gchar * path, gpointer user_data);
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
gum_collect_heap_api_if_crt_module (const gchar * name,
                                    const GumMemoryRange * range,
                                    const gchar * path,
                                    gpointer user_data)
{
  GumHeapApiList * list = (GumHeapApiList *) user_data;

  (void) range;

  if (g_ascii_strncasecmp (name, "msvcr", 5) == 0 ||
      g_ascii_strncasecmp (name, "libSystem.B", 11) == 0)
  {
    GumHeapApi api = { 0, };
    GModule * module;

    module = g_module_open (path, (GModuleFlags) 0);

    GUM_API_INIT_FIELD (malloc);
    GUM_API_INIT_FIELD (calloc);
    GUM_API_INIT_FIELD (realloc);
    GUM_API_INIT_FIELD (free);

    if (g_strncasecmp (name + strlen (name) - 5, "d.dll", 5) == 0)
    {
      GUM_API_INIT_FIELD (_malloc_dbg);
      GUM_API_INIT_FIELD (_calloc_dbg);
      GUM_API_INIT_FIELD (_realloc_dbg);
      GUM_API_INIT_FIELD (_free_dbg);
    }

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
  gboolean success;

  success = g_module_symbol (module, name, field);
  g_assert (success);
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
