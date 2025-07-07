/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

static GArray * gum_pointer_array_new_empty (void);

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumDebugSymbolDetails * details)
{
  return FALSE;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  return NULL;
}

gpointer
gum_find_function (const gchar * name)
{
  return NULL;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  return gum_pointer_array_new_empty ();
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  return gum_pointer_array_new_empty ();
}

gboolean
gum_load_symbols (const gchar * path)
{
  return FALSE;
}

static GArray *
gum_pointer_array_new_empty (void)
{
  return g_array_new (FALSE, FALSE, sizeof (gpointer));
}
