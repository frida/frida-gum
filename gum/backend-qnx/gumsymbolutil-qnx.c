/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumSymbolDetails * details)
{
  g_assert_not_reached ();
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  g_assert_not_reached ();
}

gpointer
gum_find_function (const gchar * name)
{
  g_assert_not_reached ();
}

GArray *
gum_find_functions_named (const gchar * name)
{
  return gum_find_functions_matching (name);
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  g_assert_not_reached ();
}
