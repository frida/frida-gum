/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"
#include "gumdarwinsymbolicator.h"

static gpointer do_init (gpointer data);
static void do_deinit (void);

static GArray * gum_pointer_array_new_empty (void);
static GArray * gum_pointer_array_new_take_addresses (GumAddress * addresses,
    gsize len);

static GumDarwinSymbolicator *
gum_try_get_symbolicator (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, do_init, NULL);

  return init_once.retval;
}

static gpointer
do_init (gpointer data)
{
  GumDarwinSymbolicator * symbolicator;

  symbolicator =
      gum_darwin_symbolicator_new_with_task (mach_task_self (), NULL);
  if (symbolicator == NULL)
    return NULL;

  _gum_register_early_destructor (do_deinit);

  return symbolicator;
}

static void
do_deinit (void)
{
  g_object_unref (gum_try_get_symbolicator ());
}

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumDebugSymbolDetails * details)
{
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_get_symbolicator ()) == NULL)
    return FALSE;

  return gum_darwin_symbolicator_details_from_address (symbolicator,
      GUM_ADDRESS (address), details);
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_get_symbolicator ()) == NULL)
    return NULL;

  return gum_darwin_symbolicator_name_from_address (symbolicator,
      GUM_ADDRESS (address));
}

gpointer
gum_find_function (const gchar * name)
{
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_get_symbolicator ()) == NULL)
    return NULL;

  return GSIZE_TO_POINTER (
      gum_darwin_symbolicator_find_function (symbolicator, name));
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GumDarwinSymbolicator * symbolicator;
  GumAddress * addresses;
  gsize len;

  if ((symbolicator = gum_try_get_symbolicator ()) == NULL)
    return gum_pointer_array_new_empty ();

  addresses =
      gum_darwin_symbolicator_find_functions_named (symbolicator, name, &len);

  return gum_pointer_array_new_take_addresses (addresses, len);
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GumDarwinSymbolicator * symbolicator;
  GumAddress * addresses;
  gsize len;

  if ((symbolicator = gum_try_get_symbolicator ()) == NULL)
    return gum_pointer_array_new_empty ();

  addresses =
      gum_darwin_symbolicator_find_functions_matching (symbolicator, str, &len);

  return gum_pointer_array_new_take_addresses (addresses, len);
}

static GArray *
gum_pointer_array_new_empty (void)
{
  return g_array_new (FALSE, FALSE, sizeof (gpointer));
}

static GArray *
gum_pointer_array_new_take_addresses (GumAddress * addresses,
                                      gsize len)
{
  GArray * result;
  gsize i;

  result = g_array_sized_new (FALSE, FALSE, sizeof (gpointer), len);

  for (i = 0; i != len; i++)
  {
    gpointer address = GSIZE_TO_POINTER (addresses[i]);
    g_array_append_val (result, address);
  }

  g_free (addresses);

  return result;
}
