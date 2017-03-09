/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcloak.h"

G_LOCK_DEFINE_STATIC (cloak);
GHashTable * cloaked_base_addresses = NULL;

void
_gum_cloak_init (void)
{
  cloaked_base_addresses = g_hash_table_new (NULL, NULL);
}

void
_gum_cloak_deinit (void)
{
  g_clear_pointer (&cloaked_base_addresses, g_hash_table_unref);
}

void
gum_cloak_add_base_address (GumAddress base_address)
{
  G_LOCK (cloak);
  g_hash_table_add (cloaked_base_addresses, GSIZE_TO_POINTER (base_address));
  G_UNLOCK (cloak);
}

void
gum_cloak_remove_base_address (GumAddress base_address)
{
  G_LOCK (cloak);
  g_hash_table_remove (cloaked_base_addresses, GSIZE_TO_POINTER (base_address));
  G_UNLOCK (cloak);
}

gboolean
gum_cloak_has_base_address (GumAddress base_address)
{
  gboolean result;

  G_LOCK (cloak);
  result = g_hash_table_contains (cloaked_base_addresses,
      GSIZE_TO_POINTER (base_address));
  G_UNLOCK (cloak);

  return result;
}
