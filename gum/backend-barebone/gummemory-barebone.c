/*
 * Copyright (C) 2025-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "gum/gumbarebone.h"

void
_gum_memory_backend_init (void)
{
}

void
_gum_memory_backend_deinit (void)
{
}

guint
_gum_memory_backend_query_page_size (void)
{
  return gum_barebone_query_page_size ();
}

G_GNUC_WEAK guint
gum_barebone_query_page_size (void)
{
  G_PANIC_MISSING_IMPLEMENTATION ();
  return 0;
}

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  GumPageProtection prot;

  if (!gum_memory_query_protection (address, &prot))
    return FALSE;

  return (prot & GUM_PAGE_READ) != 0;
}

G_GNUC_WEAK gboolean
gum_memory_query_protection (gconstpointer address,
                             GumPageProtection * prot)
{
  return FALSE;
}

G_GNUC_WEAK guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  return NULL;
}

G_GNUC_WEAK gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  return FALSE;
}

G_GNUC_WEAK gboolean
gum_memory_can_remap_writable (void)
{
  return FALSE;
}

G_GNUC_WEAK gpointer
gum_memory_try_remap_writable_pages (gpointer first_page,
                                     guint n_pages)
{
  return NULL;
}

G_GNUC_WEAK gpointer
gum_barebone_try_remap_writable_pages (gconstpointer * addrs,
                                       guint n_addrs)
{
  return NULL;
}

G_GNUC_WEAK void
gum_memory_dispose_writable_pages (gpointer first_page,
                                   guint n_pages)
{
}

G_GNUC_WEAK gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection prot)
{
  G_PANIC_MISSING_IMPLEMENTATION ();
  return FALSE;
}

G_GNUC_WEAK void
gum_clear_cache (gpointer address,
                 gsize size)
{
  G_PANIC_MISSING_IMPLEMENTATION ();
}

G_GNUC_WEAK gpointer
gum_memory_allocate (gpointer address,
                     gsize size,
                     gsize alignment,
                     GumPageProtection prot)
{
  G_PANIC_MISSING_IMPLEMENTATION ();
  return NULL;
}

gpointer
gum_memory_allocate_near (const GumAddressSpec * spec,
                          gsize size,
                          gsize alignment,
                          GumPageProtection prot)
{
  gpointer result;

  result = gum_memory_allocate (NULL, size, alignment, prot);
  if (result == NULL)
    return NULL;
  if (spec == NULL || gum_address_spec_is_satisfied_by (spec, result))
    return result;
  gum_memory_free (result, size);

  return NULL;
}

G_GNUC_WEAK gboolean
gum_memory_free (gpointer address,
                 gsize size)
{
  G_PANIC_MISSING_IMPLEMENTATION ();
  return FALSE;
}

G_GNUC_WEAK gboolean
gum_memory_release (gpointer address,
                    gsize size)
{
  return FALSE;
}

G_GNUC_WEAK gboolean
gum_memory_recommit (gpointer address,
                     gsize size,
                     GumPageProtection prot)
{
  return FALSE;
}

G_GNUC_WEAK gboolean
gum_memory_discard (gpointer address,
                    gsize size)
{
  return FALSE;
}

G_GNUC_WEAK gboolean
gum_memory_decommit (gpointer address,
                     gsize size)
{
  return FALSE;
}
