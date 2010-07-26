/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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

#ifndef __GUM_MEMORY_H__
#define __GUM_MEMORY_H__

#include <gum/gumdefs.h>

typedef enum _GumPageProtection GumPageProtection;
typedef struct _GumAddressSpec GumAddressSpec;

typedef gboolean (* GumMemoryIsNearFunc) (gpointer memory, gpointer address);

enum _GumPageProtection
{
  GUM_PAGE_NO_ACCESS = 0,
  GUM_PAGE_READ      = 1,
  GUM_PAGE_WRITE     = 2,
  GUM_PAGE_EXECUTE   = 4
};

struct _GumAddressSpec
{
  gpointer near_address;
  gsize max_distance;
};

#define GUM_PAGE_RW ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_WRITE))
#define GUM_PAGE_RWX ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_WRITE | GUM_PAGE_EXECUTE))

G_BEGIN_DECLS

void gum_memory_init (void);

guint gum_query_page_size (void);
gboolean gum_memory_is_readable (gpointer address, guint len);

void gum_mprotect (gpointer address, guint size, GumPageProtection page_prot);

#define gum_new(struct_type, n_structs) \
    ((struct_type *) gum_malloc (n_structs * sizeof (struct_type)))
#define gum_new0(struct_type, n_structs) \
    ((struct_type *) gum_malloc0 (n_structs * sizeof (struct_type)))

gpointer gum_malloc (gsize size);
gpointer gum_malloc0 (gsize size);
gpointer gum_realloc (gpointer mem, gsize size);
gpointer gum_memdup (gconstpointer mem, gsize byte_size);
void gum_free (gpointer mem);

gpointer gum_alloc_n_pages (guint n_pages, GumPageProtection page_prot);
gpointer gum_alloc_n_pages_near (guint n_pages, GumPageProtection page_prot, GumAddressSpec * address_spec);
void gum_free_pages (gpointer mem);

G_END_DECLS

#endif
