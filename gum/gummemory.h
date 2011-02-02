/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

typedef guint GumPageProtection;
typedef struct _GumAddressSpec GumAddressSpec;
typedef struct _GumMemoryRange GumMemoryRange;
typedef struct _GumMatchPattern GumMatchPattern;

typedef gboolean (* GumMemoryIsNearFunc) (gpointer memory, gpointer address);

enum _GumPageProtection
{
  GUM_PAGE_NO_ACCESS = 0,
  GUM_PAGE_READ      = (1 << 0),
  GUM_PAGE_WRITE     = (1 << 1),
  GUM_PAGE_EXECUTE   = (1 << 2),
};

struct _GumAddressSpec
{
  gpointer near_address;
  gsize max_distance;
};

struct _GumMemoryRange
{
  gpointer base_address;
  gsize size;
};

#define GUM_MEMORY_RANGE_INCLUDES(r, a) ((a) >= (r)->base_address && \
    (a) < (gpointer) ((guint8 *) (r)->base_address + (r)->size))

#define GUM_PAGE_RW ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_WRITE))
#define GUM_PAGE_RX ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_EXECUTE))
#define GUM_PAGE_RWX ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_WRITE | GUM_PAGE_EXECUTE))

G_BEGIN_DECLS

typedef gboolean (* GumMemoryScanMatchFunc) (gpointer address, guint size,
    gpointer user_data);

guint gum_query_page_size (void);
gboolean gum_memory_is_readable (gpointer address, guint len);
guint8 * gum_memory_read (gpointer address, guint len, gint * n_bytes_read);
gboolean gum_memory_write (gpointer address, guint8 * bytes, guint len);

void gum_memory_scan (const GumMemoryRange * range,
    const GumMatchPattern * pattern,
    GumMemoryScanMatchFunc func, gpointer user_data);

GumMatchPattern * gum_match_pattern_new_from_string (const gchar * match_str);
void gum_match_pattern_free (GumMatchPattern * pattern);

void gum_mprotect (gpointer address, guint size, GumPageProtection page_prot);

void gum_clear_cache (gpointer address, guint size);

#define gum_new(struct_type, n_structs) \
    ((struct_type *) gum_malloc (n_structs * sizeof (struct_type)))
#define gum_new0(struct_type, n_structs) \
    ((struct_type *) gum_malloc0 (n_structs * sizeof (struct_type)))

guint gum_peek_private_memory_usage (void);

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
