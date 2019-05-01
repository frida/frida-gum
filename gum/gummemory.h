/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MEMORY_H__
#define __GUM_MEMORY_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

#define GUM_TYPE_MEMORY_RANGE (gum_memory_range_get_type ())
#define GUM_MEMORY_RANGE_INCLUDES(r, a) ((a) >= (r)->base_address && \
    (a) < ((r)->base_address + (r)->size))

#define GUM_PAGE_RW ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_WRITE))
#define GUM_PAGE_RX ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_EXECUTE))
#define GUM_PAGE_RWX ((GumPageProtection) (GUM_PAGE_READ | GUM_PAGE_WRITE | \
    GUM_PAGE_EXECUTE))

G_BEGIN_DECLS

typedef guint GumMemoryOperation;
typedef guint GumPageProtection;
typedef struct _GumAddressSpec GumAddressSpec;
typedef struct _GumMemoryRange GumMemoryRange;
typedef struct _GumMatchPattern GumMatchPattern;

typedef gboolean (* GumMemoryIsNearFunc) (gpointer memory, gpointer address);

enum _GumMemoryOperation
{
  GUM_MEMOP_INVALID,
  GUM_MEMOP_READ,
  GUM_MEMOP_WRITE,
  GUM_MEMOP_EXECUTE
};

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
  GumAddress base_address;
  gsize size;
};

typedef void (* GumMemoryPatchApplyFunc) (gpointer mem, gpointer user_data);
typedef gboolean (* GumMemoryScanMatchFunc) (GumAddress address, gsize size,
    gpointer user_data);

GUM_API void gum_memory_init (void);
GUM_API void gum_memory_deinit (void);

GUM_API guint gum_query_page_size (void);
GUM_API gboolean gum_query_is_rwx_supported (void);
GUM_API gboolean gum_memory_is_readable (gconstpointer address, gsize len);
GUM_API guint8 * gum_memory_read (gconstpointer address, gsize len,
    gsize * n_bytes_read);
GUM_API gboolean gum_memory_write (gpointer address, const guint8 * bytes,
    gsize len);
GUM_API gboolean gum_memory_patch_code (gpointer address, gsize size,
    GumMemoryPatchApplyFunc apply, gpointer apply_data);
GUM_API gboolean gum_memory_mark_code (gpointer address, gsize size);

GUM_API void gum_memory_scan (const GumMemoryRange * range,
    const GumMatchPattern * pattern, GumMemoryScanMatchFunc func,
    gpointer user_data);

GUM_API GumMatchPattern * gum_match_pattern_new_from_string (
    const gchar * match_combined_str);
GUM_API void gum_match_pattern_free (GumMatchPattern * pattern);

GUM_API void gum_mprotect (gpointer address, gsize size,
    GumPageProtection page_prot);
GUM_API gboolean gum_try_mprotect (gpointer address, gsize size,
    GumPageProtection page_prot);

GUM_API void gum_clear_cache (gpointer address, gsize size);

#define gum_new(struct_type, n_structs) \
    ((struct_type *) gum_malloc (n_structs * sizeof (struct_type)))
#define gum_new0(struct_type, n_structs) \
    ((struct_type *) gum_malloc0 (n_structs * sizeof (struct_type)))

GUM_API guint gum_peek_private_memory_usage (void);

GUM_API gpointer gum_malloc (gsize size);
GUM_API gpointer gum_malloc0 (gsize size);
GUM_API gpointer gum_calloc (gsize count, gsize size);
GUM_API gpointer gum_realloc (gpointer mem, gsize size);
GUM_API gpointer gum_memalign (gsize alignment, gsize size);
GUM_API gpointer gum_memdup (gconstpointer mem, gsize byte_size);
GUM_API void gum_free (gpointer mem);

GUM_API gpointer gum_alloc_n_pages (guint n_pages, GumPageProtection page_prot);
GUM_API gpointer gum_try_alloc_n_pages (guint n_pages,
    GumPageProtection page_prot);
GUM_API gpointer gum_alloc_n_pages_near (guint n_pages,
    GumPageProtection page_prot, const GumAddressSpec * address_spec);
GUM_API gpointer gum_try_alloc_n_pages_near (guint n_pages,
    GumPageProtection page_prot, const GumAddressSpec * address_spec);
GUM_API void gum_query_page_allocation_range (gconstpointer mem, guint size,
    GumMemoryRange * range);
GUM_API void gum_free_pages (gpointer mem);

GUM_API gpointer gum_memory_allocate (gpointer address, gsize size,
    gsize alignment, GumPageProtection page_prot);
GUM_API gboolean gum_memory_free (gpointer address, gsize size);
GUM_API gboolean gum_memory_release (gpointer address, gsize size);
GUM_API gboolean gum_memory_commit (gpointer address, gsize size,
    GumPageProtection page_prot);
GUM_API gboolean gum_memory_decommit (gpointer address, gsize size);

GUM_API GType gum_memory_range_get_type (void) G_GNUC_CONST;
GUM_API GumMemoryRange * gum_memory_range_copy (const GumMemoryRange * range);
GUM_API void gum_memory_range_free (GumMemoryRange * range);

G_END_DECLS

#endif
