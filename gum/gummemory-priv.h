/*
 * Copyright (C) 2010-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MEMORY_PRIV_H__
#define __GUM_MEMORY_PRIV_H__

#include "gummemory.h"

typedef struct _GumMatchToken GumMatchToken;
typedef enum _GumMatchType GumMatchType;

enum _GumMatchType
{
  GUM_MATCH_EXACT,
  GUM_MATCH_WILDCARD,
  GUM_MATCH_MASK
};

struct _GumMatchToken
{
  GumMatchType type;
  GArray * bytes;
  GArray * masks;
  guint offset;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_memory_backend_init (void);
G_GNUC_INTERNAL void _gum_memory_backend_deinit (void);
G_GNUC_INTERNAL guint _gum_memory_backend_query_page_size (void);
G_GNUC_INTERNAL gboolean _gum_memory_is_allocation_hooked (
    GumPageProtection prot);
G_GNUC_INTERNAL gpointer _gum_memory_allocate_via_hooks (
    const GumAddressSpec * spec, gsize size, gsize alignment,
    GumPageProtection prot);
G_GNUC_INTERNAL gboolean _gum_memory_is_protection_hooked (void);
G_GNUC_INTERNAL gboolean _gum_memory_protect_via_hooks (gpointer address,
    gsize size, GumPageProtection prot);
G_GNUC_INTERNAL gint _gum_page_protection_to_posix (GumPageProtection prot);
#ifdef HAVE_LINUX
# include <sys/types.h>

G_GNUC_INTERNAL void _gum_memory_query_protections (GPtrArray * sorted_pages,
    GumPageProtection * protections);
G_GNUC_INTERNAL gboolean _gum_try_read_process_memory (pid_t pid,
    GumAddress address, gpointer buffer, gsize size);
G_GNUC_INTERNAL gboolean _gum_try_write_process_memory (pid_t pid,
    GumAddress address, gconstpointer data, gsize size);
#endif
#ifdef HAVE_WINDOWS
G_GNUC_INTERNAL gboolean _gum_windows_find_section_view (gconstpointer data,
    gpointer * section, guint64 * offset);
#endif

G_GNUC_INTERNAL gpointer gum_internal_malloc (size_t size);
G_GNUC_INTERNAL gpointer gum_internal_calloc (size_t count, size_t size);
G_GNUC_INTERNAL gpointer gum_internal_realloc (gpointer mem, size_t size);
G_GNUC_INTERNAL void gum_internal_free (gpointer mem);

G_END_DECLS

#endif
