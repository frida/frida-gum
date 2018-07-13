/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MEMORY_PRIV_H__
#define __GUM_MEMORY_PRIV_H__

#include <gum/gumdefs.h>

typedef struct _GumMatchToken GumMatchToken;
typedef enum _GumMatchType GumMatchType;

struct _GumMatchPattern
{
  GPtrArray * tokens;
  guint size;
};

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
G_GNUC_INTERNAL gint _gum_page_protection_to_posix (
    GumPageProtection page_prot);

G_END_DECLS

#endif
