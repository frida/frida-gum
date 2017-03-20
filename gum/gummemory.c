/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gumcloak-priv.h"
#include "gumcodesegment.h"
#include "gumlibc.h"
#include "gummemory-priv.h"

#include <string.h>

#ifdef HAVE_IOS
# include "backend-darwin/gumdarwin.h"
# include <mach/mach.h>
#endif
#ifdef HAVE_DARWIN
# define DARWIN                   1
#endif
#define MSPACES                   1
#define ONLY_MSPACES              1
#define USE_LOCKS                 1
#define FOOTERS                   0
#define INSECURE                  1
#define NO_MALLINFO               0
#ifdef HAVE_LIBC_MALLINFO
# define STRUCT_MALLINFO_DECLARED 1
#endif
#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4267 4702)
#endif
#ifdef _GNU_SOURCE
# undef _GNU_SOURCE
#endif
#include "dlmalloc.c"
#ifdef _MSC_VER
# pragma warning (pop)
#endif

static GumMatchPattern * gum_match_pattern_new (void);
static void gum_match_pattern_update_computed_size (GumMatchPattern * self);
static GumMatchToken * gum_match_pattern_get_longest_token (
    const GumMatchPattern * self, GumMatchType type);
static gboolean gum_match_pattern_try_match_on (const GumMatchPattern * self,
    guint8 * bytes);
static GumMatchToken * gum_match_pattern_push_token (GumMatchPattern * self,
    GumMatchType type);
static gboolean gum_match_pattern_seal (GumMatchPattern * self);

static GumMatchToken * gum_match_token_new (GumMatchType type);
static void gum_match_token_free (GumMatchToken * token);
static void gum_match_token_append (GumMatchToken * self, guint8 byte);

static gboolean gum_memory_initialized = FALSE;
static mspace gum_mspace = NULL;
static guint gum_cached_page_size;

static mspace
gum_mspace_get (void)
{
  if (gum_mspace == NULL)
    gum_mspace = create_mspace (0, TRUE);
  return gum_mspace;
}

void
gum_memory_init (void)
{
  if (gum_memory_initialized)
    return;
  gum_memory_initialized = TRUE;

  gum_cached_page_size = _gum_memory_backend_query_page_size ();

  _gum_cloak_init ();

  gum_mspace_get ();
}

void
gum_memory_deinit (void)
{
  g_assert (gum_memory_initialized);

  destroy_mspace (gum_mspace);
  gum_mspace = NULL;

  (void) DESTROY_LOCK (&malloc_global_mutex);

  _gum_cloak_deinit ();

  gum_memory_initialized = FALSE;
}

guint
gum_query_page_size (void)
{
  return gum_cached_page_size;
}

gboolean
gum_query_is_rwx_supported (void)
{
#ifdef HAVE_IOS
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    gboolean supported = FALSE;
    gpointer p;
    mach_port_t task;
    mach_vm_address_t address;
    mach_vm_size_t size = (mach_vm_size_t) 0;
    natural_t depth = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count;
    kern_return_t kr;

    p = gum_alloc_n_pages (1, GUM_PAGE_RWX);

    task = mach_task_self ();
    address = (mach_vm_address_t) p;
    while (TRUE)
    {
      info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
      kr = mach_vm_region_recurse (task, &address, &size, &depth,
          (vm_region_recurse_info_t) &info, &info_count);
      if (kr != KERN_SUCCESS)
        break;

      if (info.is_submap)
      {
        depth++;
        continue;
      }
      else
      {
        vm_prot_t requested_prot =
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
        supported = (info.protection & requested_prot) == requested_prot;
        break;
      }
    }

    gum_free_pages (p);

    g_once_init_leave (&cached_result, supported + 1);
  }

  return cached_result - 1;
#else
  return TRUE;
#endif
}

gboolean
gum_memory_patch_code (GumAddress address,
                       gsize size,
                       GumMemoryPatchApplyFunc apply,
                       gpointer apply_data)
{
  gsize page_size;
  guint8 * start_page, * end_page;
  gsize page_offset, range_size;
  gboolean rwx_supported;

  page_size = gum_query_page_size ();
  start_page = GSIZE_TO_POINTER (((gsize) address) & ~(page_size - 1));
  end_page = GSIZE_TO_POINTER (
      ((gsize) (address + size - 1)) & ~(page_size - 1));
  page_offset = ((guint8 *) GSIZE_TO_POINTER (address)) - start_page;
  range_size = (end_page + page_size) - start_page;

  rwx_supported = gum_query_is_rwx_supported ();

  if (rwx_supported || !gum_code_segment_is_supported ())
  {
    GumPageProtection protection;

    protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

    if (!gum_try_mprotect (start_page, range_size, protection))
      return FALSE;

    apply (GSIZE_TO_POINTER (address), apply_data);

    if (!gum_try_mprotect (start_page, range_size, GUM_PAGE_RX))
      return FALSE;
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;

    segment = gum_code_segment_new (range_size, NULL);
    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page, start_page, range_size);

    apply (scratch_page + page_offset, apply_data);

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, range_size, start_page);
    gum_code_segment_free (segment);
  }

  gum_clear_cache (GSIZE_TO_POINTER (address), size);

  return TRUE;
}

void
gum_memory_scan (const GumMemoryRange * range,
                 const GumMatchPattern * pattern,
                 GumMemoryScanMatchFunc func,
                 gpointer user_data)
{
  GumMatchToken * needle;
  guint8 * needle_data;
  guint needle_len;
  guint8 * cur, * end_address;

  needle = gum_match_pattern_get_longest_token (pattern, GUM_MATCH_EXACT);
  needle_data = (guint8 *) needle->bytes->data;
  needle_len = needle->bytes->len;

  cur = GSIZE_TO_POINTER (range->base_address);
  end_address = cur + range->size - (pattern->size - needle->offset) + 1;

  for (; cur < end_address; cur++)
  {
    guint8 * start;

    if (cur[0] != needle_data[0] || memcmp (cur, needle_data, needle_len) != 0)
      continue;

    start = cur - needle->offset;

    if (gum_match_pattern_try_match_on (pattern, start))
    {
      if (!func (GUM_ADDRESS (start), pattern->size, user_data))
        return;

      cur = start + pattern->size - 1;
    }
  }
}

GumMatchPattern *
gum_match_pattern_new_from_string (const gchar * match_str)
{
  GumMatchPattern * pattern;
  GumMatchToken * token = NULL;
  const gchar * ch;

  pattern = gum_match_pattern_new ();

  for (ch = match_str; *ch != '\0'; ch++)
  {
    gint upper, lower;
    guint8 value;

    if (ch[0] == ' ')
      continue;

    if (ch[0] == '?' && ch[1] == '?')
    {
      if (token == NULL || token->type != GUM_MATCH_WILDCARD)
        token = gum_match_pattern_push_token (pattern, GUM_MATCH_WILDCARD);
      gum_match_token_append (token, 0x42);

      ch++;
      continue;
    }

    if ((upper = g_ascii_xdigit_value (ch[0])) == -1)
      goto parse_error;
    if ((lower = g_ascii_xdigit_value (ch[1])) == -1)
      goto parse_error;
    value = (upper << 4) | lower;

    if (token == NULL || token->type != GUM_MATCH_EXACT)
      token = gum_match_pattern_push_token (pattern, GUM_MATCH_EXACT);
    gum_match_token_append (token, value);

    ch++;
  }

  if (!gum_match_pattern_seal (pattern))
    goto parse_error;

  return pattern;

  /* ERRORS */
parse_error:
  {
    gum_match_pattern_free (pattern);
    return NULL;
  }
}

static GumMatchPattern *
gum_match_pattern_new (void)
{
  GumMatchPattern * pattern;

  pattern = g_slice_new (GumMatchPattern);
  pattern->tokens =
      g_ptr_array_new_with_free_func ((GDestroyNotify) gum_match_token_free);
  pattern->size = 0;

  return pattern;
}

void
gum_match_pattern_free (GumMatchPattern * pattern)
{
  g_ptr_array_free (pattern->tokens, TRUE);

  g_slice_free (GumMatchPattern, pattern);
}

static void
gum_match_pattern_update_computed_size (GumMatchPattern * self)
{
  guint i;

  self->size = 0;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    self->size += token->bytes->len;
  }
}

static GumMatchToken *
gum_match_pattern_get_longest_token (const GumMatchPattern * self,
                                     GumMatchType type)
{
  GumMatchToken * longest = NULL;
  guint i;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    if (token->type == type && (longest == NULL
        || token->bytes->len > longest->bytes->len))
    {
      longest = token;
    }
  }

  return longest;
}

static gboolean
gum_match_pattern_try_match_on (const GumMatchPattern * self,
                                guint8 * bytes)
{
  guint i;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    if (token->type == GUM_MATCH_EXACT)
    {
      gchar * p;

      p = (gchar *) bytes + token->offset;
      if (p == token->bytes->data ||
          memcmp (p, token->bytes->data, token->bytes->len) != 0)
      {
        return FALSE;
      }
    }
  }

  return TRUE;
}

static GumMatchToken *
gum_match_pattern_push_token (GumMatchPattern * self,
                              GumMatchType type)
{
  GumMatchToken * token;

  gum_match_pattern_update_computed_size (self);

  token = gum_match_token_new (type);
  token->offset = self->size;
  g_ptr_array_add (self->tokens, token);

  return token;
}

static gboolean
gum_match_pattern_seal (GumMatchPattern * self)
{
  GumMatchToken * token;

  gum_match_pattern_update_computed_size (self);

  if (self->size == 0)
    return FALSE;

  token = (GumMatchToken *) g_ptr_array_index (self->tokens, 0);
  if (token->type != GUM_MATCH_EXACT)
    return FALSE;

  token = (GumMatchToken *) g_ptr_array_index (self->tokens,
      self->tokens->len - 1);
  if (token->type != GUM_MATCH_EXACT)
    return FALSE;

  return TRUE;
}

static GumMatchToken *
gum_match_token_new (GumMatchType type)
{
  GumMatchToken * token;

  token = g_slice_new (GumMatchToken);
  token->type = type;
  token->bytes = g_array_new (FALSE, FALSE, sizeof (guint8));
  token->offset = 0;

  return token;
}

static void
gum_match_token_free (GumMatchToken * token)
{
  g_array_free (token->bytes, TRUE);
  g_slice_free (GumMatchToken, token);
}

static void
gum_match_token_append (GumMatchToken * self,
                        guint8 byte)
{
  g_array_append_val (self->bytes, byte);
}

void
gum_mprotect (gpointer address,
              gsize size,
              GumPageProtection page_prot)
{
  gboolean success;

  success = gum_try_mprotect (address, size, page_prot);
  g_assert (success);
}

guint
gum_peek_private_memory_usage (void)
{
  struct mallinfo info;

  info = mspace_mallinfo (gum_mspace_get ());

  return (guint) info.uordblks;
}

gpointer
gum_malloc (gsize size)
{
  return mspace_malloc (gum_mspace_get (), size);
}

gpointer
gum_malloc0 (gsize size)
{
  return mspace_calloc (gum_mspace_get (), 1, size);
}

gpointer
gum_calloc (gsize count, gsize size)
{
  return mspace_calloc (gum_mspace_get (), count, size);
}

gpointer
gum_realloc (gpointer mem,
             gsize size)
{
  return mspace_realloc (gum_mspace_get (), mem, size);
}

gpointer
gum_memdup (gconstpointer mem,
            gsize byte_size)
{
  gpointer result;

  result = mspace_malloc (gum_mspace_get (), byte_size);
  memcpy (result, mem, byte_size);

  return result;
}

void
gum_free (gpointer mem)
{
  mspace_free (gum_mspace_get (), mem);
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection page_prot,
                        const GumAddressSpec * address_spec)
{
  gpointer result;

  result = gum_try_alloc_n_pages_near (n_pages, page_prot, address_spec);
  g_assert (result != NULL);

  return result;
}
