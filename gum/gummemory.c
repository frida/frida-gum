/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
# include <malloc.h>
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
static gint gum_memcmp_mask (const guint8 * haystack, const guint8 * needle,
    const guint8 * mask, guint len);
static GumMatchToken * gum_match_pattern_push_token (GumMatchPattern * self,
    GumMatchType type);
static gboolean gum_match_pattern_seal (GumMatchPattern * self);

static GumMatchToken * gum_match_token_new (GumMatchType type);
static void gum_match_token_free (GumMatchToken * token);
static void gum_match_token_append (GumMatchToken * self, guint8 byte);
static void gum_match_token_append_with_mask (GumMatchToken * self,
    guint8 byte, guint8 mask);

static guint gum_heap_ref_count = 0;
static mspace gum_mspace_main = NULL;
static mspace gum_mspace_capstone = NULL;
static guint gum_cached_page_size;

G_DEFINE_BOXED_TYPE (GumMemoryRange, gum_memory_range, gum_memory_range_copy,
    gum_memory_range_free)

void
gum_internal_heap_ref (void)
{
  if (gum_heap_ref_count++ > 0)
    return;

  _gum_memory_backend_init ();

  gum_cached_page_size = _gum_memory_backend_query_page_size ();

  _gum_cloak_init ();

  gum_mspace_main = create_mspace (0, TRUE);
  gum_mspace_capstone = create_mspace (0, TRUE);
}

void
gum_internal_heap_unref (void)
{
  g_assert (gum_heap_ref_count != 0);
  if (--gum_heap_ref_count > 0)
    return;

  destroy_mspace (gum_mspace_capstone);
  gum_mspace_capstone = NULL;

  destroy_mspace (gum_mspace_main);
  gum_mspace_main = NULL;

  (void) DESTROY_LOCK (&malloc_global_mutex);

  _gum_cloak_deinit ();

  _gum_memory_backend_deinit ();
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
    mach_port_t task;
    mach_vm_address_t page = 0;
    mach_vm_address_t address;
    mach_vm_size_t size = (mach_vm_size_t) 0;
    natural_t depth = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count;
    kern_return_t kr;

    task = mach_task_self ();

    kr = mach_vm_allocate (task, &page, gum_cached_page_size,
        VM_FLAGS_ANYWHERE);
    g_assert (kr == KERN_SUCCESS);

    gum_mprotect (GSIZE_TO_POINTER (page), gum_cached_page_size, GUM_PAGE_RWX);

    address = page;
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

    mach_vm_deallocate (task, page, gum_cached_page_size);

    g_once_init_leave (&cached_result, supported + 1);
  }

  return cached_result - 1;
#else
  return TRUE;
#endif
}

gboolean
gum_memory_patch_code (gpointer address,
                       gsize size,
                       GumMemoryPatchApplyFunc apply,
                       gpointer apply_data)
{
  gsize page_size;
  guint8 * start_page, * end_page;
  gsize page_offset, range_size;
  gboolean rwx_supported;

  page_size = gum_query_page_size ();
  start_page = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  end_page = GSIZE_TO_POINTER (
      (GPOINTER_TO_SIZE (address) + size - 1) & ~(page_size - 1));
  page_offset = ((guint8 *) address) - start_page;
  range_size = (end_page + page_size) - start_page;

  rwx_supported = gum_query_is_rwx_supported ();

  if (rwx_supported || !gum_code_segment_is_supported ())
  {
    GumPageProtection protection;

    protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

    if (!gum_try_mprotect (start_page, range_size, protection))
      return FALSE;

    apply (address, apply_data);

    gum_clear_cache (address, size);

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

    gum_clear_cache (address, size);
  }

  return TRUE;
}

gboolean
gum_memory_mark_code (gpointer address,
                      gsize size)
{
  gboolean success;

  if (gum_code_segment_is_supported ())
  {
    gsize page_size;
    guint8 * start_page, * end_page;

    page_size = gum_query_page_size ();
    start_page =
        GSIZE_TO_POINTER (GPOINTER_TO_SIZE (address) & ~(page_size - 1));
    end_page = GSIZE_TO_POINTER (
        (GPOINTER_TO_SIZE (address) + size - 1) & ~(page_size - 1));

    success = gum_code_segment_mark (start_page,
        end_page - start_page + page_size, NULL);
  }
  else
  {
    success = gum_try_mprotect (address, size, GUM_PAGE_RX);
  }

  gum_clear_cache (address, size);

  return success;
}

void
gum_memory_scan (const GumMemoryRange * range,
                 const GumMatchPattern * pattern,
                 GumMemoryScanMatchFunc func,
                 gpointer user_data)
{
  GumMatchToken * needle;
  guint8 * needle_data, * mask_data = NULL;
  guint needle_len;
  guint8 * cur, * end_address;

  needle = gum_match_pattern_get_longest_token (pattern, GUM_MATCH_EXACT);
  if (needle == NULL)
  {
    needle = gum_match_pattern_get_longest_token (pattern, GUM_MATCH_MASK);
    mask_data = (guint8 *) needle->masks->data;
  }

  needle_data = (guint8 *) needle->bytes->data;
  needle_len = needle->bytes->len;

  cur = GSIZE_TO_POINTER (range->base_address);
  end_address = cur + range->size - (pattern->size - needle->offset) + 1;

  for (; cur < end_address; cur++)
  {
    guint8 * start;

    if (mask_data == NULL)
    {
      if (cur[0] != needle_data[0] ||
          memcmp (cur, needle_data, needle_len) != 0)
      {
        continue;
      }
    }
    else
    {
      if ((cur[0] & mask_data[0]) != (needle_data[0] & mask_data[0]) ||
          gum_memcmp_mask ((guint8 *) cur, (guint8 *) needle_data,
              (guint8 *) mask_data, needle_len) != 0)
      {
        continue;
      }
    }

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
gum_match_pattern_new_from_string (const gchar * match_combined_str)
{
  GumMatchPattern * pattern = NULL;
  gchar ** parts;
  const gchar * match_str, * mask_str;
  gboolean has_mask = FALSE;
  GumMatchToken * token = NULL;
  const gchar * ch, * mh;

  parts = g_strsplit (match_combined_str, ":", 2);
  match_str = parts[0];
  if (match_str == NULL)
    goto parse_error;

  mask_str = parts[1];
  has_mask = mask_str != NULL;
  if (has_mask && strlen (mask_str) != strlen (match_str))
    goto parse_error;

  pattern = gum_match_pattern_new ();

  for (ch = match_str, mh = mask_str;
       *ch != '\0' && (!has_mask || *mh != '\0');
       ch++, mh++)
  {
    gint upper, lower;
    gint mask = 0xff;
    guint8 value;

    if (ch[0] == ' ')
      continue;

    if (has_mask)
    {
      while (mh[0] == ' ')
        mh++;
      if ((upper = g_ascii_xdigit_value (mh[0])) == -1)
        goto parse_error;
      if ((lower = g_ascii_xdigit_value (mh[1])) == -1)
        goto parse_error;
      mask = (upper << 4) | lower;
    }

    if (ch[0] == '?')
    {
      upper = 4;
      mask &= 0x0f;
    }
    else if ((upper = g_ascii_xdigit_value (ch[0])) == -1)
    {
      goto parse_error;
    }

    if (ch[1] == '?')
    {
      lower = 2;
      mask &= 0xf0;
    }
    else if ((lower = g_ascii_xdigit_value (ch[1])) == -1)
    {
      goto parse_error;
    }

    value = (upper << 4) | lower;

    if (mask == 0xff)
    {
      if (token == NULL || token->type != GUM_MATCH_EXACT)
        token = gum_match_pattern_push_token (pattern, GUM_MATCH_EXACT);
      gum_match_token_append (token, value);
    }
    else if (mask == 0x00)
    {
      if (token == NULL || token->type != GUM_MATCH_WILDCARD)
        token = gum_match_pattern_push_token (pattern, GUM_MATCH_WILDCARD);
      gum_match_token_append (token, 0x42);
    }
    else
    {
      if (token == NULL || token->type != GUM_MATCH_MASK)
        token = gum_match_pattern_push_token (pattern, GUM_MATCH_MASK);
      gum_match_token_append_with_mask (token, value, mask);
    }

    ch++;
    mh++;
  }

  if (!gum_match_pattern_seal (pattern))
    goto parse_error;

  g_strfreev (parts);

  return pattern;

  /* ERRORS */
parse_error:
  {
    g_strfreev (parts);
    if (pattern != NULL)
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
  gboolean no_masks = TRUE;

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
    else if (token->type == GUM_MATCH_MASK)
    {
      no_masks = FALSE;
    }
  }

  if (no_masks)
    return TRUE;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    if (token->type == GUM_MATCH_MASK)
    {
      gchar * p;

      p = (gchar *) bytes + token->offset;
      if (gum_memcmp_mask ((guint8 *) p, (guint8 *) token->bytes->data,
          (guint8 *) token->masks->data, token->masks->len) != 0)
      {
        return FALSE;
      }
    }
  }

  return TRUE;
}

static gint
gum_memcmp_mask (const guint8 * haystack,
                 const guint8 * needle,
                 const guint8 * mask,
                 guint len)
{
  guint i;

  for (i = 0; i != len; i++)
  {
    guint8 value = *(haystack++) & mask[i];
    guint8 test_value = needle[i] & mask[i];
    if (value != test_value)
      return value - test_value;
  }

  return 0;
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
  if (token->type == GUM_MATCH_WILDCARD)
    return FALSE;

  token = (GumMatchToken *) g_ptr_array_index (self->tokens,
      self->tokens->len - 1);
  if (token->type == GUM_MATCH_WILDCARD)
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
  token->masks = NULL;
  token->offset = 0;

  return token;
}

static void
gum_match_token_free (GumMatchToken * token)
{
  g_array_free (token->bytes, TRUE);
  if (token->masks != NULL)
    g_array_free (token->masks, TRUE);
  g_slice_free (GumMatchToken, token);
}

static void
gum_match_token_append (GumMatchToken * self,
                        guint8 byte)
{
  g_array_append_val (self->bytes, byte);
}

static void
gum_match_token_append_with_mask (GumMatchToken * self,
                                  guint8 byte,
                                  guint8 mask)
{
  g_array_append_val (self->bytes, byte);

  if (self->masks == NULL)
    self->masks = g_array_new (FALSE, FALSE, sizeof (guint8));

  g_array_append_val (self->masks, mask);
}

void
gum_mprotect (gpointer address,
              gsize size,
              GumPageProtection page_prot)
{
  gboolean success;

  success = gum_try_mprotect (address, size, page_prot);
  if (!success)
    g_abort ();
}

guint
gum_peek_private_memory_usage (void)
{
  guint total = 0;
  struct mallinfo info;

  info = mspace_mallinfo (gum_mspace_main);
  total += (guint) info.uordblks;

  info = mspace_mallinfo (gum_mspace_capstone);
  total += (guint) info.uordblks;

  return total;
}

gpointer
gum_malloc (gsize size)
{
  return mspace_malloc (gum_mspace_main, size);
}

gpointer
gum_malloc0 (gsize size)
{
  return mspace_calloc (gum_mspace_main, 1, size);
}

gpointer
gum_calloc (gsize count,
            gsize size)
{
  return mspace_calloc (gum_mspace_main, count, size);
}

gpointer
gum_realloc (gpointer mem,
             gsize size)
{
  return mspace_realloc (gum_mspace_main, mem, size);
}

gpointer
gum_memalign (gsize alignment,
              gsize size)
{
  return mspace_memalign (gum_mspace_main, alignment, size);
}

gpointer
gum_memdup (gconstpointer mem,
            gsize byte_size)
{
  gpointer result;

  result = mspace_malloc (gum_mspace_main, byte_size);
  memcpy (result, mem, byte_size);

  return result;
}

void
gum_free (gpointer mem)
{
  mspace_free (gum_mspace_main, mem);
}

gpointer
gum_cs_malloc (size_t size)
{
  return mspace_malloc (gum_mspace_capstone, size);
}

gpointer
gum_cs_calloc (size_t count,
               size_t size)
{
  return mspace_calloc (gum_mspace_capstone, count, size);
}

gpointer
gum_cs_realloc (gpointer mem,
                size_t size)
{
  return mspace_realloc (gum_mspace_capstone, mem, size);
}

void
gum_cs_free (gpointer mem)
{
  mspace_free (gum_mspace_capstone, mem);
}

gpointer
gum_alloc_n_pages (guint n_pages,
                   GumPageProtection page_prot)
{
  gpointer result;

  result = gum_try_alloc_n_pages (n_pages, page_prot);
  g_assert (result != NULL);

  return result;
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

GumMemoryRange *
gum_memory_range_copy (const GumMemoryRange * range)
{
  return g_slice_dup (GumMemoryRange, range);
}

void
gum_memory_range_free (GumMemoryRange * range)
{
  g_slice_free (GumMemoryRange, range);
}
