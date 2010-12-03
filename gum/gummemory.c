/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gummemory.h"

#include "gummemory-priv.h"

#include <string.h>

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

  cur = (guint8 *) range->base_address;
  end_address = cur + range->size - (pattern->size - needle->offset) + 1;

  for (; cur < end_address; cur++)
  {
    guint8 * start;

    if (cur[0] != needle_data[0] || memcmp (cur, needle_data, needle_len) != 0)
      continue;

    start = cur - needle->offset;

    if (gum_match_pattern_try_match_on (pattern, start))
    {
      if (!func (start, pattern->size, user_data))
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
  pattern->tokens = g_ptr_array_new ();
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
      if (memcmp (bytes + token->offset, token->bytes->data,
          token->bytes->len) != 0)
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