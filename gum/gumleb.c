/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumleb.h"

gint64
gum_read_sleb128 (const guint8 ** data,
                  const guint8 * end)
{
  const guint8 * p = *data;
  gint64 result = 0;
  gint offset = 0;
  guint8 value;

  do
  {
    gint64 chunk;

    g_assert (p != end);
    g_assert (offset <= 63);

    value = *p;
    chunk = value & 0x7f;
    result |= (chunk << offset);
    offset += 7;
  }
  while (*p++ & 0x80);

  if ((value & 0x40) != 0)
    result |= G_GINT64_CONSTANT (-1) << offset;

  *data = p;

  return result;
}

guint64
gum_read_uleb128 (const guint8 ** data,
                  const guint8 * end)
{
  const guint8 * p = *data;
  guint64 result = 0;
  gint offset = 0;

  do
  {
    guint64 chunk;

    g_assert (p != end);
    g_assert (offset <= 63);

    chunk = *p & 0x7f;
    result |= (chunk << offset);
    offset += 7;
  }
  while (*p++ & 0x80);

  *data = p;

  return result;
}

void
gum_skip_uleb128 (const guint8 ** data)
{
  const guint8 * p = *data;
  while ((*p & 0x80) != 0)
    p++;
  p++;
  *data = p;
}
