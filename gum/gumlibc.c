/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumlibc.h"

gpointer
gum_memcpy (gpointer dst,
            gconstpointer src,
            gsize n)
{
  gsize offset;

  for (offset = 0; offset != n;)
  {
    gsize remaining = n - offset;
    gpointer d = ((guint8 *) dst) + offset;
    gconstpointer s = ((guint8 *) src) + offset;

    if (remaining >= sizeof (gpointer))
    {
      *((gpointer *) d) = *((gpointer *) s);
      offset += sizeof (gpointer);
    }
    else
    {
      *((guint8 *) d) = *((guint8 *) s);
      offset++;
    }
  }

  return dst;
}
