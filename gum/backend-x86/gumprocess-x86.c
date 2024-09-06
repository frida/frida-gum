/*
 * Copyright (C) 2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#define GUM_DR7_LOCAL_BREAKPOINT_ENABLE            ((guint32) 1U)
#define GUM_DR7_ENABLE_MASK                        ((guint32) 3U)
#define GUM_DR7_LE                                 ((guint32) (1U <<  8))
#define GUM_DR7_RESERVED_BIT10                     ((guint32) (1U << 10))
#define GUM_DR7_CONFIG_BREAK_DATA_WRITES_ONLY      ((guint32) (1U <<  0))
#define GUM_DR7_CONFIG_BREAK_DATA_READS_AND_WRITES ((guint32) (3U <<  0))
#define GUM_DR7_CONFIG_LENGTH_ONE                  ((guint32) (0U <<  2))
#define GUM_DR7_CONFIG_LENGTH_TWO                  ((guint32) (1U <<  2))
#define GUM_DR7_CONFIG_LENGTH_FOUR                 ((guint32) (3U <<  2))
#define GUM_DR7_CONFIG_LENGTH_EIGHT                ((guint32) (2U <<  2))
#define GUM_DR7_CONFIG_MASK                        ((guint32) 0xf)

void
_gum_x86_set_breakpoint (gsize * dr7,
                         gsize * dr0,
                         guint breakpoint_id,
                         GumAddress address)
{
  *dr7 &= ~(GUM_DR7_ENABLE_MASK << (breakpoint_id * 2));
  *dr7 &= ~(GUM_DR7_CONFIG_MASK << (16 + breakpoint_id * 4));
  *dr7 |=
      GUM_DR7_RESERVED_BIT10 |
      GUM_DR7_LE |
      GUM_DR7_LOCAL_BREAKPOINT_ENABLE << (breakpoint_id * 2);
  dr0[breakpoint_id] = address;
}

void
_gum_x86_unset_breakpoint (gsize * dr7,
                           gsize * dr0,
                           guint breakpoint_id)
{
  *dr7 &= ~(GUM_DR7_ENABLE_MASK << (breakpoint_id * 2));
  *dr7 &= ~(GUM_DR7_CONFIG_MASK << (16 + breakpoint_id * 4));
  dr0[breakpoint_id] = 0;
}

void
_gum_x86_set_watchpoint (gsize * dr7,
                         gsize * dr0,
                         guint watchpoint_id,
                         GumAddress address,
                         gsize size,
                         GumWatchConditions conditions)
{
  guint32 config = 0;

  if ((conditions & GUM_WATCH_READ) == 0)
    config |= GUM_DR7_CONFIG_BREAK_DATA_WRITES_ONLY;
  else
    config |= GUM_DR7_CONFIG_BREAK_DATA_READS_AND_WRITES;

  switch (size)
  {
    case 1:
      config |= GUM_DR7_CONFIG_LENGTH_ONE;
      break;
    case 2:
      config |= GUM_DR7_CONFIG_LENGTH_TWO;
      break;
    case 4:
      config |= GUM_DR7_CONFIG_LENGTH_FOUR;
      break;
    case 8:
      config |= GUM_DR7_CONFIG_LENGTH_EIGHT;
      break;
    default:
      g_assert_not_reached ();
  }

  *dr7 &= ~(GUM_DR7_ENABLE_MASK << (watchpoint_id * 2));
  *dr7 &= ~(GUM_DR7_CONFIG_MASK << (16 + watchpoint_id * 4));
  *dr7 |=
      config << (16 + watchpoint_id * 4) |
      GUM_DR7_RESERVED_BIT10 |
      GUM_DR7_LE |
      GUM_DR7_LOCAL_BREAKPOINT_ENABLE << (watchpoint_id * 2);
  dr0[watchpoint_id] = address;
}

void
_gum_x86_unset_watchpoint (gsize * dr7,
                           gsize * dr0,
                           guint watchpoint_id)
{
  *dr7 &= ~(GUM_DR7_ENABLE_MASK << (watchpoint_id * 2));
  *dr7 &= ~(GUM_DR7_CONFIG_MASK << (16 + watchpoint_id * 4));
  dr0[watchpoint_id] = 0;
}
