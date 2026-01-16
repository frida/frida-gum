/*
 * Copyright (C) 2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"


#define GUM_TDATA1_ENABLE ((guint64) (1ULL << 0))
#define GUM_TDATA1_EXECUTE ((guint64) (1ULL << 2))
#define GUM_TDATA1_LOAD ((guint64) (1ULL << 3))
#define GUM_TDATA1_STORE ((guint64) (1ULL << 4))

/* Match type: exact match */
#define GUM_TDATA1_MATCH ((guint64) (0ULL << 7))

/* Privilege level: user mode */
#define GUM_TDATA1_USER ((guint64) (1ULL << 6))

void
_gum_riscv_set_breakpoint (GumRiscvCtrlReg * tdata1,
                           GumRiscvValueReg * tdata2,
                           guint breakpoint_id,
                           GumAddress address)
{

  tdata1[breakpoint_id] =
      GUM_TDATA1_MATCH |
      GUM_TDATA1_USER |
      GUM_TDATA1_EXECUTE |
      GUM_TDATA1_ENABLE;
  tdata2[breakpoint_id] = address;
}

void
_gum_riscv_unset_breakpoint (GumRiscvCtrlReg * tdata1,
                              GumRiscvValueReg * tdata2,
                              guint breakpoint_id)
{
  tdata1[breakpoint_id] = 0;
  tdata2[breakpoint_id] = 0;
}

void
_gum_riscv_set_watchpoint (GumRiscvCtrlReg * tdata1,
                           GumRiscvValueReg * tdata2,
                           guint watchpoint_id,
                           GumAddress address,
                           gsize size,
                           GumWatchConditions conditions)
{

  guint64 aligned_address;
  guint64 size_mask;

  /* Align address to 8 bytes for simplicity */
  aligned_address = address & ~G_GUINT64_CONSTANT (7);


  if (size == 1)
    size_mask = 0x1;
  else if (size == 2)
    size_mask = 0x3;
  else if (size <= 4)
    size_mask = 0xf;
  else
    size_mask = 0xff;

  tdata1[watchpoint_id] =
      (size_mask << 16) |
      GUM_TDATA1_MATCH |
      GUM_TDATA1_USER |
      (((conditions & GUM_WATCH_WRITE) != 0) ? GUM_TDATA1_STORE : 0ULL) |
      (((conditions & GUM_WATCH_READ) != 0) ? GUM_TDATA1_LOAD : 0ULL) |
      GUM_TDATA1_ENABLE;
  tdata2[watchpoint_id] = aligned_address;
}

void
_gum_riscv_unset_watchpoint (GumRiscvCtrlReg * tdata1,
                              GumRiscvValueReg * tdata2,
                              guint watchpoint_id)
{
  tdata1[watchpoint_id] = 0;
  tdata2[watchpoint_id] = 0;
}

