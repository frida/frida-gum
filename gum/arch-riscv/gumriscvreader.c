/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumriscvreader.h"

#include <string.h>

typedef struct _GumRiscvRedirectInfo GumRiscvRedirectInfo;

struct _GumRiscvRedirectInfo
{
  GumAddress target;
  gsize size;
};

static gboolean gum_riscv_decode_redirect (gconstpointer address,
    GumRiscvRedirectInfo * info);
static gboolean gum_riscv_decode_jal (const guint8 * code, GumAddress base,
    GumAddress * target);
static gboolean gum_riscv_decode_auipc_jalr (const guint8 * code,
    GumAddress base, GumAddress * target);
static guint32 gum_riscv_read_u32 (const guint8 * code);
static gint32 gum_riscv_sign_extend (gint32 value, guint bits);
static gint32 gum_riscv_extract_jal_offset (guint32 insn);

gboolean
gum_riscv_reader_try_get_relative_jump_info (gconstpointer address,
                                             GumAddress * target,
                                             gsize * size)
{
  GumRiscvRedirectInfo info;

  if (!gum_riscv_decode_redirect (address, &info))
    return FALSE;

  if (target != NULL)
    *target = info.target;
  if (size != NULL)
    *size = info.size;

  return TRUE;
}

gpointer
gum_riscv_reader_try_get_relative_jump_target (gconstpointer address)
{
  GumAddress target;

  if (!gum_riscv_reader_try_get_relative_jump_info (address, &target, NULL))
    return NULL;

  return GSIZE_TO_POINTER (target);
}

static gboolean
gum_riscv_decode_redirect (gconstpointer address,
                           GumRiscvRedirectInfo * info)
{
  GumAddress base = GUM_ADDRESS (address);
  const guint8 * code = address;

  if (gum_riscv_decode_jal (code, base, &info->target))
  {
    info->size = 4;
    return TRUE;
  }

  if (gum_riscv_decode_auipc_jalr (code, base, &info->target))
  {
    info->size = 8;
    return TRUE;
  }

  return FALSE;
}

static gboolean
gum_riscv_decode_jal (const guint8 * code,
                      GumAddress base,
                      GumAddress * target)
{
  guint32 insn = gum_riscv_read_u32 (code);

  if ((insn & 0x7f) != 0x6f)
    return FALSE;

  *target = base + gum_riscv_extract_jal_offset (insn);

  return TRUE;
}

static gboolean
gum_riscv_decode_auipc_jalr (const guint8 * code,
                             GumAddress base,
                             GumAddress * target)
{
  guint32 auipc = gum_riscv_read_u32 (code);
  guint32 jalr;
  guint rd, rs1, rd_jalr;
  gint32 hi20, lo12;

  if ((auipc & 0x7f) != 0x17)
    return FALSE;

  jalr = gum_riscv_read_u32 (code + 4);
  if ((jalr & 0x7f) != 0x67)
    return FALSE;

  rd = (auipc >> 7) & 0x1f;
  rs1 = (jalr >> 15) & 0x1f;
  rd_jalr = (jalr >> 7) & 0x1f;

  if (rd != rs1 || rd_jalr != 0)
    return FALSE;

  hi20 = gum_riscv_sign_extend ((gint32) (auipc >> 12), 20);
  lo12 = gum_riscv_sign_extend ((gint32) (jalr >> 20), 12);

  *target = base + (((gint64) hi20) << 12) + lo12;

  return TRUE;
}

static guint32
gum_riscv_read_u32 (const guint8 * code)
{
  guint32 value;

  memcpy (&value, code, sizeof (value));

  return GUINT32_FROM_LE (value);
}

static gint32
gum_riscv_sign_extend (gint32 value,
                       guint bits)
{
  const guint shift = 32 - bits;

  return (value << shift) >> shift;
}

static gint32
gum_riscv_extract_jal_offset (guint32 insn)
{
  gint32 offset = 0;

  offset |= ((insn >> 21) & 0x3ff) << 1;   /* imm[10:1] */
  offset |= ((insn >> 20) & 0x1) << 11;    /* imm[11] */
  offset |= ((insn >> 12) & 0xff) << 12;   /* imm[19:12] */
  offset |= ((insn >> 31) & 0x1) << 20;    /* imm[20] */

  return gum_riscv_sign_extend (offset, 21);
}
