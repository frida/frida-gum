/*
 * Copyright (C) 2014-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummipswriter.h"

#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>

#define GUM_MAX_LABEL_COUNT       100
#define GUM_MAX_LABEL_REF_COUNT   (3 * GUM_MAX_LABEL_COUNT)
#define GUM_MAX_LITERAL_REF_COUNT 100

typedef struct _GumMipsArgument GumMipsArgument;
typedef guint GumMipsMemPairOperandSize;
typedef guint GumMipsMetaReg;
typedef struct _GumMipsRegInfo GumMipsRegInfo;

struct _GumMipsLabelMapping
{
  gconstpointer id;
  gpointer address;
};

struct _GumMipsLabelRef
{
  gconstpointer id;
  guint32 * insn;
};

struct _GumMipsLiteralRef
{
  guint32 * insn;
  gint64 val;
};

struct _GumMipsArgument
{
  GumArgType type;

  union
  {
    mips_reg reg;
    GumAddress address;
  } value;
};

enum _GumMipsMetaReg
{
  GUM_MREG_R0,
  GUM_MREG_R1,
  GUM_MREG_R2,
  GUM_MREG_R3,
  GUM_MREG_R4,
  GUM_MREG_R5,
  GUM_MREG_R6,
  GUM_MREG_R7,
  GUM_MREG_R8,
  GUM_MREG_R9,
  GUM_MREG_R10,
  GUM_MREG_R11,
  GUM_MREG_R12,
  GUM_MREG_R13,
  GUM_MREG_R14,
  GUM_MREG_R15,
  GUM_MREG_R16,
  GUM_MREG_R17,
  GUM_MREG_R18,
  GUM_MREG_R19,
  GUM_MREG_R20,
  GUM_MREG_R21,
  GUM_MREG_R22,
  GUM_MREG_R23,
  GUM_MREG_R24,
  GUM_MREG_R25,
  GUM_MREG_R26,
  GUM_MREG_R27,
  GUM_MREG_R28,
  GUM_MREG_R29,
  GUM_MREG_R30,
  GUM_MREG_R31,

  GUM_MREG_HI,
  GUM_MREG_LO,

  GUM_MREG_ZERO = GUM_MREG_R0,
  GUM_MREG_AT = GUM_MREG_R1,
  GUM_MREG_V0 = GUM_MREG_R2,
  GUM_MREG_V1 = GUM_MREG_R3,
  GUM_MREG_A0 = GUM_MREG_R4,
  GUM_MREG_A1 = GUM_MREG_R5,
  GUM_MREG_A2 = GUM_MREG_R6,
  GUM_MREG_A3 = GUM_MREG_R7,
  GUM_MREG_T0 = GUM_MREG_R8,
  GUM_MREG_T1 = GUM_MREG_R9,
  GUM_MREG_T2 = GUM_MREG_R10,
  GUM_MREG_T3 = GUM_MREG_R11,
  GUM_MREG_T4 = GUM_MREG_R12,
  GUM_MREG_T5 = GUM_MREG_R13,
  GUM_MREG_T6 = GUM_MREG_R14,
  GUM_MREG_T7 = GUM_MREG_R15,
  GUM_MREG_S0 = GUM_MREG_R16,
  GUM_MREG_S1 = GUM_MREG_R17,
  GUM_MREG_S2 = GUM_MREG_R18,
  GUM_MREG_S3 = GUM_MREG_R19,
  GUM_MREG_S4 = GUM_MREG_R20,
  GUM_MREG_S5 = GUM_MREG_R21,
  GUM_MREG_S6 = GUM_MREG_R22,
  GUM_MREG_S7 = GUM_MREG_R23,
  GUM_MREG_T8 = GUM_MREG_R24,
  GUM_MREG_T9 = GUM_MREG_R25,
  GUM_MREG_K0 = GUM_MREG_R26,
  GUM_MREG_K1 = GUM_MREG_R27,
  GUM_MREG_GP = GUM_MREG_R28,
  GUM_MREG_SP = GUM_MREG_R29,
  GUM_MREG_FP = GUM_MREG_R30,
  GUM_MREG_S8 = GUM_MREG_R30,
  GUM_MREG_RA = GUM_MREG_R31,
};

struct _GumMipsRegInfo
{
  GumMipsMetaReg meta;
  guint width;
  guint index;
};

static guint8 * gum_mips_writer_lookup_address_for_label_id (
    GumMipsWriter * self, gconstpointer id);
static void gum_mips_writer_put_argument_list_setup (GumMipsWriter * self,
    guint n_args, va_list vl);
static void gum_mips_writer_put_argument_list_teardown (GumMipsWriter * self,
    guint n_args);

static void gum_mips_writer_describe_reg (GumMipsWriter * self, mips_reg reg,
    GumMipsRegInfo * ri);

GumMipsWriter *
gum_mips_writer_new (gpointer code_address)
{
  GumMipsWriter * writer;

  writer = g_slice_new (GumMipsWriter);

  gum_mips_writer_init (writer, code_address);

  return writer;
}

GumMipsWriter *
gum_mips_writer_ref (GumMipsWriter * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_mips_writer_unref (GumMipsWriter * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_mips_writer_clear (writer);

    g_slice_free (GumMipsWriter, writer);
  }
}

void
gum_mips_writer_init (GumMipsWriter * writer,
                      gpointer code_address)
{
  writer->ref_count = 1;

  writer->id_to_address = g_new (GumMipsLabelMapping, GUM_MAX_LABEL_COUNT);
  writer->label_refs = g_new (GumMipsLabelRef, GUM_MAX_LABEL_REF_COUNT);
  writer->literal_refs = g_new (GumMipsLiteralRef, GUM_MAX_LITERAL_REF_COUNT);

  gum_mips_writer_reset (writer, code_address);
}

void
gum_mips_writer_clear (GumMipsWriter * writer)
{
  gum_mips_writer_flush (writer);

  g_free (writer->id_to_address);
  g_free (writer->label_refs);
  g_free (writer->literal_refs);
}

void
gum_mips_writer_reset (GumMipsWriter * writer,
                       gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  writer->id_to_address_len = 0;
  writer->label_refs_len = 0;
  writer->literal_refs_len = 0;
}

gpointer
gum_mips_writer_cur (GumMipsWriter * self)
{
  return self->code;
}

guint
gum_mips_writer_offset (GumMipsWriter * self)
{
  return (guint) (self->code - self->base) * sizeof (guint32);
}

void
gum_mips_writer_skip (GumMipsWriter * self,
                      guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

gboolean
gum_mips_writer_flush (GumMipsWriter * self)
{
  if (self->label_refs_len > 0)
  {
    guint label_idx;

    for (label_idx = 0; label_idx != self->label_refs_len; label_idx++)
    {
      GumMipsLabelRef * r = &self->label_refs[label_idx];
      gpointer target_address;
      gssize distance;
      guint32 insn;

      target_address =
          gum_mips_writer_lookup_address_for_label_id (self, r->id);
      if (target_address == NULL)
        goto error;

      distance = ((gssize) target_address - (gssize) r->insn) / 4;

      insn = *r->insn;
      /* j <int16> */
      if (insn == 0x08000000)
      {
        if (!GUM_IS_WITHIN_INT18_RANGE (distance << 2))
          goto error;
        insn |= distance & GUM_INT16_MASK;
      }
      /* beq <int16> */
      else if ((insn & 0xfc000000) == 0x10000000)
      {
        if (!GUM_IS_WITHIN_INT18_RANGE (distance << 2))
          goto error;
        insn |= distance & GUM_INT16_MASK;
      }
      /* TODO: conditional branches */
      else if ((insn & 0x7e000000) == 0x36000000)
      {
        if (!GUM_IS_WITHIN_INT14_RANGE (distance))
          goto error;
        insn |= (distance & GUM_INT14_MASK) << 5;
      }
      else
      {
        if (!GUM_IS_WITHIN_INT19_RANGE (distance))
          goto error;
        insn |= (distance & GUM_INT19_MASK) << 5;
      }

      *r->insn = insn;
    }
    self->label_refs_len = 0;
  }

  if (self->literal_refs_len > 0)
  {
    gint64 * first_slot, * last_slot;
    guint ref_idx;

    first_slot = (gint64 *) self->code;
    last_slot = first_slot;

    for (ref_idx = 0; ref_idx != self->literal_refs_len; ref_idx++)
    {
      GumMipsLiteralRef * r;
      gint64 * cur_slot, distance;
      guint32 insn;

      r = &self->literal_refs[ref_idx];

      for (cur_slot = first_slot; cur_slot != last_slot; cur_slot++)
      {
        if (*cur_slot == r->val)
          break;
      }

      if (cur_slot == last_slot)
      {
        *cur_slot = r->val;
        last_slot++;
      }

      distance = (gint64) GPOINTER_TO_SIZE (cur_slot) -
          (gint64) GPOINTER_TO_SIZE (r->insn);

      insn = GUINT32_FROM_LE (*r->insn);
      insn |= ((distance / 4) & GUM_INT19_MASK) << 5;
      *r->insn = GUINT32_TO_LE (insn);
    }
    self->literal_refs_len = 0;

    self->code = (guint32 *) last_slot;
    self->pc += (guint8 *) last_slot - (guint8 *) first_slot;
  }

  return TRUE;

error:
  {
    self->label_refs_len = 0;
    self->literal_refs_len = 0;

    return FALSE;
  }
}

static guint8 *
gum_mips_writer_lookup_address_for_label_id (GumMipsWriter * self,
                                             gconstpointer id)
{
  guint i;

  for (i = 0; i < self->id_to_address_len; i++)
  {
    GumMipsLabelMapping * map = &self->id_to_address[i];
    if (map->id == id)
      return map->address;
  }

  return NULL;
}

static gboolean
gum_mips_writer_add_address_for_label_id (GumMipsWriter * self,
                                          gconstpointer id,
                                          gpointer address)
{
  GumMipsLabelMapping * map;

  if (self->id_to_address_len == GUM_MAX_LABEL_COUNT)
    return FALSE;

  map = &self->id_to_address[self->id_to_address_len++];
  map->id = id;
  map->address = address;

  return TRUE;
}

gboolean
gum_mips_writer_put_label (GumMipsWriter * self,
                           gconstpointer id)
{
  if (gum_mips_writer_lookup_address_for_label_id (self, id) != NULL)
    return FALSE;

  return gum_mips_writer_add_address_for_label_id (self, id, self->code);
}

static gboolean
gum_mips_writer_add_label_reference_here (GumMipsWriter * self,
                                          gconstpointer id)
{
  GumMipsLabelRef * r;

  if (self->label_refs_len == GUM_MAX_LABEL_REF_COUNT)
    return FALSE;

  r = &self->label_refs[self->label_refs_len++];
  r->id = id;
  r->insn = self->code;

  return TRUE;
}

void
gum_mips_writer_put_call_address_with_arguments (GumMipsWriter * self,
                                                 GumAddress func,
                                                 guint n_args,
                                                 ...)
{
  va_list vl;

  va_start (vl, n_args);
  gum_mips_writer_put_argument_list_setup (self, n_args, vl);
  va_end (vl);

  mips_reg target = MIPS_REG_T9;
  gum_mips_writer_put_la_reg_address (self, target, func);
  gum_mips_writer_put_jalr_reg (self, target);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

void
gum_mips_writer_put_call_reg_with_arguments (GumMipsWriter * self,
                                             mips_reg reg,
                                             guint n_args,
                                             ...)
{
  va_list vl;

  va_start (vl, n_args);
  gum_mips_writer_put_argument_list_setup (self, n_args, vl);
  va_end (vl);

  gum_mips_writer_put_jalr_reg (self, reg);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

static void
gum_mips_writer_put_argument_list_setup (GumMipsWriter * self,
                                         guint n_args,
                                         va_list vl)
{
  GumMipsArgument * args;
  gint arg_index;

  args = g_alloca (n_args * sizeof (GumMipsArgument));

  for (arg_index = 0; arg_index != (gint) n_args; arg_index++)
  {
    GumMipsArgument * arg = &args[arg_index];

    arg->type = va_arg (vl, GumArgType);
    if (arg->type == GUM_ARG_ADDRESS)
      arg->value.address = va_arg (vl, GumAddress);
    else if (arg->type == GUM_ARG_REGISTER)
      arg->value.reg = va_arg (vl, mips_reg);
    else
      g_assert_not_reached ();
  }

  for (arg_index = n_args - 1; arg_index >= 0; arg_index--)
  {
    GumMipsArgument * arg = &args[arg_index];
    mips_reg r = MIPS_REG_A0 + arg_index;

    if (arg_index < 4)
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_mips_writer_put_la_reg_address (self, r, arg->value.address);
      }
      else
      {
        if (arg->value.reg != r)
          gum_mips_writer_put_move_reg_reg (self, r, arg->value.reg);
      }
    }
    else
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_mips_writer_put_la_reg_address (self, MIPS_REG_A0,
            arg->value.address);
        gum_mips_writer_put_push_reg (self, MIPS_REG_A0);
      }
      else
      {
        gum_mips_writer_put_push_reg (self, arg->value.reg);
      }
    }
  }
}

static void
gum_mips_writer_put_argument_list_teardown (GumMipsWriter * self,
                                            guint n_args)
{
  if (n_args > 4)
  {
    gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP,
        (n_args - 4) * sizeof (guint32));
  }
}

gboolean
gum_mips_writer_can_branch_directly_between (GumAddress from,
                                             GumAddress to)
{
  gint64 lower_limit = (from & 0xf0000000);
  gint64 upper_limit = (from & 0xf0000000) + GUM_INT28_MASK;

  return lower_limit < to && to < upper_limit;
}

gboolean
gum_mips_writer_put_j_address (GumMipsWriter * self,
                               GumAddress address)
{
  if ((address & 0xf0000000) != (self->pc & 0xf0000000) || address % 4 != 0)
    return FALSE;

  gum_mips_writer_put_instruction (self,
      0x08000000 | ((address & GUM_INT28_MASK) / 4));
  gum_mips_writer_put_nop (self);

  return TRUE;
}

gboolean
gum_mips_writer_put_j_label (GumMipsWriter * self,
                             gconstpointer label_id)
{
  if (!gum_mips_writer_add_label_reference_here (self, label_id))
    return FALSE;

  gum_mips_writer_put_instruction (self, 0x08000000);
  gum_mips_writer_put_nop (self);

  return TRUE;
}

void
gum_mips_writer_put_jr_reg (GumMipsWriter * self,
                            mips_reg reg)
{
  GumMipsRegInfo ri;

  gum_mips_writer_describe_reg (self, reg, &ri);

  gum_mips_writer_put_instruction (self, 0x00000008 | (ri.index << 21));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_jal_address (GumMipsWriter * self,
                                 guint32 address)
{
  gum_mips_writer_put_instruction (self, 0x0c000000 |
      ((address & GUM_INT28_MASK) >> 2));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_jalr_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo ri;

  gum_mips_writer_describe_reg (self, reg, &ri);

  gum_mips_writer_put_instruction (self, 0x00000009 | (ri.index << 21) |
      (GUM_MREG_RA << 11));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_b_offset (GumMipsWriter * self,
                              gint32 offset)
{
  gum_mips_writer_put_instruction (self, 0x10000000 | ((offset >> 2) & 0xffff));
  gum_mips_writer_put_nop (self);
}

gboolean
gum_mips_writer_put_beq_reg_reg_label (GumMipsWriter * self,
                                       mips_reg right_reg,
                                       mips_reg left_reg,
                                       gconstpointer label_id)
{
  GumMipsRegInfo rs, rt;

  gum_mips_writer_describe_reg (self, right_reg, &rs);
  gum_mips_writer_describe_reg (self, left_reg, &rt);

  if (!gum_mips_writer_add_label_reference_here (self, label_id))
    return FALSE;

  gum_mips_writer_put_instruction (self, 0x01000000 | (rs.index << 21) |
      (rt.index << 16));
  gum_mips_writer_put_nop (self);

  return TRUE;
}

void
gum_mips_writer_put_ret (GumMipsWriter * self)
{
  gum_mips_writer_put_jr_reg (self, MIPS_REG_RA);
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_la_reg_address (GumMipsWriter * self,
                                    mips_reg reg,
                                    GumAddress address)
{
  gum_mips_writer_put_lui_reg_imm (self, reg, address >> 16);
  gum_mips_writer_put_ori_reg_reg_imm (self, reg, reg, address & 0xffff);
}

void
gum_mips_writer_put_lui_reg_imm (GumMipsWriter * self,
                                 mips_reg reg,
                                 guint imm)
{
  GumMipsRegInfo ri;

  gum_mips_writer_describe_reg (self, reg, &ri);

  gum_mips_writer_put_instruction (self, 0x3c000000 | (ri.index << 16) |
      (imm & 0xffff));
}

void
gum_mips_writer_put_ori_reg_reg_imm (GumMipsWriter * self,
                                     mips_reg dst_reg,
                                     mips_reg src_reg,
                                     guint imm)
{
  GumMipsRegInfo rt, rs;

  gum_mips_writer_describe_reg (self, dst_reg, &rt);
  gum_mips_writer_describe_reg (self, src_reg, &rs);

  gum_mips_writer_put_instruction (self, 0x34000000 | (rt.index << 16) |
      (rs.index << 21) | (imm & 0xffff));
}

void
gum_mips_writer_put_lw_reg_reg_offset (GumMipsWriter * self,
                                       mips_reg dst_reg,
                                       mips_reg base_reg,
                                       gsize src_offset)
{
  GumMipsRegInfo rt, rb;

  gum_mips_writer_describe_reg (self, dst_reg, &rt);
  gum_mips_writer_describe_reg (self, base_reg, &rb);

  gum_mips_writer_put_instruction (self, 0x8c000000 | (rb.index << 21) |
      (rt.index << 16) | (src_offset & 0xffff));
}

void
gum_mips_writer_put_sw_reg_reg_offset (GumMipsWriter * self,
                                       mips_reg src_reg,
                                       mips_reg base_reg,
                                       gsize dest_offset)
{
  GumMipsRegInfo rt, rb;

  gum_mips_writer_describe_reg (self, src_reg, &rt);
  gum_mips_writer_describe_reg (self, base_reg, &rb);

  gum_mips_writer_put_instruction (self, 0xac000000 | (rb.index << 21) |
      (rt.index << 16) | (dest_offset & 0xffff));
}

void
gum_mips_writer_put_move_reg_reg (GumMipsWriter * self,
                                  mips_reg dst_reg,
                                  mips_reg src_reg)
{
  gum_mips_writer_put_addu_reg_reg_reg (self, dst_reg, src_reg, MIPS_REG_ZERO);
}

void
gum_mips_writer_put_addu_reg_reg_reg (GumMipsWriter * self,
                                      mips_reg dst_reg,
                                      mips_reg left_reg,
                                      mips_reg right_reg)
{
  GumMipsRegInfo rs, rt, rd;

  gum_mips_writer_describe_reg (self, dst_reg, &rd);
  gum_mips_writer_describe_reg (self, left_reg, &rs);
  gum_mips_writer_describe_reg (self, right_reg, &rt);

  gum_mips_writer_put_instruction (self, 0x00000021 | (rs.index << 21) |
      (rt.index << 16) | (rd.index << 11));
}

void
gum_mips_writer_put_addi_reg_reg_imm (GumMipsWriter * self,
                                      mips_reg dst_reg,
                                      mips_reg left_reg,
                                      gint32 imm)
{
  GumMipsRegInfo rt, rs;

  gum_mips_writer_describe_reg (self, dst_reg, &rt);
  gum_mips_writer_describe_reg (self, left_reg, &rs);

  gum_mips_writer_put_instruction (self, 0x20000000 | (rs.index << 21) |
      (rt.index << 16) | (imm & 0xffff));
}

void
gum_mips_writer_put_addi_reg_imm (GumMipsWriter * self,
                                  mips_reg dst_reg,
                                  gint32 imm)
{
  gum_mips_writer_put_addi_reg_reg_imm (self, dst_reg, dst_reg, imm);
}

void
gum_mips_writer_put_sub_reg_reg_imm (GumMipsWriter * self,
                                     mips_reg dst_reg,
                                     mips_reg left_reg,
                                     gint32 imm)
{
  gum_mips_writer_put_addi_reg_reg_imm (self, dst_reg, left_reg, -imm);
}

void
gum_mips_writer_put_push_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP,
      -((gint32) sizeof (guint32)));
  gum_mips_writer_put_sw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
}

void
gum_mips_writer_put_pop_reg (GumMipsWriter * self,
                             mips_reg reg)
{
  gum_mips_writer_put_lw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
  gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP, sizeof (guint32));
}

void
gum_mips_writer_put_mfhi_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rd;

  gum_mips_writer_describe_reg (self, reg, &rd);

  gum_mips_writer_put_instruction (self, 0x00000010 | (rd.index << 11));
}

void
gum_mips_writer_put_mflo_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rd;

  gum_mips_writer_describe_reg (self, reg, &rd);

  gum_mips_writer_put_instruction (self, 0x00000012 | (rd.index << 11));
}

void
gum_mips_writer_put_mthi_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rs;

  gum_mips_writer_describe_reg (self, reg, &rs);

  gum_mips_writer_put_instruction (self, 0x00000011 | (rs.index << 21));
}

void
gum_mips_writer_put_mtlo_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rs;

  gum_mips_writer_describe_reg (self, reg, &rs);

  gum_mips_writer_put_instruction (self, 0x00000013 | (rs.index << 21));
}

void
gum_mips_writer_put_nop (GumMipsWriter * self)
{
  gum_mips_writer_put_instruction (self, 0x00000000);
}

void
gum_mips_writer_put_break (GumMipsWriter * self)
{
  gum_mips_writer_put_instruction (self, 0x0000000d);
}

void
gum_mips_writer_put_instruction (GumMipsWriter * self,
                                 guint32 insn)
{
  *self->code++ = insn;
  self->pc += 4;
}

gboolean
gum_mips_writer_put_bytes (GumMipsWriter * self,
                           const guint8 * data,
                           guint n)
{
  if (n % 4 != 0)
    return FALSE;

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;

  return TRUE;
}

static void
gum_mips_writer_describe_reg (GumMipsWriter * self,
                              mips_reg reg,
                              GumMipsRegInfo * ri)
{
  (void) self;

  if (reg >= MIPS_REG_0 && reg <= MIPS_REG_31)
  {
    ri->meta = GUM_MREG_R0 + (reg - MIPS_REG_0);
    ri->width = 32;
    ri->index = ri->meta - GUM_MREG_R0;
  }
  else if (reg == MIPS_REG_HI)
  {
    ri->meta = GUM_MREG_HI;
    ri->width = 32;
    ri->index = -1;
  }
  else if (reg == MIPS_REG_LO)
  {
    ri->meta = GUM_MREG_LO;
    ri->width = 32;
    ri->index = -1;
  }
  else
  {
    g_assert_not_reached ();
  }
}
