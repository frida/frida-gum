/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarm64writer.h"

#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>

#define GUM_MAX_LABEL_COUNT       100
#define GUM_MAX_LABEL_REF_COUNT   (3 * GUM_MAX_LABEL_COUNT)
#define GUM_MAX_LITERAL_REF_COUNT 100

typedef struct _GumArm64Argument GumArm64Argument;
typedef guint GumArm64MemPairOperandSize;
typedef guint GumArm64MetaReg;
typedef struct _GumArm64RegInfo GumArm64RegInfo;

struct _GumArm64LabelMapping
{
  gconstpointer id;
  gpointer address;
};

struct _GumArm64LabelRef
{
  gconstpointer id;
  guint32 * insn;
};

struct _GumArm64LiteralRef
{
  guint32 * insn;
  gint64 val;
};

struct _GumArm64Argument
{
  GumArgType type;

  union
  {
    arm64_reg reg;
    GumAddress address;
  } value;
};

enum _GumArm64MemPairOperandSize
{
  GUM_MEM_PAIR_OPERAND_32 = 0,
  GUM_MEM_PAIR_OPERAND_LOAD_SIGNED_64 = 1,
  GUM_MEM_PAIR_OPERAND_V64 = 1,
  GUM_MEM_PAIR_OPERAND_64 = 2,
  GUM_MEM_PAIR_OPERAND_V128 = 2
};

enum _GumArm64MetaReg
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

  GUM_MREG_FP = GUM_MREG_R29,
  GUM_MREG_LR = GUM_MREG_R30,
  GUM_MREG_SP = GUM_MREG_R31,
  GUM_MREG_ZR = GUM_MREG_R31
};

struct _GumArm64RegInfo
{
  GumArm64MetaReg meta;
  gboolean is_integer;
  guint width;
  guint index;
  guint32 sf;
};

static guint8 * gum_arm64_writer_lookup_address_for_label_id (
    GumArm64Writer * self, gconstpointer id);
static void gum_arm64_writer_put_argument_list_setup (GumArm64Writer * self,
    guint n_args, va_list vl);
static void gum_arm64_writer_put_argument_list_teardown (GumArm64Writer * self,
    guint n_args);
static void gum_arm64_writer_put_load_store_pair_pre (GumArm64Writer * self,
    GumArm64MemPairOperandSize op_size, guint opc, gboolean v, gboolean l,
    guint rt, guint rt2, guint rn, gssize pre_increment);
static void gum_arm64_writer_put_load_store_pair_post (GumArm64Writer * self,
    GumArm64MemPairOperandSize op_size, guint opc, gboolean v, gboolean l,
    guint rt, guint rt2, guint rn, gssize post_increment);
static gsize gum_mem_pair_offset_shift (GumArm64MemPairOperandSize size,
    gboolean v);

static void gum_arm64_writer_describe_reg (GumArm64Writer * self,
    arm64_reg reg, GumArm64RegInfo * ri);

void
gum_arm64_writer_init (GumArm64Writer * writer,
                       gpointer code_address)
{
  writer->id_to_address = g_new (GumArm64LabelMapping, GUM_MAX_LABEL_COUNT);
  writer->label_refs = g_new (GumArm64LabelRef, GUM_MAX_LABEL_REF_COUNT);
  writer->literal_refs = g_new (GumArm64LiteralRef, GUM_MAX_LITERAL_REF_COUNT);

  gum_arm64_writer_reset (writer, code_address);
}

void
gum_arm64_writer_reset (GumArm64Writer * writer,
                        gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  writer->id_to_address_len = 0;
  writer->label_refs_len = 0;
  writer->literal_refs_len = 0;
}

void
gum_arm64_writer_free (GumArm64Writer * writer)
{
  gum_arm64_writer_flush (writer);

  g_free (writer->id_to_address);
  g_free (writer->label_refs);
  g_free (writer->literal_refs);
}

gpointer
gum_arm64_writer_cur (GumArm64Writer * self)
{
  return self->code;
}

guint
gum_arm64_writer_offset (GumArm64Writer * self)
{
  return (guint) (self->code - self->base) * sizeof (guint32);
}

void
gum_arm64_writer_skip (GumArm64Writer * self,
                       guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

void
gum_arm64_writer_flush (GumArm64Writer * self)
{
  if (self->label_refs_len > 0)
  {
    guint label_idx;

    for (label_idx = 0; label_idx != self->label_refs_len; label_idx++)
    {
      GumArm64LabelRef * r = &self->label_refs[label_idx];
      gpointer target_address;
      gssize distance;
      guint32 insn;

      target_address =
          gum_arm64_writer_lookup_address_for_label_id (self, r->id);
      g_assert (target_address != NULL);

      distance = ((gssize) target_address - (gssize) r->insn) / 4;

      insn = GUINT32_FROM_LE (*r->insn);
      if (insn == 0x14000000)
      {
        g_assert (GUM_IS_WITHIN_INT26_RANGE (distance));
        insn |= distance & GUM_INT26_MASK;
      }
      else if ((insn & 0x7e000000) == 0x36000000)
      {
        g_assert (GUM_IS_WITHIN_INT14_RANGE (distance));
        insn |= (distance & GUM_INT14_MASK) << 5;
      }
      else
      {
        g_assert (GUM_IS_WITHIN_INT19_RANGE (distance));
        insn |= (distance & GUM_INT19_MASK) << 5;
      }

      *r->insn = GUINT32_TO_LE (insn);
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
      GumArm64LiteralRef * r;
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
}

static guint8 *
gum_arm64_writer_lookup_address_for_label_id (GumArm64Writer * self,
                                              gconstpointer id)
{
  guint i;

  for (i = 0; i < self->id_to_address_len; i++)
  {
    GumArm64LabelMapping * map = &self->id_to_address[i];
    if (map->id == id)
      return map->address;
  }

  return NULL;
}

static void
gum_arm64_writer_add_address_for_label_id (GumArm64Writer * self,
                                           gconstpointer id,
                                           gpointer address)
{
  GumArm64LabelMapping * map = &self->id_to_address[self->id_to_address_len++];

  g_assert_cmpuint (self->id_to_address_len, <=, GUM_MAX_LABEL_COUNT);

  map->id = id;
  map->address = address;
}

void
gum_arm64_writer_put_label (GumArm64Writer * self,
                            gconstpointer id)
{
  g_assert (gum_arm64_writer_lookup_address_for_label_id (self, id) == NULL);
  gum_arm64_writer_add_address_for_label_id (self, id, self->code);
}

static void
gum_arm64_writer_add_label_reference_here (GumArm64Writer * self,
                                           gconstpointer id)
{
  GumArm64LabelRef * r = &self->label_refs[self->label_refs_len++];

  g_assert_cmpuint (self->label_refs_len, <=, GUM_MAX_LABEL_REF_COUNT);

  r->id = id;
  r->insn = self->code;
}

static void
gum_arm64_writer_add_literal_reference_here (GumArm64Writer * self,
                                             guint64 val)
{
  GumArm64LiteralRef * r = &self->literal_refs[self->literal_refs_len++];

  g_assert_cmpuint (self->literal_refs_len, <=, GUM_MAX_LITERAL_REF_COUNT);

  r->insn = self->code;
  r->val = val;
}

void
gum_arm64_writer_put_call_address_with_arguments (GumArm64Writer * self,
                                                  GumAddress func,
                                                  guint n_args,
                                                  ...)
{
  va_list vl;

  va_start (vl, n_args);
  gum_arm64_writer_put_argument_list_setup (self, n_args, vl);
  va_end (vl);

  if (gum_arm64_writer_can_branch_imm (self->pc, func))
  {
    gum_arm64_writer_put_bl_imm (self, func);
  }
  else
  {
    arm64_reg target = ARM64_REG_X0 + n_args;
    gum_arm64_writer_put_ldr_reg_address (self, target, func);
    gum_arm64_writer_put_blr_reg (self, target);
  }

  gum_arm64_writer_put_argument_list_teardown (self, n_args);
}

void
gum_arm64_writer_put_call_reg_with_arguments (GumArm64Writer * self,
                                              arm64_reg reg,
                                              guint n_args,
                                              ...)
{
  va_list vl;

  va_start (vl, n_args);
  gum_arm64_writer_put_argument_list_setup (self, n_args, vl);
  va_end (vl);

  gum_arm64_writer_put_blr_reg (self, reg);

  gum_arm64_writer_put_argument_list_teardown (self, n_args);
}

static void
gum_arm64_writer_put_argument_list_setup (GumArm64Writer * self,
                                          guint n_args,
                                          va_list vl)
{
  GumArm64Argument * args;
  gint arg_index;

  args = g_alloca (n_args * sizeof (GumArm64Argument));

  for (arg_index = 0; arg_index != (gint) n_args; arg_index++)
  {
    GumArm64Argument * arg = &args[arg_index];

    arg->type = va_arg (vl, GumArgType);
    if (arg->type == GUM_ARG_ADDRESS)
      arg->value.address = va_arg (vl, GumAddress);
    else if (arg->type == GUM_ARG_REGISTER)
      arg->value.reg = va_arg (vl, arm64_reg);
    else
      g_assert_not_reached ();
  }

  for (arg_index = n_args - 1; arg_index >= 0; arg_index--)
  {
    GumArm64Argument * arg = &args[arg_index];
    arm64_reg r = ARM64_REG_X0 + arg_index;

    if (arg->type == GUM_ARG_ADDRESS)
    {
      gum_arm64_writer_put_ldr_reg_address (self, r, arg->value.address);
    }
    else
    {
      if (arg->value.reg != r)
        gum_arm64_writer_put_mov_reg_reg (self, r, arg->value.reg);
    }
  }
}

static void
gum_arm64_writer_put_argument_list_teardown (GumArm64Writer * self,
                                             guint n_args)
{
  (void) self;
  (void) n_args;
}

gboolean
gum_arm64_writer_can_branch_imm (GumAddress from,
                                 GumAddress to)
{
  gint64 distance = (gint64) to - (gint64) from;

  return GUM_IS_WITHIN_INT28_RANGE (distance);
}

void
gum_arm64_writer_put_b_imm (GumArm64Writer * self,
                            GumAddress address)
{
  gint64 distance = (gint64) address - (gint64) self->pc;

  g_assert (GUM_IS_WITHIN_INT28_RANGE (distance));
  g_assert_cmpint (distance % 4, ==, 0);

  gum_arm64_writer_put_instruction (self,
      0x14000000 | ((distance / 4) & GUM_INT26_MASK));
}

void
gum_arm64_writer_put_b_label (GumArm64Writer * self,
                              gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, 0x14000000);
}

void
gum_arm64_writer_put_b_cond_label (GumArm64Writer * self,
                                   arm64_cc cc,
                                   gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, 0x54000000 | (cc - 1));
}

void
gum_arm64_writer_put_bl_imm (GumArm64Writer * self,
                             GumAddress address)
{
  gint64 distance = (gint64) address - (gint64) self->pc;

  g_assert (GUM_IS_WITHIN_INT28_RANGE (distance));
  g_assert_cmpint (distance % 4, ==, 0);

  gum_arm64_writer_put_instruction (self,
      0x94000000 | ((distance / 4) & GUM_INT26_MASK));
}

void
gum_arm64_writer_put_br_reg (GumArm64Writer * self,
                             arm64_reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  gum_arm64_writer_put_instruction (self, 0xd61f0000 | (ri.index << 5));
}

void
gum_arm64_writer_put_blr_reg (GumArm64Writer * self,
                              arm64_reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  gum_arm64_writer_put_instruction (self, 0xd63f0000 | (ri.index << 5));
}

void
gum_arm64_writer_put_ret (GumArm64Writer * self)
{
  gum_arm64_writer_put_instruction (self, 0xd65f0000 | (GUM_MREG_LR << 5));
}

void
gum_arm64_writer_put_cbz_reg_label (GumArm64Writer * self,
                                    arm64_reg reg,
                                    gconstpointer label_id)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, ri.sf | 0x34000000 | ri.index);
}

void
gum_arm64_writer_put_cbnz_reg_label (GumArm64Writer * self,
                                     arm64_reg reg,
                                     gconstpointer label_id)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, ri.sf | 0x35000000 | ri.index);
}

void
gum_arm64_writer_put_tbz_reg_imm_label (GumArm64Writer * self,
                                        arm64_reg reg,
                                        guint bit,
                                        gconstpointer label_id)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, ri.sf | 0x36000000 |
      ((bit & GUM_INT5_MASK) << 19) | ri.index);
}

void
gum_arm64_writer_put_tbnz_reg_imm_label (GumArm64Writer * self,
                                         arm64_reg reg,
                                         guint bit,
                                         gconstpointer label_id)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, ri.sf | 0x37000000 |
      ((bit & GUM_INT5_MASK) << 19) | ri.index);
}

void
gum_arm64_writer_put_push_reg_reg (GumArm64Writer * self,
                                   arm64_reg reg_a,
                                   arm64_reg reg_b)
{
  GumArm64RegInfo ra, rb, sp;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);
  gum_arm64_writer_describe_reg (self, ARM64_REG_SP, &sp);

  g_assert_cmpuint (ra.width, ==, rb.width);

  if (ra.width == 64)
  {
    gum_arm64_writer_put_load_store_pair_pre (self, GUM_MEM_PAIR_OPERAND_64,
        2, FALSE, FALSE, ra.index, rb.index, sp.index, -16);
  }
  else
  {
    gum_arm64_writer_put_load_store_pair_pre (self, GUM_MEM_PAIR_OPERAND_32,
        0, FALSE, FALSE, ra.index, rb.index, sp.index, -8);
  }
}

void
gum_arm64_writer_put_pop_reg_reg (GumArm64Writer * self,
                                  arm64_reg reg_a,
                                  arm64_reg reg_b)
{
  GumArm64RegInfo ra, rb, sp;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);
  gum_arm64_writer_describe_reg (self, ARM64_REG_SP, &sp);

  g_assert_cmpuint (ra.width, ==, rb.width);

  if (ra.width == 64)
  {
    gum_arm64_writer_put_load_store_pair_post (self, GUM_MEM_PAIR_OPERAND_64,
        2, FALSE, TRUE, ra.index, rb.index, sp.index, 16);
  }
  else
  {
    gum_arm64_writer_put_load_store_pair_post (self, GUM_MEM_PAIR_OPERAND_32,
        0, FALSE, TRUE, ra.index, rb.index, sp.index, 8);
  }
}

void
gum_arm64_writer_put_ldr_reg_address (GumArm64Writer * self,
                                      arm64_reg reg,
                                      GumAddress address)
{
  gum_arm64_writer_put_ldr_reg_u64 (self, reg, (guint64) address);
}

void
gum_arm64_writer_put_ldr_reg_u64 (GumArm64Writer * self,
                                  arm64_reg reg,
                                  guint64 val)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  gum_arm64_writer_add_literal_reference_here (self, val);
  gum_arm64_writer_put_instruction (self,
      (ri.is_integer ? 0x58000000 : 0x5c000000) | ri.index);
}

void
gum_arm64_writer_put_ldr_reg_reg_offset (GumArm64Writer * self,
                                         arm64_reg dst_reg,
                                         arm64_reg src_reg,
                                         gsize src_offset)
{

  GumArm64RegInfo rd, rs;
  guint32 size, v, opc;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rs);

  opc = 1;
  if (rd.is_integer)
  {
    size = (rd.width == 64) ? 3 : 2;
    v = 0;
  }
  else
  {
    if (rd.width == 128)
    {
      size = 0;
      opc |= 2;
    }
    else
    {
      size = (rd.width == 64) ? 3 : 2;
    }
    v = 1;
  }

  g_assert_cmpuint (rs.width, ==, 64);

  gum_arm64_writer_put_instruction (self, 0x39000000 |
      (size << 30) | (v << 26) | (opc << 22) |
      ((guint32) src_offset / (rd.width / 8)) << 10 |
      (rs.index << 5) | rd.index);
}

void
gum_arm64_writer_put_adrp_reg_address (GumArm64Writer * self,
                                       arm64_reg reg,
                                       GumAddress address)
{
  GumArm64RegInfo ri;
  union
  {
    gint64 i;
    guint64 u;
  } distance;
  guint32 imm_hi, imm_lo;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  distance.i = (gint64) address -
      (gint64) (self->pc & ~((GumAddress) (4096 - 1)));
  g_assert (distance.i % 4096 == 0);
  distance.i /= 4096;

  g_assert (GUM_IS_WITHIN_INT21_RANGE (distance.i));

  imm_hi = (distance.u & G_GUINT64_CONSTANT (0x1ffffc)) >> 2;
  imm_lo = (distance.u & G_GUINT64_CONSTANT (0x3));

  gum_arm64_writer_put_instruction (self, 0x90000000 |
      (imm_lo << 29) | (imm_hi << 5) | ri.index);
}

void
gum_arm64_writer_put_str_reg_reg_offset (GumArm64Writer * self,
                                         arm64_reg src_reg,
                                         arm64_reg dst_reg,
                                         gsize dst_offset)
{
  GumArm64RegInfo rs, rd;
  guint32 size, v, opc;

  gum_arm64_writer_describe_reg (self, src_reg, &rs);
  gum_arm64_writer_describe_reg (self, dst_reg, &rd);

  opc = 0;
  if (rs.is_integer)
  {
    size = (rs.width == 64) ? 3 : 2;
    v = 0;
  }
  else
  {
    if (rs.width == 128)
    {
      size = 0;
      opc |= 2;
    }
    else
    {
      size = (rs.width == 64) ? 3 : 2;
    }
    v = 1;
  }

  g_assert_cmpuint (rd.width, ==, 64);

  gum_arm64_writer_put_instruction (self, 0x39000000 |
      (size << 30) | (v << 26) | (opc << 22) |
      ((guint32) dst_offset / (rs.width / 8)) << 10 |
      (rd.index << 5) | rs.index);
}

void
gum_arm64_writer_put_mov_reg_reg (GumArm64Writer * self,
                                  arm64_reg dst_reg,
                                  arm64_reg src_reg)
{
  GumArm64RegInfo rd, rs;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rs);

  g_assert_cmpuint (rd.width, ==, rs.width);

  if (rd.meta == GUM_MREG_SP || rs.meta == GUM_MREG_SP)
  {
    gum_arm64_writer_put_instruction (self, 0x91000000 | rd.index |
        (rs.index << 5));
  }
  else
  {
    gum_arm64_writer_put_instruction (self, rd.sf | 0x2a000000 | rd.index |
        (GUM_MREG_ZR << 5) | (rs.index << 16));
  }
}

void
gum_arm64_writer_put_add_reg_reg_imm (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      gsize right_value)
{
  GumArm64RegInfo rd, rl;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);

  g_assert_cmpuint (rd.width, ==, rl.width);

  gum_arm64_writer_put_instruction (self, rd.sf | 0x11000000 | rd.index |
      (rl.index << 5) | (right_value << 10));
}

void
gum_arm64_writer_put_add_reg_reg_reg (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      arm64_reg right_reg)
{
  GumArm64RegInfo rd, rl, rr;
  guint32 flags = 0;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);
  gum_arm64_writer_describe_reg (self, right_reg, &rr);

  g_assert_cmpuint (rd.width, ==, rl.width);
  g_assert_cmpuint (rd.width, ==, rr.width);

  if (rd.width == 64)
    flags |= 0x8000000;

  gum_arm64_writer_put_instruction (self, rd.sf | 0xb000000 | flags | rd.index |
      (rl.index << 5) | (rr.index << 16));
}

void
gum_arm64_writer_put_sub_reg_reg_imm (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      gsize right_value)
{
  GumArm64RegInfo rd, rl;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);

  g_assert_cmpuint (rd.width, ==, rl.width);

  gum_arm64_writer_put_instruction (self, rd.sf | 0x51000000 | rd.index |
      (rl.index << 5) | (right_value << 10));
}

void
gum_arm64_writer_put_nop (GumArm64Writer * self)
{
  gum_arm64_writer_put_instruction (self, 0xd503201f);
}

void
gum_arm64_writer_put_brk_imm (GumArm64Writer * self,
                              guint16 imm)
{
  gum_arm64_writer_put_instruction (self, 0xd4200000 | (imm << 5));
}

static void
gum_arm64_writer_put_load_store_pair_pre (GumArm64Writer * self,
                                          GumArm64MemPairOperandSize op_size,
                                          guint opc,
                                          gboolean v,
                                          gboolean l,
                                          guint rt,
                                          guint rt2,
                                          guint rn,
                                          gssize pre_increment)
{
  gsize shift = gum_mem_pair_offset_shift (op_size, v);
  gum_arm64_writer_put_instruction (self, (opc << 30) | (5 << 27) |
      (v << 26) | (3 << 23) | (l << 22) |
      (((pre_increment >> shift) & 0x7f) << 15) |
      (rt2 << 10) | (rn << 5) | rt);
}

static void
gum_arm64_writer_put_load_store_pair_post (GumArm64Writer * self,
                                           GumArm64MemPairOperandSize op_size,
                                           guint opc,
                                           gboolean v,
                                           gboolean l,
                                           guint rt,
                                           guint rt2,
                                           guint rn,
                                           gssize post_increment)
{
  gsize shift = gum_mem_pair_offset_shift (op_size, v);
  gum_arm64_writer_put_instruction (self, (opc << 30) | (5 << 27) |
      (v << 26) | (1 << 23) | (l << 22) |
      (((post_increment >> shift) & 0x7f) << 15) |
      (rt2 << 10) | (rn << 5) | rt);
}

static gsize
gum_mem_pair_offset_shift (GumArm64MemPairOperandSize size,
                           gboolean v)
{
  return v ? size + 2 : (size >> 1) + 2;
}

void
gum_arm64_writer_put_instruction (GumArm64Writer * self,
                                  guint32 insn)
{
  *self->code++ = GUINT32_TO_LE (insn);
  self->pc += 4;
}

void
gum_arm64_writer_put_bytes (GumArm64Writer * self,
                            const guint8 * data,
                            guint n)
{
  g_assert (n % 4 == 0);

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;
}

static void
gum_arm64_writer_describe_reg (GumArm64Writer * self,
                               arm64_reg reg,
                               GumArm64RegInfo * ri)
{
  (void) self;

  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_X0);
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_X29)
  {
    ri->meta = GUM_MREG_R29;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_X30)
  {
    ri->meta = GUM_MREG_R30;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_SP)
  {
    ri->meta = GUM_MREG_SP;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_W0);
    ri->is_integer = TRUE;
    ri->width = 32;
    ri->sf = 0x00000000;
  }
  else if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_S0);
    ri->is_integer = FALSE;
    ri->width = 32;
    ri->sf = 0x00000000;
  }
  else if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_D0);
    ri->is_integer = FALSE;
    ri->width = 64;
    ri->sf = 0x00000000;
  }
  else if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_Q0);
    ri->is_integer = FALSE;
    ri->width = 128;
    ri->sf = 0x00000000;
  }
  else if (reg == ARM64_REG_XZR)
  {
    ri->meta = GUM_MREG_ZR;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_WZR)
  {
    ri->meta = GUM_MREG_ZR;
    ri->is_integer = TRUE;
    ri->width = 32;
    ri->sf = 0x00000000;
  }
  else
  {
    g_assert_not_reached ();
  }
  ri->index = ri->meta - GUM_MREG_R0;
}
