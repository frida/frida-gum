/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarm64writer.h"

#include "gummemory.h"

#include <string.h>

#define GUM_MAX_LABEL_COUNT       100
#define GUM_MAX_LABEL_REF_COUNT   (3 * GUM_MAX_LABEL_COUNT)
#define GUM_MAX_LITERAL_REF_COUNT 100

#define IS_WITHIN_INT19_RANGE(i) \
    (((gint) (i)) >= -262144 && ((gint) (i)) <= 262143)
#define IS_WITHIN_INT28_RANGE(i) \
    (((gint) (i)) >= -134217728 && ((gint) (i)) <= 134217727)

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
    GumArm64Reg reg;
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

  GUM_MREG_FP = 29,
  GUM_MREG_LR = 30,
  GUM_MREG_SP = 31,
  GUM_MREG_ZR = 31,

  GUM_MREG_PC
};

struct _GumArm64RegInfo
{
  GumArm64MetaReg meta;
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
    GumArm64Reg rt, GumArm64Reg rt2, GumArm64Reg rn, gssize pre_increment);
static void gum_arm64_writer_put_load_store_pair_post (GumArm64Writer * self,
    GumArm64MemPairOperandSize op_size, guint opc, gboolean v, gboolean l,
    GumArm64Reg rt, GumArm64Reg rt2, GumArm64Reg rn, gssize post_increment);
static gsize gum_mem_pair_offset_shift (GumArm64MemPairOperandSize size,
    gboolean v);

static void gum_arm64_writer_put_instruction (GumArm64Writer * self,
    guint32 insn);

static void gum_arm64_writer_describe_reg (GumArm64Writer * self,
    GumArm64Reg reg, GumArm64RegInfo * ri);

void
gum_arm64_writer_init (GumArm64Writer * writer,
                       gpointer code_address)
{
  writer->id_to_address =
      gum_new (GumArm64LabelMapping, GUM_MAX_LABEL_COUNT);
  writer->label_refs =
      gum_new (GumArm64LabelRef, GUM_MAX_LABEL_REF_COUNT);
  writer->literal_refs =
      gum_new (GumArm64LiteralRef, GUM_MAX_LITERAL_REF_COUNT);

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

  gum_free (writer->id_to_address);
  gum_free (writer->label_refs);
  gum_free (writer->literal_refs);
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
      gssize distance_in_insns;

      target_address =
          gum_arm64_writer_lookup_address_for_label_id (self, r->id);
      g_assert (target_address != NULL);

      distance_in_insns =
          ((gssize) target_address - (gssize) r->insn) / sizeof (guint32);
      g_assert (IS_WITHIN_INT19_RANGE (distance_in_insns));

      *r->insn |= (distance_in_insns & 0x7ffff) << 5;
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
      insn |= ((distance / 4) & 0x7ffff) << 5;
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
    GumArm64Reg target = GUM_A64REG_X0 + n_args;
    gum_arm64_writer_put_ldr_reg_address (self, target, func);
    gum_arm64_writer_put_blr_reg (self, target);
  }

  gum_arm64_writer_put_argument_list_teardown (self, n_args);
}

void
gum_arm64_writer_put_call_reg_with_arguments (GumArm64Writer * self,
                                              GumArm64Reg reg,
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
      arg->value.reg = va_arg (vl, GumArm64Reg);
    else
      g_assert_not_reached ();
  }

  for (arg_index = n_args - 1; arg_index >= 0; arg_index--)
  {
    GumArm64Argument * arg = &args[arg_index];
    GumArm64Reg r = GUM_A64REG_X0 + arg_index;

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

  return IS_WITHIN_INT28_RANGE (distance);
}

void
gum_arm64_writer_put_b_imm (GumArm64Writer * self,
                            GumAddress address)
{
  gint64 distance = (gint64) address - (gint64) self->pc;

  g_assert (IS_WITHIN_INT28_RANGE (distance));
  g_assert_cmpint (distance % 4, ==, 0);

  gum_arm64_writer_put_instruction (self,
      0x14000000 | ((distance / 4) & 0x3ffffff));
}

void
gum_arm64_writer_put_bl_imm (GumArm64Writer * self,
                             GumAddress address)
{
  gint64 distance = (gint64) address - (gint64) self->pc;

  g_assert (IS_WITHIN_INT28_RANGE (distance));
  g_assert_cmpint (distance % 4, ==, 0);

  gum_arm64_writer_put_instruction (self,
      0x94000000 | ((distance / 4) & 0x3ffffff));
}

void
gum_arm64_writer_put_br_reg (GumArm64Writer * self,
                             GumArm64Reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  gum_arm64_writer_put_instruction (self, 0xd61f0000 | (ri.index << 5));
}

void
gum_arm64_writer_put_blr_reg (GumArm64Writer * self,
                              GumArm64Reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  gum_arm64_writer_put_instruction (self, 0xd63f0000 | (reg << 5));
}

void
gum_arm64_writer_put_ret (GumArm64Writer * self)
{
  gum_arm64_writer_put_instruction (self, 0xd65f0000 | (GUM_A64REG_LR << 5));
}

void
gum_arm64_writer_put_cbz_reg_label (GumArm64Writer * self,
                                    GumArm64Reg reg,
                                    gconstpointer label_id)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, ri.sf | 0x34000000 | ri.index);
}

void
gum_arm64_writer_put_cbnz_reg_label (GumArm64Writer * self,
                                     GumArm64Reg reg,
                                     gconstpointer label_id)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_add_label_reference_here (self, label_id);
  gum_arm64_writer_put_instruction (self, ri.sf | 0x35000000 | ri.index);
}

void
gum_arm64_writer_put_push_cpu_context (GumArm64Writer * self,
                                       GumAddress pc)
{
  /* upper part */
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X27, GUM_A64REG_X28);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X25, GUM_A64REG_X26);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X23, GUM_A64REG_X24);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X21, GUM_A64REG_X22);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X17, GUM_A64REG_X18);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X15, GUM_A64REG_X16);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X13, GUM_A64REG_X14);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X11, GUM_A64REG_X12);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X9, GUM_A64REG_X10);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X7, GUM_A64REG_X8);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X5, GUM_A64REG_X6);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X3, GUM_A64REG_X4);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X1, GUM_A64REG_X2);

  /* SP + X0 */
  gum_arm64_writer_put_add_reg_reg_imm (self, GUM_A64REG_X1,
      GUM_A64REG_SP, 30 * 8);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X1, GUM_A64REG_X0);

  /* alignment padding + PC */
  gum_arm64_writer_put_ldr_reg_address (self, GUM_A64REG_X0, pc);
  gum_arm64_writer_put_push_reg_reg (self, GUM_A64REG_X0, GUM_A64REG_X0);
}

void
gum_arm64_writer_put_pop_cpu_context (GumArm64Writer * self)
{
  /* alignment padding + PC */
  gum_arm64_writer_put_add_reg_reg_imm (self, GUM_A64REG_SP,
      GUM_A64REG_SP, 16);

  /* SP + X0 */
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X1, GUM_A64REG_X0);

  /* the rest */
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X1, GUM_A64REG_X2);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X3, GUM_A64REG_X4);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X5, GUM_A64REG_X6);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X7, GUM_A64REG_X8);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X9, GUM_A64REG_X10);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X11, GUM_A64REG_X12);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X13, GUM_A64REG_X14);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X15, GUM_A64REG_X16);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X17, GUM_A64REG_X18);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X21, GUM_A64REG_X22);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X23, GUM_A64REG_X24);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X25, GUM_A64REG_X26);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_X27, GUM_A64REG_X28);
  gum_arm64_writer_put_pop_reg_reg (self, GUM_A64REG_FP, GUM_A64REG_LR);
}

void
gum_arm64_writer_put_push_reg_reg (GumArm64Writer * self,
                                   GumArm64Reg reg_a,
                                   GumArm64Reg reg_b)
{
  GumArm64RegInfo ra, rb;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);

  g_assert_cmpuint (ra.width, ==, rb.width);

  if (ra.width == 64)
  {
    gum_arm64_writer_put_load_store_pair_pre (self, GUM_MEM_PAIR_OPERAND_64,
        2, FALSE, FALSE, ra.index, rb.index, GUM_A64REG_SP, -16);
  }
  else
  {
    gum_arm64_writer_put_load_store_pair_pre (self, GUM_MEM_PAIR_OPERAND_32,
        0, FALSE, FALSE, ra.index, rb.index, GUM_A64REG_SP, -8);
  }
}

void
gum_arm64_writer_put_pop_reg_reg (GumArm64Writer * self,
                                  GumArm64Reg reg_a,
                                  GumArm64Reg reg_b)
{
  GumArm64RegInfo ra, rb;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);

  g_assert_cmpuint (ra.width, ==, rb.width);

  if (ra.width == 64)
  {
    gum_arm64_writer_put_load_store_pair_post (self, GUM_MEM_PAIR_OPERAND_64,
        2, FALSE, TRUE, ra.index, rb.index, GUM_A64REG_SP, 16);
  }
  else
  {
    gum_arm64_writer_put_load_store_pair_post (self, GUM_MEM_PAIR_OPERAND_32,
        0, FALSE, TRUE, ra.index, rb.index, GUM_A64REG_SP, 8);
  }
}

void
gum_arm64_writer_put_ldr_reg_address (GumArm64Writer * self,
                                      GumArm64Reg reg,
                                      GumAddress address)
{
  gum_arm64_writer_put_ldr_reg_u64 (self, reg, (guint64) address);
}

void
gum_arm64_writer_put_ldr_reg_u64 (GumArm64Writer * self,
                                  GumArm64Reg reg,
                                  guint64 val)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  gum_arm64_writer_add_literal_reference_here (self, val);
  gum_arm64_writer_put_instruction (self, 0x58000000 | ri.index);
}

void
gum_arm64_writer_put_ldr_reg_reg_offset (GumArm64Writer * self,
                                         GumArm64Reg dst_reg,
                                         GumArm64Reg src_reg,
                                         gsize src_offset)
{
  GumArm64RegInfo rd, rs;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rs);

  g_assert_cmpuint (rs.width, ==, 64);

  if (rd.width == 64)
  {
    gum_arm64_writer_put_instruction (self, 0xf9400000 |
        ((guint32) src_offset / 8) << 10 | (rs.index << 5) | rd.index);
  }
  else
  {
    gum_arm64_writer_put_instruction (self, 0xb9400000 |
        ((guint32) src_offset / 4) << 10 | (rs.index << 5) | rd.index);
  }
}

void
gum_arm64_writer_put_str_reg_reg_offset (GumArm64Writer * self,
                                         GumArm64Reg src_reg,
                                         GumArm64Reg dst_reg,
                                         gsize dst_offset)
{
  GumArm64RegInfo rs, rd;

  gum_arm64_writer_describe_reg (self, src_reg, &rs);
  gum_arm64_writer_describe_reg (self, dst_reg, &rd);

  g_assert_cmpuint (rd.width, ==, 64);

  if (rs.width == 64)
  {
    gum_arm64_writer_put_instruction (self, 0xf9000000 |
        ((guint32) dst_offset / 8) << 10 | (rd.index << 5) | rs.index);
  }
  else
  {
    gum_arm64_writer_put_instruction (self, 0xb9000000 |
        ((guint32) dst_offset / 4) << 10 | (rd.index << 5) | rs.index);
  }
}

void
gum_arm64_writer_put_mov_reg_reg (GumArm64Writer * self,
                                  GumArm64Reg dst_reg,
                                  GumArm64Reg src_reg)
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
        (GUM_A64REG_ZR << 5) | (rs.index << 16));
  }
}

void
gum_arm64_writer_put_add_reg_reg_imm (GumArm64Writer * self,
                                      GumArm64Reg dst_reg,
                                      GumArm64Reg left_reg,
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
                                      GumArm64Reg dst_reg,
                                      GumArm64Reg left_reg,
                                      GumArm64Reg right_reg)
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
                                      GumArm64Reg dst_reg,
                                      GumArm64Reg left_reg,
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
                                          GumArm64Reg rt,
                                          GumArm64Reg rt2,
                                          GumArm64Reg rn,
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
                                           GumArm64Reg rt,
                                           GumArm64Reg rt2,
                                           GumArm64Reg rn,
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
gum_arm64_writer_put_bytes (GumArm64Writer * self,
                            const guint8 * data,
                            guint n)
{
  g_assert (n % 4 == 0);

  memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;
}

static void
gum_arm64_writer_put_instruction (GumArm64Writer * self,
                                  guint32 insn)
{
  *self->code++ = GUINT32_TO_LE (insn);
  self->pc += 4;
}

static void
gum_arm64_writer_describe_reg (GumArm64Writer * self,
                               GumArm64Reg reg,
                               GumArm64RegInfo * ri)
{
  (void) self;

  if ((reg >= GUM_A64REG_X0 && reg <= GUM_A64REG_X30) ||
      reg == 31 ||
      (reg >= GUM_A64REG_PC && reg <= GUM_A64REG_NONE))
  {
    ri->meta = GUM_MREG_R0 + reg;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg >= GUM_A64REG_W0 && reg <= GUM_A64REG_W30)
  {
    ri->meta = GUM_MREG_R0 + (reg - GUM_A64REG_W0);
    ri->width = 32;
    ri->sf = 0x00000000;
  }
  else
  {
    g_assert_not_reached ();
  }
  ri->index = ri->meta - GUM_MREG_R0;
}
