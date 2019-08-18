/*
 * Copyright (C) 2014-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummipswriter.h"

#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>

typedef struct _GumMipsLabelRef GumMipsLabelRef;
typedef struct _GumMipsLiteralRef GumMipsLiteralRef;
typedef guint GumMipsMemPairOperandSize;
typedef guint GumMipsMetaReg;
typedef struct _GumMipsRegInfo GumMipsRegInfo;

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

static void gum_mips_writer_put_argument_list_setup (GumMipsWriter * self,
    guint n_args, const GumArgument * args);
static void gum_mips_writer_put_argument_list_setup_va (GumMipsWriter * self,
    guint n_args, va_list args);
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

  writer->id_to_address = g_hash_table_new (NULL, NULL);
  writer->label_refs = g_array_new (FALSE, FALSE, sizeof (GumMipsLabelRef));

  gum_mips_writer_reset (writer, code_address);
}

void
gum_mips_writer_clear (GumMipsWriter * writer)
{
  gum_mips_writer_flush (writer);

  g_hash_table_unref (writer->id_to_address);
  g_array_free (writer->label_refs, TRUE);
}

void
gum_mips_writer_reset (GumMipsWriter * writer,
                       gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  g_hash_table_remove_all (writer->id_to_address);
  g_array_set_size (writer->label_refs, 0);
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
  guint num_refs, ref_index;

  num_refs = self->label_refs->len;
  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumMipsLabelRef * r;
    const guint32 * target_insn;
    gssize distance;
    guint32 insn;

    r = &g_array_index (self->label_refs, GumMipsLabelRef, ref_index);

    target_insn = g_hash_table_lookup (self->id_to_address, r->id);
    if (target_insn == NULL)
      goto error;

    distance = target_insn - r->insn;

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
  g_array_set_size (self->label_refs, 0);

  return TRUE;

error:
  {
    g_array_set_size (self->label_refs, 0);

    return FALSE;
  }
}

gboolean
gum_mips_writer_put_label (GumMipsWriter * self,
                           gconstpointer id)
{
  if (g_hash_table_lookup (self->id_to_address, id) != NULL)
    return FALSE;

  g_hash_table_insert (self->id_to_address, (gpointer) id, self->code);
  return TRUE;
}

static void
gum_mips_writer_add_label_reference_here (GumMipsWriter * self,
                                          gconstpointer id)
{
  GumMipsLabelRef r;

  r.id = id;
  r.insn = self->code;

  g_array_append_val (self->label_refs, r);
}

void
gum_mips_writer_put_call_address_with_arguments (GumMipsWriter * self,
                                                 GumAddress func,
                                                 guint n_args,
                                                 ...)
{
  va_list args;

  va_start (args, n_args);
  gum_mips_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  mips_reg target = MIPS_REG_T9;
  gum_mips_writer_put_la_reg_address (self, target, func);
  gum_mips_writer_put_jalr_reg (self, target);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

void
gum_mips_writer_put_call_address_with_arguments_array (
    GumMipsWriter * self,
    GumAddress func,
    guint n_args,
    const GumArgument * args)
{
  gum_mips_writer_put_argument_list_setup (self, n_args, args);

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
  va_list args;

  va_start (args, n_args);
  gum_mips_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  gum_mips_writer_put_jalr_reg (self, reg);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

void
gum_mips_writer_put_call_reg_with_arguments_array (GumMipsWriter * self,
                                                   mips_reg reg,
                                                   guint n_args,
                                                   const GumArgument * args)
{
  gum_mips_writer_put_argument_list_setup (self, n_args, args);

  gum_mips_writer_put_jalr_reg (self, reg);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

static void
gum_mips_writer_put_argument_list_setup (GumMipsWriter * self,
                                         guint n_args,
                                         const GumArgument * args)
{
  gint arg_index;

  for (arg_index = (gint) n_args - 1; arg_index >= 0; arg_index--)
  {
    const GumArgument * arg = &args[arg_index];
    mips_reg r = MIPS_REG_A0 + arg_index;

#if (GLIB_SIZEOF_VOID_P == 8)
    /*
     * MIPS64 passes 8 arguments in registers
     */
    if (arg_index < 8)
#else
    if (arg_index < 4)
#endif

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
gum_mips_writer_put_argument_list_setup_va (GumMipsWriter * self,
                                            guint n_args,
                                            va_list args)
{
  GumArgument * arg_values;
  guint arg_index;

  arg_values = g_alloca (n_args * sizeof (GumArgument));

  for (arg_index = 0; arg_index != n_args; arg_index++)
  {
    GumArgument * arg = &arg_values[arg_index];

    arg->type = va_arg (args, GumArgType);
    if (arg->type == GUM_ARG_ADDRESS)
      arg->value.address = va_arg (args, GumAddress);
    else if (arg->type == GUM_ARG_REGISTER)
      arg->value.reg = va_arg (args, mips_reg);
    else
      g_assert_not_reached ();
  }

  gum_mips_writer_put_argument_list_setup (self, n_args, arg_values);
}

static void
gum_mips_writer_put_argument_list_teardown (GumMipsWriter * self,
                                            guint n_args)
{

#if (GLIB_SIZEOF_VOID_P == 8)
  /*
   * MIPS64 passes 8 arguments in registers
   */
  if (n_args > 8)
  {
    gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP,
        (n_args - 8) * sizeof (guint64));
  }
#else
  if (n_args > 4)
  {
    gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP,
        (n_args - 4) * sizeof (guint32));
  }
#endif
}

gboolean
gum_mips_writer_can_branch_directly_between (GumAddress from,
                                             GumAddress to)
{
#if (GLIB_SIZEOF_VOID_P == 8)
  gint64 lower_limit = (from & 0xfffffffff0000000);
  gint64 upper_limit = (from & 0xfffffffff0000000) + GUM_INT28_MASK;
#else
  gint64 lower_limit = (from & 0xf0000000);
  gint64 upper_limit = (from & 0xf0000000) + GUM_INT28_MASK;
#endif

  return lower_limit < to && to < upper_limit;
}

gboolean
gum_mips_writer_put_j_address (GumMipsWriter * self,
                               GumAddress address)
{
#if (GLIB_SIZEOF_VOID_P == 8)
  if ((address & 0xfffffffff0000000) !=
      (self->pc & 0xfffffffff0000000) || address % 4 != 0)
  {
    return FALSE;
  }
#else
  if ((address & 0xf0000000) != (self->pc & 0xf0000000) || address % 4 != 0)
  {
    return FALSE;
  }
#endif

  gum_mips_writer_put_instruction (self,
      0x08000000 | ((address & GUM_INT28_MASK) / 4));
  gum_mips_writer_put_nop (self);

  return TRUE;
}

void
gum_mips_writer_put_j_label (GumMipsWriter * self,
                             gconstpointer label_id)
{
  gum_mips_writer_add_label_reference_here (self, label_id);
  gum_mips_writer_put_instruction (self, 0x08000000);
  gum_mips_writer_put_nop (self);
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

void
gum_mips_writer_put_beq_reg_reg_label (GumMipsWriter * self,
                                       mips_reg right_reg,
                                       mips_reg left_reg,
                                       gconstpointer label_id)
{
  GumMipsRegInfo rs, rt;

  gum_mips_writer_describe_reg (self, right_reg, &rs);
  gum_mips_writer_describe_reg (self, left_reg, &rt);

  gum_mips_writer_add_label_reference_here (self, label_id);
  gum_mips_writer_put_instruction (self, 0x01000000 | (rs.index << 21) |
      (rt.index << 16));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_ret (GumMipsWriter * self)
{
  gum_mips_writer_put_jr_reg (self, MIPS_REG_RA);
  gum_mips_writer_put_nop (self);
}

#if (GLIB_SIZEOF_VOID_P == 8)
/*
 * Instruction used to load a 64 bit value from the address in
 * a register + an offset.
 */
void
gum_mips_write_put_ld_reg( GumMipsWriter * self,
                           mips_reg base_reg,
                           mips_reg dest_reg,
                           gushort offset)
{
  GumMipsRegInfo base;
  gum_mips_writer_describe_reg (self, base_reg, &base);
  GumMipsRegInfo rt;
  gum_mips_writer_describe_reg (self, dest_reg, &rt);
  gum_mips_writer_put_instruction (self, 0x68000000 | (base.index << 21) |
    (rt.index << 16) | offset);
}

/*
 * A variant of gum_mips_writer_put_j_address without the trailing nop,
 * used to minimise the size of the trampoline we build.
 */
void
gum_mips_writer_put_j_address2 (GumMipsWriter * self,
                                GumAddress address)
{
  g_assert((address & 0xf0000000) == (self->pc & 0xf0000000));
  g_assert(address % 4 == 0);
  gum_mips_writer_put_instruction (self,
    0x08000000 | ((address & GUM_INT28_MASK) / 4));
}

/* double shift logical left instruction used to shift a 64bit value by a
 * given number of bits (<32). This is used when loading a 64 bit immediate
 * 16 bits at a time when we cannot rely on the value of T9 and we aren't
 * size constrained.
 */
void
gum_mips_writer_put_dsll_reg_reg (GumMipsWriter * self,
                                  mips_reg rt_reg,
                                  mips_reg rd_reg,
                                  guint sa)
{
  GumMipsRegInfo rt;
  gum_mips_writer_describe_reg (self, rt_reg, &rt);
  GumMipsRegInfo rd;
  gum_mips_writer_describe_reg (self, rd_reg, &rd);
  g_assert(sa & 0x1f == sa);

  gum_mips_writer_put_instruction (
    self,
    (rt.index << 16) | (rd.index << 11) | (sa << 6) | 0x38);
}

#endif

void
gum_mips_writer_put_la_reg_address (GumMipsWriter * self,
                                    mips_reg reg,
                                    GumAddress address)
{
#if (GLIB_SIZEOF_VOID_P == 8)
  gum_mips_writer_put_lui_reg_imm(self, reg, (address >> 48));
  gum_mips_writer_put_ori_reg_reg_imm(self, reg, reg, (address >> 32) & 0xffff);
  gum_mips_writer_put_dsll_reg_reg(self, reg, reg, 16);
  gum_mips_writer_put_ori_reg_reg_imm(self, reg, reg, (address >> 16) & 0xffff);
  gum_mips_writer_put_dsll_reg_reg(self, reg, reg, 16);
  gum_mips_writer_put_ori_reg_reg_imm(self, reg, reg, address & 0xffff);
#else
  gum_mips_writer_put_lui_reg_imm (self, reg, address >> 16);
  gum_mips_writer_put_ori_reg_reg_imm (self, reg, reg, address & 0xffff);
#endif
}

/*
 * This builds our minimal sized trampoline. We place our address raw into the
 * instruction stream and jump over it. We use R9 (which points to the start
 * of the function) to reference the immediate in the instruction stream. Note
 * that this load is executed from the branch delay slot. Finally, MIPS64 only
 * supports aligned 64 bit loads and hence we must align the address in the
 * instruction stream accordingly. We can see therefore that the trampoline is
 * one instruction larger if the function is not 64 bit aligned (the
 * instruction stream need only be 32 bit aligned).
 */
#if (GLIB_SIZEOF_VOID_P == 8)
void
gum_mips_writer_put_prologue_trampoline (GumMipsWriter * self,
                                         mips_reg reg,
                                         GumAddress address)
{
  if(self->pc % 8 == 0)
  {
    gum_mips_writer_put_j_address2(self, self->pc + 0x10);
    gum_mips_write_put_ld_reg(self, MIPS_REG_T9, reg, 0x8);
  }
  else
  {
    gum_mips_writer_put_j_address2(self, self->pc + 0x14);
    gum_mips_write_put_ld_reg(self, MIPS_REG_T9, reg, 0xc);
    gum_mips_writer_put_nop (self);

  }
  g_assert(self->pc % 8 == 0);
  gum_mips_writer_put_instruction(self, address >> 32);
  gum_mips_writer_put_instruction(self, address & 0xffffffff);
  gum_mips_writer_put_jr_reg (self, reg);
}
#endif

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

#if (GLIB_SIZEOF_VOID_P == 8)
  /*
   * A number of the other MIPS instructions being written here need to
   * be modified. MIPS64 retained backward compatibility with MIPS32 and
   * introduced new instructions for 64 bit data manipulation. MIPS
   * refers to these as doublewords. The mnemonic for the instruction
   * is different to the original.
   */
  gum_mips_writer_put_instruction (self, 0xdc000000 | (rb.index << 21) |
      (rt.index << 16) | (src_offset & 0xffff));
#else
  gum_mips_writer_put_instruction (self, 0x8c000000 | (rb.index << 21) |
      (rt.index << 16) | (src_offset & 0xffff));
#endif
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

#if (GLIB_SIZEOF_VOID_P == 8)
  /*
   * A number of the other MIPS instructions being written here need to
   * be modified. MIPS64 retained backward compatibility with MIPS32 and
   * introduced new instructions for 64 bit data manipulation. MIPS
   * refers to these as doublewords. The mnemonic for the instruction
   * is different to the original.
   */
  gum_mips_writer_put_instruction (self, 0xfc000000 | (rb.index << 21) |
      (rt.index << 16) | (dest_offset & 0xffff));
#else
  gum_mips_writer_put_instruction (self, 0xac000000 | (rb.index << 21) |
      (rt.index << 16) | (dest_offset & 0xffff));
  #endif
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

#if (GLIB_SIZEOF_VOID_P == 8)
  /*
   * A number of the other MIPS instructions being written here need to
   * be modified. MIPS64 retained backward compatibility with MIPS32 and
   * introduced new instructions for 64 bit data manipulation. MIPS
   * refers to these as doublewords. The mnemonic for the instruction
   * is different to the original.
   */
  gum_mips_writer_put_instruction (self, 0x000000a5 | (rs.index << 21) |
      (rt.index << 16) | (rd.index << 11));
#else
  gum_mips_writer_put_instruction (self, 0x00000021 | (rs.index << 21) |
      (rt.index << 16) | (rd.index << 11));
#endif
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

  g_assert(imm & 0xffff = imm);
#if (GLIB_SIZEOF_VOID_P == 8)
  /*
   * A number of the other MIPS instructions being written here need to
   * be modified. MIPS64 retained backward compatibility with MIPS32 and
   * introduced new instructions for 64 bit data manipulation. MIPS
   * refers to these as doublewords. The mnemonic for the instruction
   * is different to the original.
   */
  gum_mips_writer_put_instruction (self, 0x64000000 | (rs.index << 21) |
      (rt.index << 16) | (imm & 0xffff));
#else
  gum_mips_writer_put_instruction (self, 0x20000000 | (rs.index << 21) |
      (rt.index << 16) | (imm & 0xffff));
#endif
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
      -((gsize) sizeof (gsize)));
  gum_mips_writer_put_sw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
}

void
gum_mips_writer_put_pop_reg (GumMipsWriter * self,
                             mips_reg reg)
{
  gum_mips_writer_put_lw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
  gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP, sizeof (gsize));
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
  if (reg >= MIPS_REG_0 && reg <= MIPS_REG_31)
  {
    ri->meta = GUM_MREG_R0 + (reg - MIPS_REG_0);
    ri->width = (GLIB_SIZEOF_VOID_P * 8);
    ri->index = ri->meta - GUM_MREG_R0;
  }
  else if (reg == MIPS_REG_HI)
  {
    ri->meta = GUM_MREG_HI;
    ri->width = (GLIB_SIZEOF_VOID_P * 8);
    ri->index = -1;
  }
  else if (reg == MIPS_REG_LO)
  {
    ri->meta = GUM_MREG_LO;
    ri->width = (GLIB_SIZEOF_VOID_P * 8);
    ri->index = -1;
  }
  else
  {
    g_assert_not_reached ();
  }
}
