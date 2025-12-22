/*
 * Copyright (C) 2014-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumriscvwriter.h"

#include "gumlibc.h"
#include "gummemory.h"

#if GLIB_SIZEOF_VOID_P == 8
# define GUM_RISCV_MAX_ARGS_IN_REGISTERS 8
#else
# define GUM_RISCV_MAX_ARGS_IN_REGISTERS 8
#endif

typedef struct _GumRiscvLabelRef GumRiscvLabelRef;
typedef struct _GumRiscvRegInfo GumRiscvRegInfo;

struct _GumRiscvLabelRef
{
  gconstpointer id;
  guint32 * insn;
  guint type;  /* Instruction type for label resolution */
};

struct _GumRiscvRegInfo
{
  guint index;
};

static void gum_riscv_writer_put_argument_list_setup (GumRiscvWriter * self,
    guint n_args, const GumArgument * args);
static void gum_riscv_writer_put_argument_list_setup_va (GumRiscvWriter * self,
    guint n_args, va_list args);
static void gum_riscv_writer_put_argument_list_teardown (GumRiscvWriter * self,
    guint n_args);

static void gum_riscv_writer_describe_reg (GumRiscvWriter * self, riscv_reg reg,
    GumRiscvRegInfo * ri);

static gboolean gum_riscv_writer_has_label_defs (GumRiscvWriter * self);
static gboolean gum_riscv_writer_has_label_refs (GumRiscvWriter * self);
static void gum_riscv_writer_add_label_reference_here (GumRiscvWriter * self,
    gconstpointer id, guint type);

GumRiscvWriter *
gum_riscv_writer_new (gpointer code_address)
{
  GumRiscvWriter * writer;

  writer = g_slice_new (GumRiscvWriter);

  gum_riscv_writer_init (writer, code_address);

  return writer;
}

GumRiscvWriter *
gum_riscv_writer_ref (GumRiscvWriter * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_riscv_writer_unref (GumRiscvWriter * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_riscv_writer_clear (writer);

    g_slice_free (GumRiscvWriter, writer);
  }
}

void
gum_riscv_writer_init (GumRiscvWriter * writer,
                      gpointer code_address)
{
  writer->ref_count = 1;
  writer->flush_on_destroy = TRUE;

  writer->label_defs = NULL;
  writer->label_refs.data = NULL;

  gum_riscv_writer_reset (writer, code_address);
}

static gboolean
gum_riscv_writer_has_label_defs (GumRiscvWriter * self)
{
  return self->label_defs != NULL;
}

static gboolean
gum_riscv_writer_has_label_refs (GumRiscvWriter * self)
{
  return self->label_refs.data != NULL;
}

void
gum_riscv_writer_reset (GumRiscvWriter * writer,
                       gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  if (gum_riscv_writer_has_label_defs (writer))
    gum_metal_hash_table_remove_all (writer->label_defs);

  if (gum_riscv_writer_has_label_refs (writer))
    gum_metal_array_remove_all (&writer->label_refs);
}

void
gum_riscv_writer_clear (GumRiscvWriter * writer)
{
  if (writer->flush_on_destroy)
    gum_riscv_writer_flush (writer);

  if (gum_riscv_writer_has_label_defs (writer))
    gum_metal_hash_table_unref (writer->label_defs);

  if (gum_riscv_writer_has_label_refs (writer))
    gum_metal_array_free (&writer->label_refs);
}

gpointer
gum_riscv_writer_cur (GumRiscvWriter * self)
{
  return self->code;
}

guint
gum_riscv_writer_offset (GumRiscvWriter * self)
{
  return (guint) ((guint8 *) self->code - (guint8 *) self->base);
}

void
gum_riscv_writer_skip (GumRiscvWriter * self,
                      guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

gboolean
gum_riscv_writer_flush (GumRiscvWriter * self)
{
  guint num_refs, ref_index;

  if (!gum_riscv_writer_has_label_refs (self))
    return TRUE;

  if (!gum_riscv_writer_has_label_defs (self))
    return FALSE;

  num_refs = self->label_refs.length;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumRiscvLabelRef * r;
    const guint32 * target_insn;
    gssize distance;
    gint64 offset_bytes;
    guint32 insn;

    r = gum_metal_array_element_at (&self->label_refs, ref_index);

    target_insn = gum_metal_hash_table_lookup (self->label_defs, r->id);
    if (target_insn == NULL)
      goto error;

    distance = target_insn - r->insn;
    offset_bytes = distance * 4;

    insn = GUINT32_FROM_LE (*r->insn);

    /* RISC-V instruction opcodes:
     * 0x63 = Branch (B-type)
     * 0x6f = JAL (J-type)
     * 0x67 = JALR (I-type)
     */
    if ((insn & 0x7f) == 0x63)
    {
      /* B-type: beq, bne, blt, bge, etc. - 13-bit signed offset */
      if (!GUM_IS_WITHIN_INT13_RANGE (offset_bytes))
        goto error;

      gint32 imm = (gint32) offset_bytes;
      guint32 imm12 = ((imm >> 12) & 0x1) << 31;
      guint32 imm11 = ((imm >> 11) & 0x1) << 7;
      guint32 imm10_5 = ((imm >> 5) & 0x3f) << 25;
      guint32 imm4_1 = ((imm >> 1) & 0xf) << 8;

      insn = (insn & ~0xfe000f80) | imm12 | imm11 | imm10_5 | imm4_1;
    }
    else if ((insn & 0x7f) == 0x6f)
    {
      /* J-type: JAL */
      if (!GUM_IS_WITHIN_INT21_RANGE (offset_bytes))
        goto error;

      gint32 imm = (gint32) offset_bytes;
      guint32 imm20 = ((imm >> 20) & 0x1) << 31;
      guint32 imm19_12 = ((imm >> 12) & 0xff) << 12;
      guint32 imm11 = ((imm >> 11) & 0x1) << 20;
      guint32 imm10_1 = ((imm >> 1) & 0x3ff) << 21;

      insn = (insn & ~0xfff00000) | imm20 | imm19_12 | imm11 | imm10_1;
    }
    else if ((insn & 0x7f) == 0x67)
    {
      /* I-type: JALR - offset is 12-bit signed */
      if (!GUM_IS_WITHIN_INT12_RANGE (offset_bytes))
        goto error;

      gint32 imm = (gint32) offset_bytes & GUM_INT12_MASK;
      insn = (insn & ~0xfff00000) | (imm << 20);
    }
    else
    {
      goto error;
    }

    *r->insn = GUINT32_TO_LE (insn);
  }

  gum_metal_array_remove_all (&self->label_refs);

  return TRUE;

error:
  {
    gum_metal_array_remove_all (&self->label_refs);

    return FALSE;
  }
}

gboolean
gum_riscv_writer_put_label (GumRiscvWriter * self,
                           gconstpointer id)
{
  if (!gum_riscv_writer_has_label_defs (self))
    self->label_defs = gum_metal_hash_table_new (NULL, NULL);

  if (gum_metal_hash_table_lookup (self->label_defs, id) != NULL)
    return FALSE;

  gum_metal_hash_table_insert (self->label_defs, (gpointer) id, self->code);

  return TRUE;
}

static void
gum_riscv_writer_add_label_reference_here (GumRiscvWriter * self,
                                          gconstpointer id,
                                          guint type)
{
  GumRiscvLabelRef * r;

  if (!gum_riscv_writer_has_label_refs (self))
    gum_metal_array_init (&self->label_refs, sizeof (GumRiscvLabelRef));

  r = gum_metal_array_append (&self->label_refs);
  r->id = id;
  r->insn = self->code;
  r->type = type;
}

void
gum_riscv_writer_put_call_address_with_arguments (GumRiscvWriter * self,
                                                 GumAddress func,
                                                 guint n_args,
                                                 ...)
{
  va_list args;

  va_start (args, n_args);
  gum_riscv_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  riscv_reg target = RISCV_REG_T1;
  gum_riscv_writer_put_la_reg_address (self, target, func);
  gum_riscv_writer_put_jalr_reg (self, RISCV_REG_RA, target, 0);

  gum_riscv_writer_put_argument_list_teardown (self, n_args);
}

void
gum_riscv_writer_put_call_address_with_arguments_array (
    GumRiscvWriter * self,
    GumAddress func,
    guint n_args,
    const GumArgument * args)
{
  gum_riscv_writer_put_argument_list_setup (self, n_args, args);

  riscv_reg target = RISCV_REG_T1;
  gum_riscv_writer_put_la_reg_address (self, target, func);
  gum_riscv_writer_put_jalr_reg (self, RISCV_REG_RA, target, 0);

  gum_riscv_writer_put_argument_list_teardown (self, n_args);
}

void
gum_riscv_writer_put_call_reg_with_arguments (GumRiscvWriter * self,
                                             riscv_reg reg,
                                             guint n_args,
                                             ...)
{
  va_list args;

  va_start (args, n_args);
  gum_riscv_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  gum_riscv_writer_put_jalr_reg (self, RISCV_REG_RA, reg, 0);

  gum_riscv_writer_put_argument_list_teardown (self, n_args);
}

void
gum_riscv_writer_put_call_reg_with_arguments_array (GumRiscvWriter * self,
                                                   riscv_reg reg,
                                                   guint n_args,
                                                   const GumArgument * args)
{
  gum_riscv_writer_put_argument_list_setup (self, n_args, args);

  gum_riscv_writer_put_jalr_reg (self, RISCV_REG_RA, reg, 0);

  gum_riscv_writer_put_argument_list_teardown (self, n_args);
}

static void
gum_riscv_writer_put_argument_list_setup (GumRiscvWriter * self,
                                         guint n_args,
                                         const GumArgument * args)
{
  gint arg_index;

  for (arg_index = (gint) n_args - 1; arg_index >= 0; arg_index--)
  {
    const GumArgument * arg = &args[arg_index];
    riscv_reg r = RISCV_REG_A0 + arg_index;

    if (arg_index < GUM_RISCV_MAX_ARGS_IN_REGISTERS)
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_riscv_writer_put_la_reg_address (self, r, arg->value.address);
      }
      else
      {
        if (arg->value.reg != r)
          gum_riscv_writer_put_mv_reg_reg (self, r, arg->value.reg);
      }
    }
    else
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_riscv_writer_put_la_reg_address (self, RISCV_REG_T0,
            arg->value.address);
        gum_riscv_writer_put_push_reg (self, RISCV_REG_T0);
      }
      else
      {
        gum_riscv_writer_put_push_reg (self, arg->value.reg);
      }
    }
  }
}

static void
gum_riscv_writer_put_argument_list_setup_va (GumRiscvWriter * self,
                                            guint n_args,
                                            va_list args)
{
  GumArgument * arg_values;
  guint arg_index;

  arg_values = g_newa (GumArgument, n_args);

  for (arg_index = 0; arg_index != n_args; arg_index++)
  {
    GumArgument * arg = &arg_values[arg_index];

    arg->type = va_arg (args, GumArgType);
    if (arg->type == GUM_ARG_ADDRESS)
      arg->value.address = va_arg (args, GumAddress);
    else if (arg->type == GUM_ARG_REGISTER)
      arg->value.reg = va_arg (args, riscv_reg);
    else
      g_assert_not_reached ();
  }

  gum_riscv_writer_put_argument_list_setup (self, n_args, arg_values);
}

static void
gum_riscv_writer_put_argument_list_teardown (GumRiscvWriter * self,
                                            guint n_args)
{
  if (n_args > GUM_RISCV_MAX_ARGS_IN_REGISTERS)
  {
    guint stack_args = n_args - GUM_RISCV_MAX_ARGS_IN_REGISTERS;
    gum_riscv_writer_put_addi_reg_reg_imm (self, RISCV_REG_SP, RISCV_REG_SP,
        stack_args * GLIB_SIZEOF_VOID_P);
  }
}

gboolean
gum_riscv_writer_can_branch_directly_between (GumAddress from,
                                             GumAddress to)
{
  gint64 distance = (gint64) to - (gint64) from;
  return GUM_IS_WITHIN_INT21_RANGE (distance);
}

gboolean
gum_riscv_writer_put_jal_imm (GumRiscvWriter * self,
                             GumAddress address)
{
  gint64 offset = (gint64) address - (gint64) self->pc;

  if (!GUM_IS_WITHIN_INT21_RANGE (offset))
    return FALSE;

  gint32 imm = (gint32) offset;
  guint32 imm20 = ((imm >> 20) & 0x1) << 31;
  guint32 imm19_12 = ((imm >> 12) & 0xff) << 12;
  guint32 imm11 = ((imm >> 11) & 0x1) << 20;
  guint32 imm10_1 = ((imm >> 1) & 0x3ff) << 21;

  guint32 insn = 0x6f | imm20 | imm19_12 | imm11 | imm10_1;
  gum_riscv_writer_put_instruction (self, insn);

  return TRUE;
}

void
gum_riscv_writer_put_jal_label (GumRiscvWriter * self,
                                gconstpointer label_id)
{
  gum_riscv_writer_add_label_reference_here (self, label_id, 0x6f);
  gum_riscv_writer_put_instruction (self, 0x6f);
}

void
gum_riscv_writer_put_jalr_reg (GumRiscvWriter * self,
                              riscv_reg rd,
                              riscv_reg rs,
                              gint32 offset)
{
  GumRiscvRegInfo rd_info, rs_info;

  gum_riscv_writer_describe_reg (self, rd, &rd_info);
  gum_riscv_writer_describe_reg (self, rs, &rs_info);

  g_assert (GUM_IS_WITHIN_INT12_RANGE (offset));

  guint32 imm = (guint32) offset & GUM_INT12_MASK;
  guint32 insn = 0x67 | (rd_info.index << 7) | (rs_info.index << 15) |
      (imm << 20);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_ret (GumRiscvWriter * self)
{
  gum_riscv_writer_put_jalr_reg (self, RISCV_REG_ZERO, RISCV_REG_RA, 0);
}

void
gum_riscv_writer_put_la_reg_address (GumRiscvWriter * self,
                                    riscv_reg reg,
                                    GumAddress address)
{
#if GLIB_SIZEOF_VOID_P == 8
  /*
   * Load 64-bit address on RV64.
   *
   * LUI loads a 20-bit immediate into bits [31:12] and SIGN-EXTENDS to 64 bits.
   * ADDI adds a 12-bit sign-extended immediate.
   *
   * LUI+ADDI can only load addresses where the result of LUI (after sign
   * extension) plus ADDI equals the target. This works when:
   * - For positive targets (bits 63:32 = 0): hi20 must be < 0x80000
   * - For negative targets (bits 63:32 = all 1s): hi20 must be >= 0x80000
   *
   * For addresses outside this range (like 0x0000003f_xxxxxxxx), we need
   * a longer sequence using shifts.
   */
  gint32 lo12 = ((gint32) address) & 0xfff;
  gint32 hi20;
  gboolean use_short_sequence;

  /* Sign-extend lo12 for compensation in ADDI */
  if (lo12 >= 0x800)
    lo12 -= 0x1000;
  hi20 = (gint32) (((gint64) address - lo12) >> 12);

  /*
   * Check if LUI+ADDI will produce the correct result:
   * - If address has bits 63:32 = 0, we need hi20 in [0, 0x7ffff]
   * - If address has bits 63:32 = all 1s, we need hi20 in [-0x80000, -1]
   * - Otherwise, we need the full 64-bit sequence
   */
  if ((address >> 32) == 0)
  {
    /* Positive address: hi20 must not have bit 19 set (would cause negative sign extension) */
    use_short_sequence = (hi20 >= 0 && hi20 < 0x80000);
  }
  else if ((address >> 32) == G_GUINT64_CONSTANT (0xffffffff))
  {
    /* Negative address: hi20 must have bit 19 set */
    use_short_sequence = (hi20 < 0 || hi20 >= 0x80000);
  }
  else
  {
    /* Address has non-trivial upper 32 bits, need full sequence */
    use_short_sequence = FALSE;
  }

  if (use_short_sequence)
  {
    gum_riscv_writer_put_lui_reg_imm (self, reg, hi20);
    if (lo12 != 0)
      gum_riscv_writer_put_addi_reg_reg_imm (self, reg, reg, lo12);
  }
  else
  {
    /*
     * Full 64-bit address loading sequence.
     * We build the address in chunks using shifts.
     *
     * Strategy: Split into 4 parts of varying sizes to minimize instructions.
     * Use: LUI (20 bits) + ADDIW (12 bits) + SLLI + ADDI + SLLI + ADDI
     */
    guint64 addr = address;

    /* Extract parts */
    gint32 lo12 = addr & 0xfff;
    if (lo12 >= 0x800)
      lo12 -= 0x1000;
    addr -= lo12;

    gint32 mid12 = (addr >> 12) & 0xfff;
    if (mid12 >= 0x800)
      mid12 -= 0x1000;
    addr -= ((gint64) mid12) << 12;

    gint32 mid20 = (addr >> 24) & 0xfff;
    if (mid20 >= 0x800)
      mid20 -= 0x1000;
    addr -= ((gint64) mid20) << 24;

    gint32 hi20 = (addr >> 36) & 0xfffff;
    if (hi20 >= 0x80000)
      hi20 -= 0x100000;

    /* LUI loads bits [31:12] and sign-extends */
    gum_riscv_writer_put_lui_reg_imm (self, reg, hi20);
    if (mid20 != 0)
      gum_riscv_writer_put_addi_reg_reg_imm (self, reg, reg, mid20);

    /* Shift left 12 bits */
    gum_riscv_writer_put_slli_reg_reg_imm (self, reg, reg, 12);
    if (mid12 != 0)
      gum_riscv_writer_put_addi_reg_reg_imm (self, reg, reg, mid12);

    /* Shift left 12 bits */
    gum_riscv_writer_put_slli_reg_reg_imm (self, reg, reg, 12);
    if (lo12 != 0)
      gum_riscv_writer_put_addi_reg_reg_imm (self, reg, reg, lo12);
  }
#else
  /* Load 32-bit address on RV32: use LUI + ADDI */
  gint32 lo12 = ((gint32) address) & 0xfff;
  /* Sign-extend lo12 for compensation */
  if (lo12 >= 0x800)
    lo12 -= 0x1000;
  gint32 hi20 = (((gint32) address) - lo12) >> 12;

  gum_riscv_writer_put_lui_reg_imm (self, reg, hi20);
  if (lo12 != 0)
    gum_riscv_writer_put_addi_reg_reg_imm (self, reg, reg, lo12);
#endif
}

void
gum_riscv_writer_put_lui_reg_imm (GumRiscvWriter * self,
                                 riscv_reg reg,
                                 gint32 imm)
{
  GumRiscvRegInfo ri;

  gum_riscv_writer_describe_reg (self, reg, &ri);

  /*
   * LUI instruction encoding:
   * [31:12] = imm[31:12]
   * [11:7]  = rd
   * [6:0]   = opcode (0x37)
   *
   * The immediate is placed in the upper 20 bits of the instruction,
   * and the hardware places it in bits [31:12] of the destination register.
   */
  guint32 imm20 = imm & 0xfffff;
  guint32 insn = 0x37 | (ri.index << 7) | (imm20 << 12);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_auipc_reg_imm (GumRiscvWriter * self,
                                   riscv_reg reg,
                                   gint32 imm)
{
  GumRiscvRegInfo ri;

  gum_riscv_writer_describe_reg (self, reg, &ri);

  /*
   * AUIPC instruction encoding:
   * [31:12] = imm[31:12]
   * [11:7]  = rd
   * [6:0]   = opcode (0x17)
   *
   * AUIPC forms a 32-bit offset from the 20-bit U-immediate, filling
   * in the lowest 12 bits with zeros, adds this offset to the pc,
   * then places the result in register rd.
   */
  guint32 imm20 = imm & 0xfffff;
  guint32 insn = 0x17 | (ri.index << 7) | (imm20 << 12);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_slli_reg_reg_imm (GumRiscvWriter * self,
                                      riscv_reg dst_reg,
                                      riscv_reg src_reg,
                                      guint8 shamt)
{
  GumRiscvRegInfo rd, rs;

  gum_riscv_writer_describe_reg (self, dst_reg, &rd);
  gum_riscv_writer_describe_reg (self, src_reg, &rs);

  /*
   * SLLI instruction encoding (RV64I):
   * [31:26] = 0x00
   * [25:20] = shamt[5:0]
   * [19:15] = rs1
   * [14:12] = funct3 (0x1)
   * [11:7]  = rd
   * [6:0]   = opcode (0x13)
   */
#if GLIB_SIZEOF_VOID_P == 8
  g_assert (shamt < 64);
#else
  g_assert (shamt < 32);
#endif

  guint32 insn = 0x13 | (rd.index << 7) | (0x1 << 12) | (rs.index << 15) |
      ((guint32) shamt << 20);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_addi_reg_reg_imm (GumRiscvWriter * self,
                                      riscv_reg dst_reg,
                                      riscv_reg src_reg,
                                      gint32 imm)
{
  GumRiscvRegInfo rd, rs;

  gum_riscv_writer_describe_reg (self, dst_reg, &rd);
  gum_riscv_writer_describe_reg (self, src_reg, &rs);

  g_assert (GUM_IS_WITHIN_INT12_RANGE (imm));

  guint32 imm12 = (guint32) imm & GUM_INT12_MASK;
  guint32 insn = 0x13 | (rd.index << 7) | (rs.index << 15) | (imm12 << 20);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_add_reg_reg_reg (GumRiscvWriter * self,
                                      riscv_reg dst_reg,
                                      riscv_reg src_reg1,
                                      riscv_reg src_reg2)
{
  GumRiscvRegInfo rd, rs1, rs2;

  gum_riscv_writer_describe_reg (self, dst_reg, &rd);
  gum_riscv_writer_describe_reg (self, src_reg1, &rs1);
  gum_riscv_writer_describe_reg (self, src_reg2, &rs2);

  guint32 insn = 0x33 | (rd.index << 7) | (rs1.index << 15) | (rs2.index << 20);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_ld_reg_reg_offset (GumRiscvWriter * self,
                                       riscv_reg dst_reg,
                                       riscv_reg src_reg,
                                       gint32 offset)
{
  GumRiscvRegInfo rd, rs;

  gum_riscv_writer_describe_reg (self, dst_reg, &rd);
  gum_riscv_writer_describe_reg (self, src_reg, &rs);

  g_assert (GUM_IS_WITHIN_INT12_RANGE (offset));

  guint32 imm12 = (guint32) offset & GUM_INT12_MASK;
  guint32 insn = 0x3003 | (rd.index << 7) | (rs.index << 15) | (imm12 << 20);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_lw_reg_reg_offset (GumRiscvWriter * self,
                                       riscv_reg dst_reg,
                                       riscv_reg src_reg,
                                       gint32 offset)
{
  GumRiscvRegInfo rd, rs;

  gum_riscv_writer_describe_reg (self, dst_reg, &rd);
  gum_riscv_writer_describe_reg (self, src_reg, &rs);

  g_assert (GUM_IS_WITHIN_INT12_RANGE (offset));

  guint32 imm12 = (guint32) offset & GUM_INT12_MASK;
  guint32 insn = 0x2003 | (rd.index << 7) | (rs.index << 15) | (imm12 << 20);

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_sd_reg_reg_offset (GumRiscvWriter * self,
                                       riscv_reg src_reg,
                                       riscv_reg dst_reg,
                                       gint32 offset)
{
  GumRiscvRegInfo rs, rd;

  gum_riscv_writer_describe_reg (self, src_reg, &rs);
  gum_riscv_writer_describe_reg (self, dst_reg, &rd);

  g_assert (GUM_IS_WITHIN_INT12_RANGE (offset));

  guint32 imm12 = (guint32) offset & GUM_INT12_MASK;
  guint32 imm11_5 = (imm12 >> 5) << 25;
  guint32 imm4_0 = (imm12 & 0x1f) << 7;
  guint32 insn = 0x3023 | (rs.index << 20) | (rd.index << 15) | imm11_5 | imm4_0;

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_sw_reg_reg_offset (GumRiscvWriter * self,
                                       riscv_reg src_reg,
                                       riscv_reg dst_reg,
                                       gint32 offset)
{
  GumRiscvRegInfo rs, rd;

  gum_riscv_writer_describe_reg (self, src_reg, &rs);
  gum_riscv_writer_describe_reg (self, dst_reg, &rd);

  g_assert (GUM_IS_WITHIN_INT12_RANGE (offset));

  guint32 imm12 = (guint32) offset & GUM_INT12_MASK;
  guint32 imm11_5 = (imm12 >> 5) << 25;
  guint32 imm4_0 = (imm12 & 0x1f) << 7;
  guint32 insn = 0x2023 | (rs.index << 20) | (rd.index << 15) | imm11_5 | imm4_0;

  gum_riscv_writer_put_instruction (self, insn);
}

void
gum_riscv_writer_put_mv_reg_reg (GumRiscvWriter * self,
                                 riscv_reg dst_reg,
                                 riscv_reg src_reg)
{
  /* MV is ADDI with zero immediate */
  gum_riscv_writer_put_addi_reg_reg_imm (self, dst_reg, src_reg, 0);
}

void
gum_riscv_writer_put_push_reg (GumRiscvWriter * self,
                              riscv_reg reg)
{
  gum_riscv_writer_put_addi_reg_reg_imm (self, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
#if GLIB_SIZEOF_VOID_P == 8
  gum_riscv_writer_put_sd_reg_reg_offset (self, reg, RISCV_REG_SP, 0);
#else
  gum_riscv_writer_put_sw_reg_reg_offset (self, reg, RISCV_REG_SP, 0);
#endif
}

void
gum_riscv_writer_put_pop_reg (GumRiscvWriter * self,
                             riscv_reg reg)
{
#if GLIB_SIZEOF_VOID_P == 8
  gum_riscv_writer_put_ld_reg_reg_offset (self, reg, RISCV_REG_SP, 0);
#else
  gum_riscv_writer_put_lw_reg_reg_offset (self, reg, RISCV_REG_SP, 0);
#endif
  gum_riscv_writer_put_addi_reg_reg_imm (self, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
}

void
gum_riscv_writer_put_nop (GumRiscvWriter * self)
{
  gum_riscv_writer_put_instruction (self, 0x00000013); /* ADDI x0, x0, 0 */
}

void
gum_riscv_writer_put_instruction (GumRiscvWriter * self,
                                 guint32 insn)
{
  *self->code++ = GUINT32_TO_LE (insn);
  self->pc += 4;
}

gboolean
gum_riscv_writer_put_bytes (GumRiscvWriter * self,
                           const guint8 * data,
                           guint n)
{
  /*
   * RISC-V instructions can be:
   * - 4 bytes (standard 32-bit instructions)
   * - 2 bytes (compressed instructions with C extension)
   *
   * We accept any size that is a multiple of 2 (minimum instruction size).
   */
  if (n % 2 != 0)
    return FALSE;

  gum_memcpy (self->code, data, n);
  self->code = (guint32 *) (((guint8 *) self->code) + n);
  self->pc += n;

  return TRUE;
}

static void
gum_riscv_writer_describe_reg (GumRiscvWriter * self,
                              riscv_reg reg,
                              GumRiscvRegInfo * ri)
{
  /*
   * In Capstone's RISC-V header, ABI names (RISCV_REG_ZERO, RISCV_REG_RA, etc.)
   * are aliases for RISCV_REG_X0 through RISCV_REG_X31, so they have the same
   * numeric values. We can simply compute the index by subtracting RISCV_REG_X0.
   */
  g_assert (reg >= RISCV_REG_X0 && reg <= RISCV_REG_X31);
  ri->index = reg - RISCV_REG_X0;
}
