/*
 * Copyright (C) 2010-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarmwriter.h"

#include "gumarmreg.h"
#include "gumlibc.h"
#include "gummemory.h"
#include "gumprocess.h"

typedef struct _GumArmLabelRef GumArmLabelRef;
typedef struct _GumArmLiteralRef GumArmLiteralRef;

struct _GumArmLabelRef
{
  gconstpointer id;
  guint32 * insn;
  guint32 shift;
  guint32 mask;
};

struct _GumArmLiteralRef
{
  guint32 * insn;
  guint32 val;
};

static void gum_arm_writer_reset_refs (GumArmWriter * self);

static gboolean gum_arm_writer_try_commit_label_refs (GumArmWriter * self);
static void gum_arm_writer_maybe_commit_literals (GumArmWriter * self);
static void gum_arm_writer_commit_literals (GumArmWriter * self);

GumArmWriter *
gum_arm_writer_new (gpointer code_address)
{
  GumArmWriter * writer;

  writer = g_slice_new (GumArmWriter);

  gum_arm_writer_init (writer, code_address);

  return writer;
}

GumArmWriter *
gum_arm_writer_ref (GumArmWriter * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_arm_writer_unref (GumArmWriter * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_arm_writer_clear (writer);

    g_slice_free (GumArmWriter, writer);
  }
}

void
gum_arm_writer_init (GumArmWriter * writer,
                     gpointer code_address)
{
  writer->ref_count = 1;

  writer->target_os = gum_process_get_native_os ();

  writer->label_defs = NULL;
  writer->label_refs.data = NULL;
  writer->literal_refs.data = NULL;

  gum_arm_writer_reset (writer, code_address);
}

static gboolean
gum_arm_writer_has_label_defs (GumArmWriter * self)
{
  return self->label_defs != NULL;
}

static gboolean
gum_arm_writer_has_label_refs (GumArmWriter * self)
{
  return self->label_refs.data != NULL;
}

static gboolean
gum_arm_writer_has_literal_refs (GumArmWriter * self)
{
  return self->literal_refs.data != NULL;
}

void
gum_arm_writer_clear (GumArmWriter * writer)
{
  gum_arm_writer_flush (writer);

  if (gum_arm_writer_has_label_defs (writer))
    gum_metal_hash_table_unref (writer->label_defs);

  if (gum_arm_writer_has_label_refs (writer))
    gum_metal_array_free (&writer->label_refs);

  if (gum_arm_writer_has_literal_refs (writer))
    gum_metal_array_free (&writer->literal_refs);
}

void
gum_arm_writer_reset (GumArmWriter * writer,
                      gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  if (gum_arm_writer_has_label_defs (writer))
    gum_metal_hash_table_remove_all (writer->label_defs);

  gum_arm_writer_reset_refs (writer);
}

static void
gum_arm_writer_reset_refs (GumArmWriter * self)
{
  if (gum_arm_writer_has_label_refs (self))
    gum_metal_array_remove_all (&self->label_refs);

  if (gum_arm_writer_has_literal_refs (self))
    gum_metal_array_remove_all (&self->literal_refs);

  self->earliest_literal_insn = NULL;
}

void
gum_arm_writer_set_target_os (GumArmWriter * self,
                              GumOS os)
{
  self->target_os = os;
}

gpointer
gum_arm_writer_cur (GumArmWriter * self)
{
  return self->code;
}

guint
gum_arm_writer_offset (GumArmWriter * self)
{
  return (guint) (self->code - self->base) * sizeof (guint32);
}

void
gum_arm_writer_skip (GumArmWriter * self,
                     guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

gboolean
gum_arm_writer_flush (GumArmWriter * self)
{
  if (!gum_arm_writer_try_commit_label_refs (self))
    goto error;

  gum_arm_writer_commit_literals (self);

  return TRUE;

error:
  {
    gum_arm_writer_reset_refs (self);

    return FALSE;
  }
}

gboolean
gum_arm_writer_put_label (GumArmWriter * self,
                          gconstpointer id)
{
  if (!gum_arm_writer_has_label_defs (self))
    self->label_defs = gum_metal_hash_table_new (NULL, NULL);

  if (gum_metal_hash_table_lookup (self->label_defs, id) != NULL)
    return FALSE;

  gum_metal_hash_table_insert (self->label_defs, (gpointer) id, self->code);

  return TRUE;
}

static void
gum_arm_writer_add_label_reference_here (GumArmWriter * self,
                                         gconstpointer id,
                                         guint32 shift,
                                         guint32 mask)
{
  GumArmLabelRef * r;

  if (!gum_arm_writer_has_label_refs (self))
    gum_metal_array_init (&self->label_refs, sizeof (GumArmLabelRef));

  r = gum_metal_array_append (&self->label_refs);
  r->id = id;
  r->shift = shift;
  r->mask = mask;
  r->insn = self->code;
}

static void
gum_arm_writer_add_literal_reference_here (GumArmWriter * self,
                                           guint32 val)
{
  GumArmLiteralRef * r;

  if (!gum_arm_writer_has_literal_refs (self))
    gum_metal_array_init (&self->literal_refs, sizeof (GumArmLiteralRef));

  r = gum_metal_array_append (&self->literal_refs);
  r->insn = self->code;
  r->val = val;

  if (self->earliest_literal_insn == NULL)
    self->earliest_literal_insn = r->insn;
}

gboolean
gum_arm_writer_put_bcc_imm (GumArmWriter * self,
                            arm_cc cc,
                            GumAddress target)
{
  gint32 distance_in_bytes, distance_in_words;
  guint8 cond;

  distance_in_bytes = target - (self->pc + 8);
  if (!GUM_IS_WITHIN_INT26_RANGE (distance_in_bytes))
    return FALSE;

  gum_arm_cond_describe(cc,  &cond);
  distance_in_words = distance_in_bytes / 4;

  gum_arm_writer_put_instruction (self, 0x0a000000 |
      (cond << 28) |
      (distance_in_words & GUM_INT24_MASK));

  return TRUE;
}

gboolean
gum_arm_writer_put_b_imm (GumArmWriter * self,
                          GumAddress target)
{
  return gum_arm_writer_put_bcc_imm(self, ARM_CC_AL, target);
}

void
gum_arm_writer_put_bxcc_reg (GumArmWriter * self,
                             arm_cc cc,
                             arm_reg reg)
{
  GumArmRegInfo ri;
  guint8 cond;

  gum_arm_reg_describe (reg, &ri);
  gum_arm_cond_describe(cc,  &cond);

  gum_arm_writer_put_instruction (self, 0x012fff10 | (cond << 28) | ri.index);
}

void
gum_arm_writer_put_bx_reg (GumArmWriter * self,
                           arm_reg reg)
{
  gum_arm_writer_put_bxcc_reg(self, ARM_CC_AL, reg);
}

void
gum_arm_writer_put_b_label (GumArmWriter * self,
                            gconstpointer label_id)
{
  gum_arm_writer_add_label_reference_here (self, label_id, 0, GUM_INT24_MASK);
  gum_arm_writer_put_instruction (self, 0xea000000);
}

gboolean
gum_arm_writer_put_ldr_reg_address (GumArmWriter * self,
                                    arm_reg reg,
                                    GumAddress address)
{
  return gum_arm_writer_put_ldr_reg_u32 (self, reg, (guint32) address);
}

gboolean
gum_arm_writer_put_ldr_reg_u32 (GumArmWriter * self,
                                arm_reg reg,
                                guint32 val)
{
  GumArmRegInfo ri;

  gum_arm_reg_describe (reg, &ri);

  gum_arm_writer_add_literal_reference_here (self, val);
  gum_arm_writer_put_instruction (self, 0xe51f0000 | (ri.index << 12));

  return TRUE;
}

void
gum_arm_writer_put_sub_reg_reg_imm (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    arm_reg src_reg,
                                    guint32 imm_val)
{
  GumArmRegInfo rd, rs;

  gum_arm_reg_describe (dst_reg, &rd);
  gum_arm_reg_describe (src_reg, &rs);

  if (src_reg != dst_reg || (imm_val & GUM_INT12_MASK) != 0)
  {
    gum_arm_writer_put_instruction (self, 0xe2400000 | rd.index << 12 |
       rs.index << 16 | (imm_val & GUM_INT12_MASK));
  }
}

void
gum_arm_writer_put_add_reg_reg_imm (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    arm_reg src_reg,
                                    guint32 imm_val)
{
  GumArmRegInfo rd, rs;

  gum_arm_reg_describe (dst_reg, &rd);
  gum_arm_reg_describe (src_reg, &rs);

  if (src_reg != dst_reg || (imm_val & GUM_INT12_MASK) != 0)
  {
    gum_arm_writer_put_instruction (self, 0xe2800000 | rd.index << 12 |
        rs.index << 16 | (imm_val & GUM_INT12_MASK));
  }
}

void
gum_arm_writer_put_ldrcc_reg_reg_offset (GumArmWriter * self,
                                    arm_cc cc,
                                    arm_reg dst_reg,
                                    arm_reg src_reg,
                                    GumArmIndexMode mode,
                                    gsize src_offset)
{
  guint8 cond;
  GumArmRegInfo rd, rs;

  g_assert(src_offset <= 4095);

  gum_arm_cond_describe(cc, &cond);
  gum_arm_reg_describe (dst_reg, &rd);
  gum_arm_reg_describe (src_reg, &rs);

  gum_arm_writer_put_instruction (self, 0x05100000 | (cond << 28) |
      (mode << 23) | rd.index << 12 | rs.index << 16 | src_offset);
}

void
gum_arm_writer_put_ldr_reg_reg_offset (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    arm_reg src_reg,
                                    GumArmIndexMode mode,
                                    gsize src_offset)
{
  gum_arm_writer_put_ldrcc_reg_reg_offset(self, ARM_CC_AL, dst_reg, src_reg,
    mode, src_offset);
}

void
gum_arm_writer_put_nop (GumArmWriter * self)
{
  gum_arm_writer_put_instruction (self, 0xe1a00000);
}

void
gum_arm_writer_put_breakpoint (GumArmWriter * self)
{
  switch (self->target_os)
  {
    case GUM_OS_LINUX:
    case GUM_OS_ANDROID:
    default: /* TODO: handle other OSes */
      gum_arm_writer_put_instruction (self, 0xe7f001f0);
      break;
  }
}

void
gum_arm_writer_put_instruction (GumArmWriter * self,
                                guint32 insn)
{
  *self->code++ = GUINT32_TO_LE (insn);
  self->pc += 4;

  gum_arm_writer_maybe_commit_literals (self);
}

gboolean
gum_arm_writer_put_bytes (GumArmWriter * self,
                          const guint8 * data,
                          guint n)
{
  if (n % 4 != 0)
    return FALSE;

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;

  gum_arm_writer_maybe_commit_literals (self);

  return TRUE;
}

static gboolean
gum_arm_writer_try_commit_label_refs (GumArmWriter * self)
{
  guint num_refs, ref_index;

  if (!gum_arm_writer_has_label_refs (self))
    return TRUE;

  if (!gum_arm_writer_has_label_defs (self))
    return FALSE;

  num_refs = self->label_refs.length;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumArmLabelRef * r;
    const guint32 * target_insn;
    gssize distance;
    guint32 insn;

    r = gum_metal_array_element_at (&self->label_refs, ref_index);

    target_insn = gum_metal_hash_table_lookup (self->label_defs, r->id);
    if (target_insn == NULL)
      return FALSE;

    distance = target_insn - (r->insn + 2);
    distance <<= r->shift;
    if ((distance & (~r->mask)) != 0)
      return FALSE;

    insn = GUINT32_FROM_LE (*r->insn);
    insn |= distance & GUM_INT24_MASK;
    *r->insn = GUINT32_TO_LE (insn);
  }

  gum_metal_array_remove_all (&self->label_refs);

  return TRUE;
}

static void
gum_arm_writer_maybe_commit_literals (GumArmWriter * self)
{
  gsize space_used;
  gconstpointer after_literals = self->code;

  if (self->earliest_literal_insn == NULL)
    return;

  space_used = (self->code - self->earliest_literal_insn) * sizeof (guint32);
  space_used += self->literal_refs.length * sizeof (guint32);
  if (space_used <= 4096)
    return;

  self->earliest_literal_insn = NULL;

  gum_arm_writer_put_b_label (self, after_literals);
  gum_arm_writer_commit_literals (self);
  gum_arm_writer_put_label (self, after_literals);
}

static void
gum_arm_writer_commit_literals (GumArmWriter * self)
{
  guint num_refs, ref_index;
  guint32 * first_slot, * last_slot;

  if (!gum_arm_writer_has_literal_refs (self))
    return;

  num_refs = self->literal_refs.length;
  if (num_refs == 0)
    return;

  first_slot = self->code;
  last_slot = first_slot;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumArmLiteralRef * r;
    guint32 * cur_slot;
    gint64 distance_in_words;
    guint32 insn;

    r = gum_metal_array_element_at (&self->literal_refs, ref_index);

    for (cur_slot = first_slot; cur_slot != last_slot; cur_slot++)
    {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
      if (GUINT32_FROM_LE (*cur_slot) == r->val)
#else
      if (GUINT32_FROM_BE (*cur_slot) == r->val)
#endif
        break;
    }

    if (cur_slot == last_slot)
    {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
      *cur_slot = GUINT32_TO_LE (r->val);
#else
      *cur_slot = GUINT32_TO_BE (r->val);
#endif
      last_slot++;
    }

    distance_in_words = cur_slot - (r->insn + 2);

    insn = GUINT32_FROM_LE (*r->insn);
    insn |= ABS (distance_in_words) * 4;
    if (distance_in_words >= 0)
      insn |= 1 << 23;
    *r->insn = GUINT32_TO_LE (insn);
  }

  self->code = last_slot;
  self->pc += (guint8 *) last_slot - (guint8 *) first_slot;

  gum_metal_array_remove_all (&self->literal_refs);
}

void
gum_arm_writer_put_push_registers (GumArmWriter * self, guint cnt, ...)
{
    va_list regs;
    GumArmRegInfo ri;
    va_start(regs, cnt);
    arm_reg reg;
    gushort mask = 0;

    for (guint idx = 0; idx < cnt; idx++)
    {
        reg = va_arg(regs, arm_reg);
        gum_arm_reg_describe (reg, &ri);
        mask |= 1 << ri.index;
    }

    gum_arm_writer_put_instruction (self, 0xe92d0000 | mask);

    va_end(regs);
}

void gum_arm_write_put_ldmia_registers_by_mask(GumArmWriter * self, arm_reg reg,
    gushort mask)
{
    GumArmRegInfo ri;
    gum_arm_reg_describe (reg, &ri);
    g_assert(((1 << ri.index) & mask) == 0);
    gum_arm_writer_put_instruction (self, 0xe8b00000 | (ri.index << 16) | mask);
}

void
gum_arm_writer_put_pop_registers (GumArmWriter * self, guint cnt, ...)
{
    va_list regs;
    GumArmRegInfo ri;
    va_start(regs, cnt);
    arm_reg reg;
    gushort mask = 0;

    for (guint idx = 0; idx < cnt; idx++)
    {
        reg = va_arg(regs, arm_reg);
        gum_arm_reg_describe (reg, &ri);
        mask |= 1 << ri.index;
    }

    gum_arm_write_put_ldmia_registers_by_mask(self, ARM_REG_SP, mask);

    va_end(regs);
}

void
gum_arm_writer_put_mov_cpsr_to_reg (GumArmWriter * self, arm_reg reg)
{
    GumArmRegInfo ri;
    gum_arm_reg_describe (reg, &ri);
    gum_arm_writer_put_instruction (self, 0xe10f0000 | ri.index << 12);
}

void
gum_arm_writer_put_mov_reg_to_cpsr (GumArmWriter * self, arm_reg reg)
{
    GumArmRegInfo ri;
    gum_arm_reg_describe (reg, &ri);
    gum_arm_writer_put_instruction (self, 0xe129f000 | ri.index);
}

static void
gum_arm_writer_put_argument_list_setup (GumArmWriter * self,
                                        guint n_args,
                                        const GumArgument * args)
{
  gint arg_index;

  for (arg_index = (gint) n_args - 1; arg_index >= 0; arg_index--)
  {
      const GumArgument * arg = &args[arg_index];
      arm_reg dst_reg = ARM_REG_R0 + arg_index;

      if (arg->type == GUM_ARG_ADDRESS)
      {
          gum_arm_writer_put_ldr_reg_address (self, dst_reg,
              arg->value.address);
      }
      else
      {
          arm_reg src_reg = arg->value.reg;
          GumArmRegInfo rs;

          gum_arm_reg_describe (src_reg, &rs);

          if (src_reg != dst_reg)
          {
              gum_arm_writer_put_mov_reg_reg (self, dst_reg, arg->value.reg);
          }
      }
  }
}

static void
gum_arm_writer_put_argument_list_teardown (GumArmWriter * self,
                                             guint n_args)
{
}

gboolean
gum_arm_writer_can_branch_directly_between (GumArmWriter * self,
                                              GumAddress from,
                                              GumAddress to)
{
  gint distance = (gint) to - from;

  return GUM_IS_WITHIN_INT26_RANGE (distance);
}

void
gum_arm_writer_put_call_address_with_arguments_array(GumArmWriter * self,
                                                GumAddress func,
                                                guint n_args,
                                                const GumArgument * args)
{
  gum_arm_writer_put_argument_list_setup (self, n_args, args);

  if (gum_arm_writer_can_branch_directly_between (self, self->pc, func))
  {
    gum_arm_writer_put_bl_imm (self, func);
  }
  else
  {
    arm_reg target = ARM_REG_R0 + n_args;
    gum_arm_writer_put_ldr_reg_address (self, target, func);
    gum_arm_writer_put_blr_reg (self, target);
  }

  gum_arm_writer_put_argument_list_teardown (self, n_args);
}

void
gum_arm_writer_put_mov_reg_reg (GumArmWriter * self,
                                  arm_reg dst_reg,
                                  arm_reg src_reg)
{
    gum_arm_writer_put_add_reg_reg_imm(self, dst_reg, src_reg, 0);
}

gboolean
gum_arm_writer_put_bl_imm (GumArmWriter * self,
                          GumAddress target)
{
  gint32 distance_in_bytes, distance_in_words;

  distance_in_bytes = target - (self->pc + 8);
  if (!GUM_IS_WITHIN_INT26_RANGE (distance_in_bytes))
    return FALSE;

  distance_in_words = distance_in_bytes / 4;

  gum_arm_writer_put_instruction (self, 0xeb000000 |
      (distance_in_words & GUM_INT24_MASK));

  return TRUE;
}

gboolean
gum_arm_writer_put_blr_reg (GumArmWriter * self, arm_reg reg)
{
  GumArmRegInfo ri;

  gum_arm_reg_describe (reg, &ri);
  gum_arm_writer_put_instruction (self, 0xe12fff30 | ri.index);

  return TRUE;
}

void
gum_arm_writer_put_strcc_reg_reg_offset (GumArmWriter * self,
                                         arm_cc cc,
                                         arm_reg src_reg,
                                         arm_reg dst_reg,
                                         GumArmIndexMode mode,
                                         gsize dst_offset)
{
  guint8 cond;
  GumArmRegInfo rs, rd;

  gum_arm_cond_describe(cc, &cond);
  gum_arm_reg_describe (src_reg, &rs);
  gum_arm_reg_describe (dst_reg, &rd);

  g_assert(dst_offset <= 4095);

  gum_arm_writer_put_instruction (self, 0x05000000 |
      (cond << 28) |
      (mode << 23) |
      (rs.index << 12) | rd.index << 16 |
      dst_offset);
}

void
gum_arm_writer_put_str_reg_reg_offset (GumArmWriter * self,
                                         arm_reg src_reg,
                                         arm_reg dst_reg,
                                         GumArmIndexMode mode,
                                         gsize dst_offset)
{

  gum_arm_writer_put_strcc_reg_reg_offset(self, ARM_CC_AL, src_reg,
      dst_reg, mode, dst_offset);
}

void
gum_arm_writer_put_ret (GumArmWriter * self)
{
  gum_arm_writer_put_instruction (self, 0xe1a0f00e);
}

void
gum_arm_writer_put_brk_imm (GumArmWriter * self,
                              guint16 imm)
{
  gum_arm_writer_put_instruction (self, 0xe7f000f0 |
    ((imm >> 4) << 8) | (imm & 0xf));
}

void
gum_arm_writer_put_add_reg_reg_reg (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    arm_reg src_reg1,
                                    arm_reg src_reg2)
{
  GumArmRegInfo rd, rs1, rs2;

  gum_arm_reg_describe (dst_reg, &rd);
  gum_arm_reg_describe (src_reg1, &rs1);
  gum_arm_reg_describe (src_reg2, &rs2);

  gum_arm_writer_put_instruction (self, 0xe0800000 | rd.index << 12 |
      rs1.index << 16 | rs2.index);
}

void
gum_arm_writer_put_sub_reg_reg_reg (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    arm_reg src_reg1,
                                    arm_reg src_reg2)
{
  GumArmRegInfo rd, rs1, rs2;

  gum_arm_reg_describe (dst_reg, &rd);
  gum_arm_reg_describe (src_reg1, &rs1);
  gum_arm_reg_describe (src_reg2, &rs2);

  gum_arm_writer_put_instruction (self, 0xe0400000 | rd.index << 12 |
      rs1.index << 16 | rs2.index);
}

void
gum_arm_writer_put_cmp_reg_imm (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    guint32 imm_val)
{
  GumArmRegInfo rd;

  gum_arm_reg_describe (dst_reg, &rd);

  gum_arm_writer_put_instruction (self, 0xe3500000 | rd.index << 16);
}

void
gum_arm_writer_put_bcc_label (GumArmWriter * self,
  arm_cc cc,
  gconstpointer label_id)
{
  guint8 cond;

  gum_arm_cond_describe(cc, &cond);
  gum_arm_writer_add_label_reference_here (self, label_id, 0, GUM_INT24_MASK);
  gum_arm_writer_put_instruction (self, 0x0a000000 | cond << 28);
}

void
gum_arm_writer_put_str_reg_label (GumArmWriter * self,
  arm_reg reg,
  gconstpointer label_id)
{
  GumArmRegInfo r;

  gum_arm_reg_describe (reg, &r);
  gum_arm_writer_add_label_reference_here (self, label_id, 2, GUM_INT12_MASK);

  gum_arm_writer_put_instruction(self, 0xe58f0000 | (r.index << 12));
}

void
gum_arm_writer_put_ldr_reg_label (GumArmWriter * self,
  arm_reg reg,
  gconstpointer label_id)
{
  GumArmRegInfo r;

  gum_arm_reg_describe (reg, &r);
  gum_arm_writer_add_label_reference_here (self, label_id, 2, GUM_INT12_MASK);

  gum_arm_writer_put_instruction(self, 0xe59f0000 | (r.index << 12));
}