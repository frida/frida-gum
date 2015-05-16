/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthumbwriter.h"

#include "gummemory.h"
#include "gumprocess.h"

#include <string.h>

#define GUM_MAX_LABEL_COUNT       100
#define GUM_MAX_LREF_COUNT        (3 * GUM_MAX_LABEL_COUNT)
#define GUM_MAX_LITERAL_REF_COUNT 100

#define IS_WITHIN_INT8_RANGE(i) \
    (((gint) (i)) >= -128 && ((gint) (i)) <= 127)
#define IS_WITHIN_UINT7_RANGE(i) \
    (((gint) (i)) >= 0 && ((gint) (i)) <= 127)

typedef struct _GumThumbArgument GumThumbArgument;

struct _GumThumbLabelMapping
{
  gconstpointer id;
  gpointer address;
};

struct _GumThumbLabelRef
{
  gconstpointer id;
  guint16 * insn;
};

struct _GumThumbLiteralRef
{
  guint16 * insn;
  guint32 val;
};

struct _GumThumbArgument
{
  GumArgType type;

  union
  {
    GumArmReg reg;
    GumAddress address;
  } value;
};

static guint8 * gum_thumb_writer_lookup_address_for_label_id (
    GumThumbWriter * self, gconstpointer id);
static void gum_thumb_writer_put_argument_list_setup (GumThumbWriter * self,
    guint n_args, va_list vl);
static void gum_thumb_writer_put_argument_list_teardown (GumThumbWriter * self,
    guint n_args);
static guint16 gum_thumb_writer_make_ldr_or_str_reg_reg_offset (
    GumArmReg left_reg, GumArmReg right_reg, guint8 right_offset);

void
gum_thumb_writer_init (GumThumbWriter * writer,
                       gpointer code_address)
{
  writer->id_to_address = gum_new (GumThumbLabelMapping, GUM_MAX_LABEL_COUNT);
  writer->label_refs = gum_new (GumThumbLabelRef, GUM_MAX_LREF_COUNT);
  writer->literal_refs = gum_new (GumThumbLiteralRef, GUM_MAX_LITERAL_REF_COUNT);

  gum_thumb_writer_reset (writer, code_address);
}

void
gum_thumb_writer_reset (GumThumbWriter * writer,
                        gpointer code_address)
{
  writer->target_os = gum_process_get_native_os ();

  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  writer->id_to_address_len = 0;
  writer->label_refs_len = 0;
  writer->literal_refs_len = 0;
}

void
gum_thumb_writer_free (GumThumbWriter * writer)
{
  gum_thumb_writer_flush (writer);

  gum_free (writer->id_to_address);
  gum_free (writer->label_refs);
  gum_free (writer->literal_refs);
}

void
gum_thumb_writer_set_target_os (GumThumbWriter * self,
                                GumOS os)
{
  self->target_os = os;
}

gpointer
gum_thumb_writer_cur (GumThumbWriter * self)
{
  return self->code;
}

guint
gum_thumb_writer_offset (GumThumbWriter * self)
{
  return (guint) (self->code - self->base) * sizeof (guint16);
}

void
gum_thumb_writer_skip (GumThumbWriter * self,
                       guint n_bytes)
{
  self->code = (guint16 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

void
gum_thumb_writer_flush (GumThumbWriter * self)
{
  if (self->label_refs_len > 0)
  {
    guint label_idx;

    for (label_idx = 0; label_idx != self->label_refs_len; label_idx++)
    {
      GumThumbLabelRef * r = &self->label_refs[label_idx];
      gpointer target_address;
      gssize distance;
      guint16 insn;

      target_address =
          gum_thumb_writer_lookup_address_for_label_id (self, r->id);
      g_assert (target_address != NULL);

      distance = ((gssize) target_address - (gssize) (r->insn + 2)) / 2;

      insn = GUINT16_FROM_LE (*r->insn);
      if ((insn & 0xf000) == 0xd000)
      {
        g_assert (IS_WITHIN_INT8_RANGE (distance));

        insn |= distance & 0x00ff;
      }
      else
      {
        guint16 i, imm5;

        g_assert (IS_WITHIN_UINT7_RANGE (distance));

        i = (distance >> 5) & 1;
        imm5 = distance & 0x001f;

        insn |= (i << 9) | (imm5 << 3);
      }

      *r->insn = GUINT16_TO_LE (insn);
    }
    self->label_refs_len = 0;
  }

  if (self->literal_refs_len > 0)
  {
    guint32 * first_slot, * last_slot;
    guint ref_idx;

    if ((GPOINTER_TO_SIZE (self->code) & 2) == 0)
      first_slot = (guint32 *) (self->code + 0);
    else
      first_slot = (guint32 *) (self->code + 1);
    last_slot = first_slot;

    for (ref_idx = 0; ref_idx != self->literal_refs_len; ref_idx++)
    {
      GumThumbLiteralRef * r;
      guint32 * cur_slot;
      gsize distance_in_words;

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

      distance_in_words = cur_slot - (guint32 *) (r->insn + 1);
      *r->insn = GUINT16_TO_LE (GUINT16_FROM_LE (*r->insn) | distance_in_words);
    }
    self->literal_refs_len = 0;

    self->code = (guint16 *) last_slot;
    self->pc += (guint8 *) last_slot - (guint8 *) first_slot;
  }
}

static guint8 *
gum_thumb_writer_lookup_address_for_label_id (GumThumbWriter * self,
                                              gconstpointer id)
{
  guint i;

  for (i = 0; i < self->id_to_address_len; i++)
  {
    GumThumbLabelMapping * map = &self->id_to_address[i];
    if (map->id == id)
      return map->address;
  }

  return NULL;
}

static void
gum_thumb_writer_add_address_for_label_id (GumThumbWriter * self,
                                           gconstpointer id,
                                           gpointer address)
{
  GumThumbLabelMapping * map = &self->id_to_address[self->id_to_address_len++];

  g_assert_cmpuint (self->id_to_address_len, <=, GUM_MAX_LABEL_COUNT);

  map->id = id;
  map->address = address;
}

void
gum_thumb_writer_put_label (GumThumbWriter * self,
                            gconstpointer id)
{
  g_assert (gum_thumb_writer_lookup_address_for_label_id (self, id) == NULL);
  gum_thumb_writer_add_address_for_label_id (self, id, self->code);
}

static void
gum_thumb_writer_add_label_reference_here (GumThumbWriter * self,
                                           gconstpointer id)
{
  GumThumbLabelRef * r = &self->label_refs[self->label_refs_len++];

  g_assert_cmpuint (self->label_refs_len, <=, GUM_MAX_LREF_COUNT);

  r->id = id;
  r->insn = self->code;
}

static void
gum_thumb_writer_add_literal_reference_here (GumThumbWriter * self,
                                             guint32 val)
{
  GumThumbLiteralRef * r = &self->literal_refs[self->literal_refs_len++];

  g_assert_cmpuint (self->literal_refs_len, <=, GUM_MAX_LITERAL_REF_COUNT);

  r->insn = self->code;
  r->val = val;
}

void
gum_thumb_writer_put_call_address_with_arguments (GumThumbWriter * self,
                                                  GumAddress func,
                                                  guint n_args,
                                                  ...)
{
  va_list vl;

  va_start (vl, n_args);
  gum_thumb_writer_put_argument_list_setup (self, n_args, vl);
  va_end (vl);

  gum_thumb_writer_put_push_regs (self, 1, GUM_AREG_R0);
  gum_thumb_writer_put_ldr_reg_address (self, GUM_AREG_R0, func);
  gum_thumb_writer_put_mov_reg_reg (self, GUM_AREG_LR, GUM_AREG_R0);
  gum_thumb_writer_put_pop_regs (self, 1, GUM_AREG_R0);
  gum_thumb_writer_put_blx_reg (self, GUM_AREG_LR);

  gum_thumb_writer_put_argument_list_teardown (self, n_args);
}

void
gum_thumb_writer_put_call_reg_with_arguments (GumThumbWriter * self,
                                              GumArmReg reg,
                                              guint n_args,
                                              ...)
{
  va_list vl;

  va_start (vl, n_args);
  gum_thumb_writer_put_argument_list_setup (self, n_args, vl);
  va_end (vl);

  gum_thumb_writer_put_blx_reg (self, reg);

  gum_thumb_writer_put_argument_list_teardown (self, n_args);
}

static void
gum_thumb_writer_put_argument_list_setup (GumThumbWriter * self,
                                          guint n_args,
                                          va_list vl)
{
  GumThumbArgument * args;
  gint arg_index;

  args = g_alloca (n_args * sizeof (GumThumbArgument));

  for (arg_index = 0; arg_index != (gint) n_args; arg_index++)
  {
    GumThumbArgument * arg = &args[arg_index];

    arg->type = va_arg (vl, GumArgType);
    if (arg->type == GUM_ARG_ADDRESS)
      arg->value.address = va_arg (vl, GumAddress);
    else if (arg->type == GUM_ARG_REGISTER)
      arg->value.reg = va_arg (vl, GumArmReg);
    else
      g_assert_not_reached ();
  }

  for (arg_index = n_args - 1; arg_index >= 0; arg_index--)
  {
    GumThumbArgument * arg = &args[arg_index];
    GumArmReg r = GUM_AREG_R0 + arg_index;

    if (arg_index < 4)
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_thumb_writer_put_ldr_reg_address (self, r, arg->value.address);
      }
      else
      {
        if (arg->value.reg != r)
          gum_thumb_writer_put_mov_reg_reg (self, r, arg->value.reg);
      }
    }
    else
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_thumb_writer_put_ldr_reg_address (self, GUM_AREG_R0, arg->value.address);
        gum_thumb_writer_put_push_regs (self, 1, GUM_AREG_R0);
      }
      else
      {
        gum_thumb_writer_put_push_regs (self, 1, arg->value.reg);
      }
    }
  }
}

static void
gum_thumb_writer_put_argument_list_teardown (GumThumbWriter * self,
                                             guint n_args)
{
  (void) self;
  (void) n_args;
}

void
gum_thumb_writer_put_bx_reg (GumThumbWriter * self,
                             GumArmReg reg)
{
  gum_thumb_writer_put_instruction (self, 0x4700 | (reg << 3));
}

void
gum_thumb_writer_put_blx_reg (GumThumbWriter * self,
                              GumArmReg reg)
{
  gum_thumb_writer_put_instruction (self, 0x4780 | (reg << 3));
}

void
gum_thumb_writer_put_cmp_reg_imm (GumThumbWriter * self,
                                  GumArmReg reg,
                                  guint8 imm_value)
{
  gum_thumb_writer_put_instruction (self, 0x2800 | (reg << 8) | imm_value);
}

void
gum_thumb_writer_put_beq_label (GumThumbWriter * self,
                                gconstpointer label_id)
{
  gum_thumb_writer_add_label_reference_here (self, label_id);
  gum_thumb_writer_put_instruction (self, 0xd000);
}

void
gum_thumb_writer_put_bne_label (GumThumbWriter * self,
                                gconstpointer label_id)
{
  gum_thumb_writer_add_label_reference_here (self, label_id);
  gum_thumb_writer_put_instruction (self, 0xd100);
}

void
gum_thumb_writer_put_cbz_reg_label (GumThumbWriter * self,
                                    GumArmReg reg,
                                    gconstpointer label_id)
{
  gum_thumb_writer_add_label_reference_here (self, label_id);
  gum_thumb_writer_put_instruction (self, 0xb100 | reg);
}

void
gum_thumb_writer_put_cbnz_reg_label (GumThumbWriter * self,
                                     GumArmReg reg,
                                     gconstpointer label_id)
{
  gum_thumb_writer_add_label_reference_here (self, label_id);
  gum_thumb_writer_put_instruction (self, 0xb900 | reg);
}

void
gum_thumb_writer_put_push_regs (GumThumbWriter * self,
                                guint n_regs,
                                GumArmReg first_reg,
                                ...)
{
  guint16 insn = 0xb400;
  va_list vl;
  GumArmReg cur_reg;
  guint reg_idx;

  g_assert_cmpuint (n_regs, !=, 0);

  va_start (vl, first_reg);
  cur_reg = first_reg;
  for (reg_idx = 0; reg_idx != n_regs; reg_idx++)
  {
    g_assert ((cur_reg >= GUM_AREG_R0 && cur_reg <= GUM_AREG_R7) ||
        cur_reg == GUM_AREG_LR);

    if (cur_reg == GUM_AREG_LR)
      insn |= 0x100;
    else
      insn |= (1 << (cur_reg - GUM_AREG_R0));

    cur_reg = va_arg (vl, GumArmReg);
  }
  va_end (vl);

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_pop_regs (GumThumbWriter * self,
                               guint n_regs,
                               GumArmReg first_reg,
                               ...)
{
  guint16 insn = 0xbc00;
  va_list vl;
  GumArmReg cur_reg;
  guint reg_idx;

  g_assert_cmpuint (n_regs, !=, 0);

  va_start (vl, first_reg);
  cur_reg = first_reg;
  for (reg_idx = 0; reg_idx != n_regs; reg_idx++)
  {
    g_assert ((cur_reg >= GUM_AREG_R0 && cur_reg <= GUM_AREG_R7) ||
        cur_reg == GUM_AREG_PC);

    if (cur_reg == GUM_AREG_PC)
      insn |= 0x100;
    else
      insn |= (1 << (cur_reg - GUM_AREG_R0));

    cur_reg = va_arg (vl, GumArmReg);
  }
  va_end (vl);

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_ldr_reg_address (GumThumbWriter * self,
                                      GumArmReg reg,
                                      GumAddress address)
{
  gum_thumb_writer_put_ldr_reg_u32 (self, reg, (guint32) address);
}

void
gum_thumb_writer_put_ldr_reg_u32 (GumThumbWriter * self,
                                  GumArmReg reg,
                                  guint32 val)
{
  gum_thumb_writer_add_literal_reference_here (self, val);
  gum_thumb_writer_put_instruction (self, 0x4800 | (reg << 8));
}

void
gum_thumb_writer_put_ldr_reg_reg (GumThumbWriter * self,
                                  GumArmReg dst_reg,
                                  GumArmReg src_reg)
{
  gum_thumb_writer_put_ldr_reg_reg_offset (self, dst_reg, src_reg, 0);
}

void
gum_thumb_writer_put_ldr_reg_reg_offset (GumThumbWriter * self,
                                         GumArmReg dst_reg,
                                         GumArmReg src_reg,
                                         guint8 src_offset)
{
  guint16 insn;

  insn = gum_thumb_writer_make_ldr_or_str_reg_reg_offset (dst_reg,
      src_reg, src_offset);
  insn |= 0x0800;

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_str_reg_reg (GumThumbWriter * self,
                                  GumArmReg src_reg,
                                  GumArmReg dst_reg)
{
  gum_thumb_writer_put_str_reg_reg_offset (self, src_reg, dst_reg, 0);
}

void
gum_thumb_writer_put_str_reg_reg_offset (GumThumbWriter * self,
                                         GumArmReg src_reg,
                                         GumArmReg dst_reg,
                                         guint8 dst_offset)
{
  guint16 insn;

  insn = gum_thumb_writer_make_ldr_or_str_reg_reg_offset (src_reg,
      dst_reg, dst_offset);

  gum_thumb_writer_put_instruction (self, insn);
}

static guint16
gum_thumb_writer_make_ldr_or_str_reg_reg_offset (GumArmReg left_reg,
                                                 GumArmReg right_reg,
                                                 guint8 right_offset)
{
  guint16 insn;

  g_assert (right_offset % 4 == 0);

  if (right_reg == GUM_AREG_SP)
  {
    g_assert_cmpuint (right_offset, <=, 1020);

    insn = 0x9000 | (left_reg << 8) | (right_offset / 4);
  }
  else
  {
    g_assert_cmpuint (right_offset, <=, 124);

    insn = 0x6000 | (right_offset / 4) << 6 | (right_reg << 3) | left_reg;
  }

  return insn;
}

void
gum_thumb_writer_put_mov_reg_reg (GumThumbWriter * self,
                                  GumArmReg dst_reg,
                                  GumArmReg src_reg)
{
  guint16 insn;

  if (dst_reg <= GUM_AREG_R7 && src_reg <= GUM_AREG_R7)
  {
    insn = 0x1c00 | (src_reg << 3) | dst_reg;
  }
  else
  {
    guint16 dst_is_high;

    if (dst_reg > GUM_AREG_R7)
    {
      dst_is_high = 1;
      dst_reg -= GUM_AREG_R7 + 1;
    }
    else
    {
      dst_is_high = 0;
    }

    insn = 0x4600 | (dst_is_high << 7) | (src_reg << 3) | dst_reg;
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_mov_reg_u8 (GumThumbWriter * self,
                                 GumArmReg dst_reg,
                                 guint8 imm_value)
{
  gum_thumb_writer_put_instruction (self, 0x2000 | (dst_reg << 8) | imm_value);
}

void
gum_thumb_writer_put_add_reg_imm (GumThumbWriter * self,
                                  GumArmReg dst_reg,
                                  gssize imm_value)
{
  guint16 insn, sign_mask = 0x0000;

  if (dst_reg == GUM_AREG_SP)
  {
    g_assert (imm_value % 4 == 0);

    if (imm_value < 0)
      sign_mask = 0x0080;

    insn = 0xb000 | sign_mask | ABS (imm_value / 4);
  }
  else
  {
    if (imm_value < 0)
      sign_mask = 0x0800;

    insn = 0x3000 | sign_mask | (dst_reg << 8) | ABS (imm_value);
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_add_reg_reg (GumThumbWriter * self,
                                  GumArmReg dst_reg,
                                  GumArmReg src_reg)
{
  gum_thumb_writer_put_add_reg_reg_reg (self, dst_reg, dst_reg, src_reg);
}

void
gum_thumb_writer_put_add_reg_reg_reg (GumThumbWriter * self,
                                      GumArmReg dst_reg,
                                      GumArmReg left_reg,
                                      GumArmReg right_reg)
{
  guint16 insn;

  if (left_reg == dst_reg)
  {
    insn = 0x4400;
    if (dst_reg <= GUM_AREG_R7)
      insn |= dst_reg;
    else
      insn |= 0x0080 | (dst_reg - GUM_AREG_R8);
    if (right_reg <= GUM_AREG_R7)
      insn |= (right_reg << 3);
    else
      insn |= 0x0040 | ((right_reg - GUM_AREG_R8) << 3);
  }
  else
  {
    insn = 0x1800 | (right_reg << 6) | (left_reg << 3) | dst_reg;
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_add_reg_reg_imm (GumThumbWriter * self,
                                      GumArmReg dst_reg,
                                      GumArmReg left_reg,
                                      gssize right_value)
{
  guint16 insn;

  if (left_reg == dst_reg)
  {
    gum_thumb_writer_put_add_reg_imm (self, dst_reg, right_value);
    return;
  }

  if (left_reg == GUM_AREG_SP || left_reg == GUM_AREG_PC)
  {
    guint16 base_mask;

    g_assert_cmpint (right_value, >=, 0);
    g_assert (right_value % 4 == 0);

    if (left_reg == GUM_AREG_SP)
      base_mask = 0x0800;
    else
      base_mask = 0x0000;

    insn = 0xa000 | base_mask | (dst_reg << 8) | (right_value / 4);
  }
  else
  {
    guint16 sign_mask = 0x0000;

    g_assert_cmpuint (ABS (right_value), <=, 7);

    if (right_value < 0)
      sign_mask = 0x0200;

    insn = 0x1c00 | sign_mask | (ABS (right_value) << 6) | (left_reg << 3) |
        dst_reg;
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_sub_reg_imm (GumThumbWriter * self,
                                  GumArmReg dst_reg,
                                  gssize imm_value)
{
  gum_thumb_writer_put_add_reg_imm (self, dst_reg, -imm_value);
}

void
gum_thumb_writer_put_sub_reg_reg (GumThumbWriter * self,
                                  GumArmReg dst_reg,
                                  GumArmReg src_reg)
{
  gum_thumb_writer_put_sub_reg_reg_reg (self, dst_reg, dst_reg, src_reg);
}

void
gum_thumb_writer_put_sub_reg_reg_reg (GumThumbWriter * self,
                                      GumArmReg dst_reg,
                                      GumArmReg left_reg,
                                      GumArmReg right_reg)
{
  guint16 insn;

  insn = 0x1a00 | (right_reg << 6) | (left_reg << 3) | dst_reg;

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_sub_reg_reg_imm (GumThumbWriter * self,
                                      GumArmReg dst_reg,
                                      GumArmReg left_reg,
                                      gssize right_value)
{
  gum_thumb_writer_put_add_reg_reg_imm (self, dst_reg, left_reg, -right_value);
}

void
gum_thumb_writer_put_nop (GumThumbWriter * self)
{
  gum_thumb_writer_put_instruction (self, 0x46c0);
}

void
gum_thumb_writer_put_bkpt_imm (GumThumbWriter * self,
                               guint8 imm)
{
  gum_thumb_writer_put_instruction (self, 0xbe00 | imm);
}

void
gum_thumb_writer_put_breakpoint (GumThumbWriter * self)
{
  switch (self->target_os)
  {
    case GUM_OS_LINUX:
    case GUM_OS_ANDROID:
      gum_thumb_writer_put_instruction (self, 0xde01);
      break;
    default:
      gum_thumb_writer_put_bkpt_imm (self, 0);
      gum_thumb_writer_put_bx_reg (self, GUM_AREG_LR);
      break;
  }
}

void
gum_thumb_writer_put_bytes (GumThumbWriter * self,
                            const guint8 * data,
                            guint n)
{
  g_assert (n % 2 == 0);

  memcpy (self->code, data, n);
  self->code += n / sizeof (guint16);
  self->pc += n;
}

void
gum_thumb_writer_put_instruction (GumThumbWriter * self,
                                  guint16 insn)
{
  *self->code++ = GUINT16_TO_LE (insn);
  self->pc += 2;
}

