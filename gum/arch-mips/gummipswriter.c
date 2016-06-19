/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

static guint8 * gum_mips_writer_lookup_address_for_label_id (
    GumMipsWriter * self, gconstpointer id);
static void gum_mips_writer_put_argument_list_setup (GumMipsWriter * self,
    guint n_args, va_list vl);
static void gum_mips_writer_put_argument_list_teardown (GumMipsWriter * self,
    guint n_args);

void
gum_mips_writer_init (GumMipsWriter * writer,
                      gpointer code_address)
{
  writer->id_to_address = g_new (GumMipsLabelMapping, GUM_MAX_LABEL_COUNT);
  writer->label_refs = g_new (GumMipsLabelRef, GUM_MAX_LABEL_REF_COUNT);
  writer->literal_refs = g_new (GumMipsLiteralRef, GUM_MAX_LITERAL_REF_COUNT);

  gum_mips_writer_reset (writer, code_address);
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

void
gum_mips_writer_free (GumMipsWriter * writer)
{
  gum_mips_writer_flush (writer);

  g_free (writer->id_to_address);
  g_free (writer->label_refs);
  g_free (writer->literal_refs);
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

void
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
      g_assert (target_address != NULL);

      distance = ((gssize) target_address - (gssize) r->insn) / 4;

      insn = *r->insn;
      if (insn == 0x08000000)
      {
        g_assert (GUM_IS_WITHIN_INT16_RANGE (distance));
        insn |= distance & GUM_INT16_MASK;
      }
      /* TODO: conditional branches */
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

static void
gum_mips_writer_add_address_for_label_id (GumMipsWriter * self,
                                          gconstpointer id,
                                          gpointer address)
{
  GumMipsLabelMapping * map = &self->id_to_address[self->id_to_address_len++];

  g_assert_cmpuint (self->id_to_address_len, <=, GUM_MAX_LABEL_COUNT);

  map->id = id;
  map->address = address;
}

void
gum_mips_writer_put_label (GumMipsWriter * self,
                           gconstpointer id)
{
  g_assert (gum_mips_writer_lookup_address_for_label_id (self, id) == NULL);
  gum_mips_writer_add_address_for_label_id (self, id, self->code);
}

static void
gum_mips_writer_add_label_reference_here (GumMipsWriter * self,
                                          gconstpointer id)
{
  GumMipsLabelRef * r = &self->label_refs[self->label_refs_len++];

  g_assert_cmpuint (self->label_refs_len, <=, GUM_MAX_LABEL_REF_COUNT);

  r->id = id;
  r->insn = self->code;
}

static void
gum_mips_writer_add_literal_reference_here (GumMipsWriter * self,
                                            guint64 val)
{
  GumMipsLiteralRef * r = &self->literal_refs[self->literal_refs_len++];

  g_assert_cmpuint (self->literal_refs_len, <=, GUM_MAX_LITERAL_REF_COUNT);

  r->insn = self->code;
  r->val = val;
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

  if (gum_mips_writer_can_branch_address (self->pc, func))
  {
    gum_mips_writer_put_jal_address (self, func);
  }
  else
  {
    mips_reg target = MIPS_REG_AT;
    gum_mips_writer_put_la_reg_address (self, target, func);
    gum_mips_writer_put_jalr_reg (self, target);
  }

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
          gum_mips_writer_put_mov_reg_reg (self, r, arg->value.reg);
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
gum_mips_writer_can_branch_address (GumAddress from,
                                    GumAddress to)
{
  gint64 lower_limit = (from & 0xf0000000);
  gint64 upper_limit = (from & 0xf0000000) + GUM_INT28_MASK;

  return lower_limit < to && to < upper_limit;
}

void
gum_mips_writer_put_j_address (GumMipsWriter * self,
                               GumAddress address)
{

  g_assert_cmpint (address & 0xf0000000, ==, self->pc & 0xf0000000);
  g_assert_cmpint (address % 4, ==, 0);

  gum_mips_writer_put_instruction (self,
      0x08000000 | ((address & GUM_INT28_MASK) / 4));
  gum_mips_writer_put_nop (self);
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
  gum_mips_writer_put_instruction (self, 0x00000008 | (reg << 21));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_jal_address (GumMipsWriter * self,
                                 guint32 address)
{
  gum_mips_writer_put_instruction (self, 0x0c000000 | ((address & GUM_INT28_MASK) >> 2));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_jalr_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_instruction (self, 0x00000009 | (reg << 21));
  gum_mips_writer_put_nop (self);
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
  gum_mips_writer_put_instruction (self, 0x3c000000 | (reg << 16) |
      (imm & 0xffff));
}

void
gum_mips_writer_put_ori_reg_reg_imm (GumMipsWriter * self,
                                     mips_reg rt,
                                     mips_reg rs,
                                     guint imm)
{
  gum_mips_writer_put_instruction (self, 0x34000000 | (rt << 16) |
      (rs << 21) | (imm & 0xffff));
}

void
gum_mips_writer_put_lw_reg_reg_offset (GumMipsWriter * self,
                                       mips_reg dest_reg,
                                       mips_reg base_reg,
                                       gsize src_offset)
{
  gum_mips_writer_put_instruction (self, 0x8c000000 | (base_reg << 21) |
      (dest_reg << 16) | (src_offset & 0xffff));
}

void
gum_mips_writer_put_sw_reg_reg_offset (GumMipsWriter * self,
                                       mips_reg src_reg,
                                       mips_reg base_reg,
                                       gsize dest_offset)
{
  gum_mips_writer_put_instruction (self, 0xac000000 | (base_reg << 21) |
      (src_reg << 16) | (dest_offset & 0xffff));
}

void
gum_mips_writer_put_mov_reg_reg (GumMipsWriter * self,
                                 mips_reg dst_reg,
                                 mips_reg src_reg)
{
  gum_mips_writer_put_addu_reg_reg_reg (self, dst_reg, src_reg, MIPS_REG_ZERO);
}

void
gum_mips_writer_put_addu_reg_reg_reg (GumMipsWriter * self,
                                      mips_reg dest_reg,
                                      mips_reg left_reg,
                                      mips_reg right_reg)
{
  gum_mips_writer_put_instruction (self, 0x00000021 | (left_reg << 21) |
      (right_reg << 16) | (dest_reg << 11));
}

void
gum_mips_writer_put_addi_reg_reg_imm (GumMipsWriter * self,
                                      mips_reg dest_reg,
                                      mips_reg left_reg,
                                      gint32 imm)
{
  gum_mips_writer_put_instruction (self, 0x20000000 | (left_reg << 21) |
      (dest_reg << 16) | (imm & 0xffff));
}

void
gum_mips_writer_put_addi_reg_imm (GumMipsWriter * self,
                                  mips_reg dest_reg,
                                  gint32 imm)
{
  gum_mips_writer_put_addi_reg_reg_imm (self, dest_reg, dest_reg, imm);
}

void
gum_mips_writer_put_sub_reg_reg_imm (GumMipsWriter * self,
                                     mips_reg dest_reg,
                                     mips_reg left_reg,
                                     gint32 imm)
{
  gum_mips_writer_put_addi_reg_reg_imm (self, dest_reg, left_reg, -imm);
}


void
gum_mips_writer_put_push_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_sw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
  gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP, -sizeof(guint32));
}

void
gum_mips_writer_put_pop_reg (GumMipsWriter * self,
                             mips_reg reg)
{
  gum_mips_writer_put_lw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
  gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP, sizeof(guint32));
}

void
gum_mips_writer_put_mfhi_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_instruction (self, 0x00000010 | (reg << 11));
}

void
gum_mips_writer_put_mflo_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_instruction (self, 0x00000012 | (reg << 11));
}

void
gum_mips_writer_put_mthi_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_instruction (self, 0x00000011 | (reg << 21));
}

void
gum_mips_writer_put_mtlo_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_instruction (self, 0x00000013 | (reg << 21));
}



void
gum_mips_writer_put_nop (GumMipsWriter * self)
{
  gum_mips_writer_put_instruction (self, 0x00000000);
}

void
gum_mips_writer_put_instruction (GumMipsWriter * self,
                                 guint32 insn)
{
  *self->code++ = insn;
  self->pc += 4;
}

void
gum_mips_writer_put_bytes (GumMipsWriter * self,
                           const guint8 * data,
                           guint n)
{
  g_assert (n % 4 == 0);

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;
}
