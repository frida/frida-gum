/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarmwriter.h"

#include "gumarmreg.h"
#include "gumlibc.h"
#include "gummemory.h"
#include "gumprocess.h"

#include <string.h>

typedef struct _GumArmLabelRef GumArmLabelRef;
typedef struct _GumArmLiteralRef GumArmLiteralRef;

struct _GumArmLabelRef
{
  gconstpointer id;
  guint32 * insn;
};

struct _GumArmLiteralRef
{
  guint32 * insn;
  guint32 val;
};

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

  writer->id_to_address = g_hash_table_new (NULL, NULL);
  writer->label_refs = g_array_new (FALSE, FALSE, sizeof (GumArmLabelRef));
  writer->literal_refs = g_array_new (FALSE, FALSE, sizeof (GumArmLiteralRef));

  gum_arm_writer_reset (writer, code_address);
}

void
gum_arm_writer_clear (GumArmWriter * writer)
{
  gum_arm_writer_flush (writer);

  g_hash_table_unref (writer->id_to_address);
  g_array_free (writer->label_refs, TRUE);
  g_array_free (writer->literal_refs, TRUE);
}

void
gum_arm_writer_reset (GumArmWriter * writer,
                      gpointer code_address)
{
  writer->target_os = gum_process_get_native_os ();

  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  g_hash_table_remove_all (writer->id_to_address);
  g_array_set_size (writer->label_refs, 0);
  g_array_set_size (writer->literal_refs, 0);
  writer->earliest_literal_insn = NULL;
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
    g_array_set_size (self->label_refs, 0);
    g_array_set_size (self->literal_refs, 0);

    return FALSE;
  }
}

gboolean
gum_arm_writer_put_label (GumArmWriter * self,
                          gconstpointer id)
{
  if (g_hash_table_lookup (self->id_to_address, id) != NULL)
    return FALSE;

  g_hash_table_insert (self->id_to_address, (gpointer) id, self->code);
  return TRUE;
}

static void
gum_arm_writer_add_label_reference_here (GumArmWriter * self,
                                         gconstpointer id)
{
  GumArmLabelRef r;

  r.id = id;
  r.insn = self->code;

  g_array_append_val (self->label_refs, r);
}

static void
gum_arm_writer_add_literal_reference_here (GumArmWriter * self,
                                           guint32 val)
{
  GumArmLiteralRef r;

  r.insn = self->code;
  r.val = val;

  g_array_append_val (self->literal_refs, r);

  if (self->earliest_literal_insn == NULL)
  {
    self->earliest_literal_insn = r.insn;
  }
}

gboolean
gum_arm_writer_put_b_imm (GumArmWriter * self,
                          GumAddress target)
{
  gint32 distance_in_bytes, distance_in_words;

  distance_in_bytes = target - (self->pc + 8);
  if (!GUM_IS_WITHIN_INT26_RANGE (distance_in_bytes))
    return FALSE;

  distance_in_words = distance_in_bytes / 4;

  gum_arm_writer_put_instruction (self, 0xea000000 |
      (distance_in_words & GUM_INT24_MASK));

  return TRUE;
}

void
gum_arm_writer_put_bx_reg (GumArmWriter * self,
                           arm_reg reg)
{
  GumArmRegInfo ri;

  gum_arm_reg_describe (reg, &ri);

  gum_arm_writer_put_instruction (self, 0xe12fff10 | ri.index);
}

void
gum_arm_writer_put_b_label (GumArmWriter * self,
                            gconstpointer label_id)
{
  gum_arm_writer_add_label_reference_here (self, label_id);
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
gum_arm_writer_put_add_reg_reg_imm (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    arm_reg src_reg,
                                    guint32 imm_val)
{
  GumArmRegInfo rd, rs;

  gum_arm_reg_describe (dst_reg, &rd);
  gum_arm_reg_describe (src_reg, &rs);

  gum_arm_writer_put_instruction (self, 0xe2800000 | rd.index << 12 |
      rs.index << 16 | (imm_val & GUM_INT12_MASK));
}

void
gum_arm_writer_put_ldr_reg_reg_imm (GumArmWriter * self,
                                    arm_reg dst_reg,
                                    arm_reg src_reg,
                                    guint32 imm_val)
{
  GumArmRegInfo rd, rs;

  gum_arm_reg_describe (dst_reg, &rd);
  gum_arm_reg_describe (src_reg, &rs);

  gum_arm_writer_put_instruction (self, 0xe5900000 | rd.index << 12 |
      rs.index << 16 | (imm_val & GUM_INT12_MASK));
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

  num_refs = self->label_refs->len;
  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumArmLabelRef * r;
    const guint32 * target_insn;
    gssize distance;
    guint32 insn;

    r = &g_array_index (self->label_refs, GumArmLabelRef, ref_index);

    target_insn = g_hash_table_lookup (self->id_to_address, r->id);
    if (target_insn == NULL)
      return FALSE;

    distance = target_insn - (r->insn + 2);
    if (!GUM_IS_WITHIN_INT24_RANGE (distance))
      return FALSE;

    insn = GUINT32_FROM_LE (*r->insn);
    insn |= distance & GUM_INT24_MASK;
    *r->insn = GUINT32_TO_LE (insn);
  }

  g_array_set_size (self->label_refs, 0);

  return TRUE;
}

static void
gum_arm_writer_maybe_commit_literals (GumArmWriter * self)
{
  guint space_used;
  gconstpointer after_literals = self->code;

  if (self->earliest_literal_insn == NULL)
    return;

  space_used = (self->code - self->earliest_literal_insn) * sizeof (guint32);
  space_used += self->literal_refs->len * sizeof (guint32);
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

  num_refs = self->literal_refs->len;
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

    r = &g_array_index (self->literal_refs, GumArmLiteralRef, ref_index);

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

    distance_in_words = cur_slot - (r->insn + 2);

    insn = GUINT32_FROM_LE (*r->insn);
    insn |= ABS (distance_in_words) * 4;
    if (distance_in_words >= 0)
      insn |= 1 << 23;
    *r->insn = GUINT32_TO_LE (insn);
  }

  self->code = last_slot;
  self->pc += (guint8 *) last_slot - (guint8 *) first_slot;

  g_array_set_size (self->literal_refs, 0);
}
