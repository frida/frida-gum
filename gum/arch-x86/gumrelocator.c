/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumrelocator.h"
#include "gumudis86.h"

#include <string.h>

#define GUM_MAX_INPUT_INSN_COUNT (100)

static gboolean gum_relocator_write_one_instruction (GumRelocator * self);
static void gum_relocator_put_label_for (GumRelocator * self,
    ud_t * insn);

void
gum_relocator_init (GumRelocator * relocator,
                    const guint8 * input_code,
                    GumCodeWriter * output)
{
  relocator->input_insns = g_new (ud_t, GUM_MAX_INPUT_INSN_COUNT);

  gum_relocator_reset (relocator, input_code, output);
}

void
gum_relocator_reset (GumRelocator * relocator,
                     const guint8 * input_code,
                     GumCodeWriter * output)
{
  relocator->input_start = relocator->input_cur = input_code;
  relocator->output = output;

  relocator->inpos = relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

void
gum_relocator_free (GumRelocator * relocator)
{
  g_free (relocator->input_insns);
}

static guint
gum_relocator_inpos (GumRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_relocator_outpos (GumRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_relocator_increment_inpos (GumRelocator * self)
{
  self->inpos++;
  g_assert_cmpint (self->inpos, >, self->outpos);
}

static void
gum_relocator_increment_outpos (GumRelocator * self)
{
  self->outpos++;
  g_assert_cmpint (self->outpos, <=, self->inpos);
}

guint
gum_relocator_read_one (GumRelocator * self,
                        const ud_t ** insn)
{
  const guint buf_size = 4096;
  ud_t * ud;
  guint in_size;

  if (self->eoi)
    return 0;

  ud = &self->input_insns[gum_relocator_inpos (self)];
  gum_relocator_increment_inpos (self);

  ud_init (ud);
  ud_set_mode (ud, GUM_CPU_MODE);
  /*ud_set_syntax (ud, UD_SYN_INTEL);*/

  ud_set_pc (ud, (uint64_t) self->input_cur);
  ud_set_input_buffer (ud, (guint8 *) self->input_cur, buf_size);

  in_size = ud_disassemble (ud);
  g_assert (in_size != 0);

  switch (ud->mnemonic)
  {
    case UD_Ijcxz:
    case UD_Ijecxz:
    case UD_Ijrcxz:
      return 0; /* FIXME: not supported */
      break;

    case UD_Ijmp:
    case UD_Icall:
    case UD_Iret:
    case UD_Iretf:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;

    default:
      if (gum_mnemonic_is_jcc (ud->mnemonic))
        self->eob = TRUE;
      break;
  }

  if (insn != NULL)
    *insn = ud;

  self->input_cur += in_size;

  return self->input_cur - self->input_start;
}

ud_t *
gum_relocator_peek_next_write_insn (GumRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return &self->input_insns[gum_relocator_outpos (self)];
}

gpointer
gum_relocator_peek_next_write_source (GumRelocator * self)
{
  ud_t * next;

  next = gum_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (ud_insn_off (next));
}

void
gum_relocator_skip_one (GumRelocator * self)
{
  ud_t * next;

  next = gum_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_relocator_increment_outpos (self);

  gum_relocator_put_label_for (self, next);
}

void
gum_relocator_skip_one_no_label (GumRelocator * self)
{
  ud_t * next;

  next = gum_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_relocator_increment_outpos (self);
}

gboolean
gum_relocator_write_one (GumRelocator * self)
{
  ud_t * cur;

  if ((cur = gum_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  gum_relocator_put_label_for (self, cur);

  return gum_relocator_write_one_instruction (self);
}

gboolean
gum_relocator_write_one_no_label (GumRelocator * self)
{
  return gum_relocator_write_one_instruction (self);
}

static gboolean
gum_relocator_write_one_instruction (GumRelocator * self)
{
  ud_t * cur;
  guint8 * cur_start, * cur_end;
  guint cur_len;
  gboolean passthrough = FALSE;

  if ((cur = gum_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_relocator_increment_outpos (self);

  cur_len = ud_insn_len (cur);
  cur_start = GSIZE_TO_POINTER (ud_insn_off (cur));
  cur_end = cur_start + cur_len;

  switch (cur->mnemonic)
  {
    case UD_Icall:
    case UD_Ijmp:
      {
        ud_operand_t * op = &cur->operand[0];
        if (op->type == UD_OP_JIMM && op->base == UD_NONE)
        {
          gconstpointer target = NULL;

          if (op->size == 32)
            target = cur_end + op->lval.sdword;
          else if (op->size == 8)
            target = cur_end + op->lval.sbyte;
          else
            g_assert_not_reached ();

          if (cur->mnemonic == UD_Icall)
            gum_code_writer_put_call (self->output, target);
          else
            gum_code_writer_put_jmp (self->output, target);
        }
        else if ((cur->mnemonic == UD_Icall && op->type == UD_OP_MEM) ||
            (cur->mnemonic == UD_Ijmp && op->type == UD_OP_JIMM
                && op->size == 8))
        {
          passthrough = TRUE;
        }
        else
        {
          /* FIXME */
          g_assert_not_reached ();
        }
      }
      break;

    default:
      if (gum_mnemonic_is_jcc (cur->mnemonic))
      {
        ud_operand_t * op = &cur->operand[0];
        if (op->type == UD_OP_JIMM && op->size == 8 && op->base == UD_NONE)
        {
          const guint8 * target = cur_end + op->lval.sbyte;

          /* FIXME */
          if (target >= self->input_start && target < self->input_cur)
          {
            gum_code_writer_put_jcc_short_label (self->output, cur_start[0],
                GUINT_TO_POINTER (target));
          }
          else
          {
            gum_code_writer_put_jcc_near (self->output,
                gum_jcc_insn_to_near_opcode (cur_start), target);
          }
        }
        else
        {
          /* FIXME */
          g_assert_not_reached ();
        }
      }
      else
      {
        passthrough = TRUE;
      }
      break;
  }

  if (passthrough)
    gum_code_writer_put_bytes (self->output, cur_start, cur_len);

  return TRUE;
}

void
gum_relocator_write_all (GumRelocator * self)
{
  guint count = 0;

  while (gum_relocator_write_one (self))
    count++;

  g_assert_cmpuint (count, >, 0);
}

gboolean
gum_relocator_eob (GumRelocator * self)
{
  return self->eob;
}

gboolean
gum_relocator_eoi (GumRelocator * self)
{
  return self->eoi;
}

static void
gum_relocator_put_label_for (GumRelocator * self,
                             ud_t * insn)
{
  gum_code_writer_put_label (self->output,
      GSIZE_TO_POINTER (ud_insn_off (insn)));
}

gboolean
gum_relocator_can_relocate (gpointer address,
                            guint min_bytes)
{
  guint8 * buf;
  GumCodeWriter cw;
  GumRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_code_writer_init (&cw, buf);

  gum_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      return FALSE;
  }
  while (reloc_bytes < min_bytes);

  gum_relocator_free (&rl);

  gum_code_writer_free (&cw);

  return TRUE;
}

guint
gum_relocator_relocate (gpointer from,
                        guint min_bytes,
                        gpointer to)
{
  GumCodeWriter cw;
  GumRelocator rl;
  guint reloc_bytes;

  gum_code_writer_init (&cw, to);

  gum_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < min_bytes);

  gum_relocator_write_all (&rl);

  gum_relocator_free (&rl);
  gum_code_writer_free (&cw);

  return reloc_bytes;
}
