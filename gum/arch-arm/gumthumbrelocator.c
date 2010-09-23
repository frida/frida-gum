/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumthumbrelocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const GumArmInstruction * insn;
  const guint8 * start;
  const guint8 * end;
  guint len;

  GumThumbWriter * code_writer;
};

static gboolean gum_thumb_relocator_write_one_instruction (GumThumbRelocator * self);

void
gum_thumb_relocator_init (GumThumbRelocator * relocator,
                          gconstpointer input_code,
                          GumThumbWriter * output)
{
  relocator->input_insns = gum_new (GumArmInstruction,
      GUM_MAX_INPUT_INSN_COUNT);

  gum_thumb_relocator_reset (relocator, input_code, output);
}

void
gum_thumb_relocator_reset (GumThumbRelocator * relocator,
                           gconstpointer input_code,
                           GumThumbWriter * output)
{
  relocator->input_start = relocator->input_cur = input_code;
  relocator->output = output;

  relocator->inpos = relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

void
gum_thumb_relocator_free (GumThumbRelocator * relocator)
{
  gum_free (relocator->input_insns);
}

static guint
gum_thumb_relocator_inpos (GumThumbRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_thumb_relocator_outpos (GumThumbRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_thumb_relocator_increment_inpos (GumThumbRelocator * self)
{
  self->inpos++;
  g_assert_cmpint (self->inpos, >, self->outpos);
}

static void
gum_thumb_relocator_increment_outpos (GumThumbRelocator * self)
{
  self->outpos++;
  g_assert_cmpint (self->outpos, <=, self->inpos);
}

guint
gum_thumb_relocator_read_one (GumThumbRelocator * self,
                              const GumArmInstruction ** instruction)
{
  guint16 raw_insn;
  guint group, operation;
  GumArmInstruction * insn;

  if (self->eoi)
    return 0;

  raw_insn = GUINT16_FROM_LE (*((guint16 *) self->input_cur));
  insn = &self->input_insns[gum_thumb_relocator_inpos (self)];

  group = (raw_insn >> 12) & 0xf;
  operation = (raw_insn >> 8) & 0xf;

  switch (group)
  {
    case 0xa:
      insn->mnemonic = GUM_ARM_ADD;
      break;

    case 0xb:
      if (operation == 4 || operation == 5)
      {
        insn->mnemonic = GUM_ARM_PUSH;
        break;
      }

    default:
      return 0;
  }

  insn->address = self->input_cur;

  gum_thumb_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += sizeof (guint16);

  return self->input_cur - self->input_start;
}

GumArmInstruction *
gum_thumb_relocator_peek_next_write_insn (GumThumbRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return &self->input_insns[gum_thumb_relocator_outpos (self)];
}

gpointer
gum_thumb_relocator_peek_next_write_source (GumThumbRelocator * self)
{
  GumArmInstruction * next;

  next = gum_thumb_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  g_assert_not_reached ();
  return NULL;
}

void
gum_thumb_relocator_skip_one (GumThumbRelocator * self)
{
  GumArmInstruction * next;

  next = gum_thumb_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_thumb_relocator_increment_outpos (self);
}

gboolean
gum_thumb_relocator_write_one (GumThumbRelocator * self)
{
  GumArmInstruction * cur;

  if ((cur = gum_thumb_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  return gum_thumb_relocator_write_one_instruction (self);
}

static gboolean
gum_thumb_relocator_write_one_instruction (GumThumbRelocator * self)
{
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;

  if ((ctx.insn = gum_thumb_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_thumb_relocator_increment_outpos (self);

  ctx.len = sizeof (guint16);
  ctx.start = ctx.insn->address;
  ctx.end = ctx.start + ctx.len;

  ctx.code_writer = self->output;

  /* ... */

  if (!rewritten)
    gum_thumb_writer_put_bytes (ctx.code_writer, ctx.start, ctx.len);

  return TRUE;
}

void
gum_thumb_relocator_write_all (GumThumbRelocator * self)
{
  guint count = 0;

  while (gum_thumb_relocator_write_one (self))
    count++;

  g_assert_cmpuint (count, >, 0);
}

gboolean
gum_thumb_relocator_eob (GumThumbRelocator * self)
{
  return self->eob;
}

gboolean
gum_thumb_relocator_eoi (GumThumbRelocator * self)
{
  return self->eoi;
}

gboolean
gum_thumb_relocator_can_relocate (gpointer address,
                                  guint min_bytes)
{
  guint8 * buf;
  GumThumbWriter cw;
  GumThumbRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_thumb_writer_init (&cw, buf);

  gum_thumb_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_thumb_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      return FALSE;
  }
  while (reloc_bytes < min_bytes);

  gum_thumb_relocator_free (&rl);

  gum_thumb_writer_free (&cw);

  return TRUE;
}

guint
gum_thumb_relocator_relocate (gpointer from,
                              guint min_bytes,
                              gpointer to)
{
  GumThumbWriter cw;
  GumThumbRelocator rl;
  guint reloc_bytes;

  gum_thumb_writer_init (&cw, to);

  gum_thumb_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_thumb_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < min_bytes);

  gum_thumb_relocator_write_all (&rl);

  gum_thumb_relocator_free (&rl);
  gum_thumb_writer_free (&cw);

  return reloc_bytes;
}

