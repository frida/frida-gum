/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumcodewriter.h"

#include <string.h>

#define GUM_MAX_LABEL_COUNT (10 * 1000)
#define GUM_MAX_LREF_COUNT  (3 * GUM_MAX_LABEL_COUNT)

#define IS_WITHIN_UINT8_RANGE(i) ((i) >= -128 && (i) <= 127)

typedef enum _GumMetaReg
{
  GUM_META_REG_XAX = 0,
  GUM_META_REG_XCX,
  GUM_META_REG_XDX,
  GUM_META_REG_XBX,
  GUM_META_REG_XSP,
  GUM_META_REG_XBP,
  GUM_META_REG_XSI,
  GUM_META_REG_XDI,
} GumMetaReg;

typedef enum _GumLabelRefSize
{
  GUM_LREF_SHORT,
  GUM_LREF_NEAR
} GumLabelRefSize;

struct _GumLabelMapping
{
  gconstpointer id;
  gpointer address;
};

struct _GumLabelRef
{
  gconstpointer id;
  guint8 * address;
  GumLabelRefSize size;
};

static gboolean gum_cpu_reg_is_wide (GumCpuReg reg);
static GumMetaReg gum_meta_reg_from_cpu_reg (GumCpuReg reg);

static guint8 * gum_code_writer_lookup_address_for_label_id (
    GumCodeWriter * self, gconstpointer id);

void
gum_code_writer_init (GumCodeWriter * writer,
                      gpointer code_address)
{
  writer->id_to_address = g_new (GumLabelMapping, GUM_MAX_LABEL_COUNT);
  writer->label_refs = g_new (GumLabelRef, GUM_MAX_LREF_COUNT);

  gum_code_writer_reset (writer, code_address);
}

void
gum_code_writer_reset (GumCodeWriter * writer,
                       gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;

  writer->id_to_address_len = 0;
  writer->label_refs_len = 0;
}

void
gum_code_writer_free (GumCodeWriter * writer)
{
  gum_code_writer_flush (writer);

  g_free (writer->id_to_address);
  g_free (writer->label_refs);
}

gpointer
gum_code_writer_cur (GumCodeWriter * self)
{
  return self->code;
}

guint
gum_code_writer_offset (GumCodeWriter * self)
{
  return self->code - self->base;
}

void
gum_code_writer_flush (GumCodeWriter * self)
{
  guint i;

  for (i = 0; i < self->label_refs_len; i++)
  {
    GumLabelRef * r = &self->label_refs[i];
    gpointer target_address;
    gint32 distance;

    target_address = gum_code_writer_lookup_address_for_label_id (self, r->id);
    g_assert (target_address != NULL);

    distance = (gssize) target_address - (gssize) r->address;

    if (r->size == GUM_LREF_SHORT)
    {
      g_assert (IS_WITHIN_UINT8_RANGE (distance));
      *((gint8 *) (r->address - 1)) = distance;
    }
    else
    {
      *((gint32 *) (r->address - 4)) = distance;
    }
  }

  self->label_refs_len = 0;
}

static guint8 *
gum_code_writer_lookup_address_for_label_id (GumCodeWriter * self,
                                             gconstpointer id)
{
  guint i;

  for (i = 0; i < self->id_to_address_len; i++)
  {
    GumLabelMapping * map = &self->id_to_address[i];
    if (map->id == id)
      return map->address;
  }

  return NULL;
}

static void
gum_code_writer_add_address_for_label_id (GumCodeWriter * self,
                                          gconstpointer id,
                                          gpointer address)
{
  GumLabelMapping * map = &self->id_to_address[self->id_to_address_len++];

  g_assert_cmpuint (self->id_to_address_len, <=, GUM_MAX_LABEL_COUNT);

  map->id = id;
  map->address = address;
}

void
gum_code_writer_put_label (GumCodeWriter * self,
                           gconstpointer id)
{
  g_assert (gum_code_writer_lookup_address_for_label_id (self, id) == NULL);
  gum_code_writer_add_address_for_label_id (self, id, self->code);
}

static void
gum_code_writer_add_label_reference_here (GumCodeWriter * self,
                                          gconstpointer id,
                                          GumLabelRefSize size)
{
  GumLabelRef * r = &self->label_refs[self->label_refs_len++];

  g_assert_cmpuint (self->label_refs_len, <=, GUM_MAX_LREF_COUNT);

  r->id = id;
  r->address = self->code;
  r->size = size;
}

void
gum_code_writer_put_call (GumCodeWriter * self,
                          gconstpointer target)
{
  self->code[0] = 0xe8;
  *((gint32 *) (self->code + 1)) =
      GPOINTER_TO_SIZE (target) - GPOINTER_TO_SIZE (self->code + 5);
  self->code += 5;
}

void
gum_code_writer_put_call_reg (GumCodeWriter * self,
                              GumCpuReg reg)
{
  self->code[0] = 0xff;
  self->code[1] = 0xd0 | reg;
  self->code += 2;
}

void
gum_code_writer_put_call_indirect (GumCodeWriter * self,
                                   gconstpointer * addr)
{
  self->code[0] = 0xff;
  self->code[1] = 0x15;
  *((gconstpointer **) (self->code + 2)) = addr;
  self->code += 6;
}

void
gum_code_writer_put_call_near_label (GumCodeWriter * self,
                                     gconstpointer label_id)
{
  gum_code_writer_put_call (self, self->code);
  gum_code_writer_add_label_reference_here (self, label_id, GUM_LREF_NEAR);
}

void
gum_code_writer_put_ret (GumCodeWriter * self)
{
  self->code[0] = 0xc3;
  self->code++;
}

void
gum_code_writer_put_jmp (GumCodeWriter * self,
                         gconstpointer target)
{
  gint32 distance;

  distance = GPOINTER_TO_SIZE (target) - GPOINTER_TO_SIZE (self->code + 2);

  if (IS_WITHIN_UINT8_RANGE (distance))
  {
    self->code[0] = 0xeb;
    *((gint8 *) (self->code + 1)) = distance;
    self->code += 2;
  }
  else
  {
    distance -= 3;

    self->code[0] = 0xe9;
    *((gint32 *) (self->code + 1)) = distance;
    self->code += 5;
  }
}

void
gum_code_writer_put_jmp_short_label (GumCodeWriter * self,
                                     gconstpointer label_id)
{
  gum_code_writer_put_jmp (self, self->code);
  gum_code_writer_add_label_reference_here (self, label_id, GUM_LREF_SHORT);
}

void
gum_code_writer_put_jcc_short_label (GumCodeWriter * self,
                                     guint8 opcode,
                                     gconstpointer label_id)
{
  self->code[0] = opcode;
  *((gint8 *) (self->code + 1)) = (gint8) -2;
  self->code += 2;

  gum_code_writer_add_label_reference_here (self, label_id, GUM_LREF_SHORT);
}

void
gum_code_writer_put_jcc_near (GumCodeWriter * self,
                              guint8 opcode,
                              gconstpointer target)
{
  gint32 distance;

  distance = GPOINTER_TO_SIZE (target) - GPOINTER_TO_SIZE (self->code + 6);

  self->code[0] = 0x0f;
  self->code[1] = opcode;
  *((gint32 *) (self->code + 2)) = distance;
  self->code += 6;
}

void
gum_code_writer_put_jmp_reg_ptr (GumCodeWriter * self,
                                 GumCpuReg reg)
{
  self->code[0] = 0xff;
  self->code[1] = 0x20 | reg;
  self->code += 2;
}

void
gum_code_writer_put_jz (GumCodeWriter * self,
                        gconstpointer target,
                        GumBranchHint hint)
{
  gint32 distance;

  distance = GPOINTER_TO_SIZE (target) - GPOINTER_TO_SIZE (self->code + 3);

  g_assert (IS_WITHIN_UINT8_RANGE (distance)); /* for now */

  if (hint != GUM_NO_HINT)
    *self->code++ = (hint == GUM_LIKELY) ? 0x3e : 0x2e;
  self->code[0] = 0x74;
  self->code[1] = distance;
  self->code += 2;
}

void
gum_code_writer_put_jz_label (GumCodeWriter * self,
                              gconstpointer label_id,
                              GumBranchHint hint)
{
  gum_code_writer_put_jz (self, self->code, hint);
  gum_code_writer_add_label_reference_here (self, label_id, GUM_LREF_SHORT);
}

void
gum_code_writer_put_jle (GumCodeWriter * self,
                         gconstpointer target,
                         GumBranchHint hint)
{
  gint32 distance;

  distance = GPOINTER_TO_SIZE (target) - GPOINTER_TO_SIZE (self->code + 3);

  g_assert (IS_WITHIN_UINT8_RANGE (distance)); /* for now */

  self->code[0] = (hint == GUM_LIKELY) ? 0x3e : 0x2e;
  self->code[1] = 0x7e;
  self->code[2] = distance;
  self->code += 3;
}

void
gum_code_writer_put_jle_label (GumCodeWriter * self,
                               gconstpointer label_id,
                               GumBranchHint hint)
{
  gum_code_writer_put_jle (self, self->code, hint);
  gum_code_writer_add_label_reference_here (self, label_id, GUM_LREF_SHORT);
}

void
gum_code_writer_put_add_reg_i8 (GumCodeWriter * self,
                                GumCpuReg reg,
                                gint8 imm_value)
{
  self->code[0] = 0x83;
  self->code[1] = 0xc0 | reg;
  *((gint8 *) (self->code + 2)) = imm_value;
  self->code += 3;
}

void
gum_code_writer_put_add_reg_i32 (GumCodeWriter * self,
                                 GumCpuReg reg,
                                 gint32 imm_value)
{
  if (reg == GUM_REG_EAX)
  {
    self->code[0] = 0x05;
    *((gint32 *) (self->code + 1)) = imm_value;
    self->code += 5;
  }
  else
  {
    self->code[0] = 0x81;
    self->code[1] = 0xc0 | reg;
    *((gint32 *) (self->code + 2)) = imm_value;
    self->code += 6;
  }
}

void
gum_code_writer_put_add_reg_reg (GumCodeWriter * self,
                                 GumCpuReg dst_reg,
                                 GumCpuReg src_reg)
{
  self->code[0] = 0x01;
  self->code[1] = 0xc0 | (src_reg << 3) | dst_reg;
  self->code += 2;
}

void
gum_code_writer_put_sub_reg_i8 (GumCodeWriter * self,
                                GumCpuReg reg,
                                gint8 imm_value)
{
  self->code[0] = 0x83;
  self->code[1] = 0xe8 | reg;
  *((gint8 *) (self->code + 2)) = imm_value;
  self->code += 3;
}

void
gum_code_writer_put_sub_reg_i32 (GumCodeWriter * self,
                                 GumCpuReg reg,
                                 gint32 imm_value)
{
  if (reg == GUM_REG_EAX)
  {
    self->code[0] = 0x2d;
    *((gint32 *) (self->code + 1)) = imm_value;
    self->code += 5;
  }
  else
  {
    self->code[0] = 0x81;
    self->code[1] = 0xe8 | reg;
    *((gint32 *) (self->code + 2)) = imm_value;
    self->code += 6;
  }
}

void
gum_code_writer_put_sub_reg_reg (GumCodeWriter * self,
                                 GumCpuReg dst_reg,
                                 GumCpuReg src_reg)
{
  self->code[0] = 0x29;
  self->code[1] = 0xc0 | (src_reg << 3) | dst_reg;
  self->code += 2;
}

void
gum_code_writer_put_inc_reg (GumCodeWriter * self,
                             GumCpuReg reg)
{
  self->code[0] = 0xff;
  self->code[1] = 0xc0 | reg;
  self->code += 2;
}

void
gum_code_writer_put_dec_reg (GumCodeWriter * self,
                             GumCpuReg reg)
{
  self->code[0] = 0xff;
  self->code[1] = 0xc8 | reg;
  self->code += 2;
}

void
gum_code_writer_put_lock_xadd_reg_ptr_reg (GumCodeWriter * self,
                                           GumCpuReg dst_reg,
                                           GumCpuReg src_reg)
{
  self->code[0] = 0xf0; /* lock prefix */
  self->code[1] = 0x0f;
  self->code[2] = 0xc1;
  self->code[3] = 0x00 | (src_reg << 3) | dst_reg;
  self->code += 4;

  if (dst_reg == GUM_REG_ESP)
  {
    *self->code++ = 0x24;
  }
  else if (dst_reg == GUM_REG_EBP)
  {
    self->code[-1] |= 0x40;
    *self->code++ = 0x00;
  }
}

void
gum_code_writer_put_lock_cmpxchg_reg_ptr_reg (GumCodeWriter * self,
                                              GumCpuReg dst_reg,
                                              GumCpuReg src_reg)
{
  GumMetaReg dst, src;

  g_assert (!gum_cpu_reg_is_wide (src_reg));

  dst = gum_meta_reg_from_cpu_reg (dst_reg);
  src = gum_meta_reg_from_cpu_reg (src_reg);

  self->code[0] = 0xf0; /* lock prefix */
  self->code[1] = 0x0f;
  self->code[2] = 0xb1;
  self->code[3] = 0x00 | (src << 3) | dst;
  self->code += 4;

  if (dst == GUM_META_REG_XSP)
  {
    *self->code++ = 0x24;
  }
  else if (dst == GUM_META_REG_XBP)
  {
    self->code[-1] |= 0x40;
    *self->code++ = 0x00;
  }
}

void
gum_code_writer_put_and_reg_u32 (GumCodeWriter * self,
                                 GumCpuReg reg,
                                 guint32 imm_value)
{
  if (reg == GUM_REG_EAX)
  {
    self->code[0] = 0x25;
    *((guint32 *) (self->code + 1)) = imm_value;
    self->code += 5;
  }
  else
  {
    self->code[0] = 0x81;
    self->code[1] = 0xe0 | reg;
    *((guint32 *) (self->code + 2)) = imm_value;
    self->code += 6;
  }
}

void
gum_code_writer_put_shl_reg_u8 (GumCodeWriter * self,
                                GumCpuReg reg,
                                guint8 imm_value)
{
  self->code[0] = 0xc1;
  self->code[1] = 0xe0 | reg;
  self->code[2] = imm_value;
  self->code += 3;
}

void
gum_code_writer_put_mov_reg_reg (GumCodeWriter * self,
                                 GumCpuReg dst_reg,
                                 GumCpuReg src_reg)
{
  self->code[0] = 0x89;
  self->code[1] = 0xc0 | (src_reg << 3) | dst_reg;
  self->code += 2;
}

void
gum_code_writer_put_mov_reg_u32 (GumCodeWriter * self,
                                 GumCpuReg dst_reg,
                                 guint32 imm_value)
{
  self->code[0] = 0xb8 | dst_reg;
  *((guint32 *) (self->code + 1)) = imm_value;
  self->code += 5;
}

void
gum_code_writer_put_mov_reg_ptr_u32 (GumCodeWriter * self,
                                     GumCpuReg dst_reg,
                                     guint32 imm_value)
{
  gum_code_writer_put_mov_reg_offset_ptr_u32 (self, dst_reg, 0, imm_value);
}

void
gum_code_writer_put_mov_reg_offset_ptr_u32 (GumCodeWriter * self,
                                            GumCpuReg dst_reg,
                                            gssize dst_offset,
                                            guint32 imm_value)
{
  g_assert (IS_WITHIN_UINT8_RANGE (dst_offset));

  *self->code++ = 0xc7;

  if (dst_offset == 0 && dst_reg != GUM_REG_EBP)
  {
    *self->code++ = 0x00 | dst_reg;
    if (dst_reg == GUM_REG_ESP)
      *self->code++ = 0x24;
  }
  else
  {
    *self->code++ = 0x40 | dst_reg;
    if (dst_reg == GUM_REG_ESP)
      *self->code++ = 0x24;
    *self->code++ = dst_offset;
  }

  *((guint32 *) self->code) = imm_value;
  self->code += 4;
}

void
gum_code_writer_put_mov_reg_imm_ptr (GumCodeWriter * self,
                                     GumCpuReg dst_reg,
                                     gconstpointer imm_ptr)
{
  if (dst_reg == GUM_REG_EAX)
  {
    self->code[0] = 0xa1;
    *((gconstpointer *) (self->code + 1)) = imm_ptr;
    self->code += 5;
  }
  else
  {
    self->code[0] = 0x8b;
    self->code[1] = 0x05 | (dst_reg << 3);
    *((gconstpointer *) (self->code + 2)) = imm_ptr;
    self->code += 6;
  }
}

void
gum_code_writer_put_mov_imm_ptr_reg (GumCodeWriter * self,
                                     gconstpointer address,
                                     GumCpuReg reg)
{
  if (reg == GUM_REG_EAX)
  {
    self->code[0] = 0xa3;
    *((gconstpointer *) (self->code + 1)) = address;
    self->code += 5;
  }
  else
  {
    self->code[0] = 0x89;
    self->code[1] = (reg << 3) | 0x5;
    *((gconstpointer *) (self->code + 2)) = address;
    self->code += 6;
  }
}

void
gum_code_writer_put_mov_reg_ptr_reg (GumCodeWriter * self,
                                     GumCpuReg dst_reg,
                                     GumCpuReg src_reg)
{
  gum_code_writer_put_mov_reg_offset_ptr_reg (self, dst_reg, 0, src_reg);
}

void
gum_code_writer_put_mov_reg_offset_ptr_reg (GumCodeWriter * self,
                                            GumCpuReg dst_reg,
                                            gint8 dst_offset,
                                            GumCpuReg src_reg)
{
  *self->code++ = 0x89;

  if (dst_offset == 0 && dst_reg != GUM_REG_EBP)
  {
    *self->code++ = 0x00 | (src_reg << 3) | dst_reg;
    if (dst_reg == GUM_REG_ESP)
      *self->code++ = 0x24;
  }
  else
  {
    *self->code++ = 0x40 | (src_reg << 3) | dst_reg;
    if (dst_reg == GUM_REG_ESP)
      *self->code++ = 0x24;
    *self->code++ = dst_offset;
  }
}

void
gum_code_writer_put_mov_reg_reg_ptr (GumCodeWriter * self,
                                     GumCpuReg dst_reg,
                                     GumCpuReg src_reg)
{
  gum_code_writer_put_mov_reg_reg_offset_ptr (self, dst_reg, src_reg, 0);
}

void
gum_code_writer_put_mov_reg_reg_offset_ptr (GumCodeWriter * self,
                                            GumCpuReg dst_reg,
                                            GumCpuReg src_reg,
                                            gssize src_offset)
{
  g_assert (IS_WITHIN_UINT8_RANGE (src_offset));

  self->code[0] = 0x8b;
  self->code[1] = 0x40 | src_reg | (dst_reg << 3);
  self->code += 2;

  if (src_reg == GUM_REG_ESP)
  {
    self->code[0] = 0x24;
    self->code++;
  }

  *((gint8 *) self->code) = src_offset;
  self->code++;
}

void
gum_code_writer_put_mov_fs_u32_ptr_reg (GumCodeWriter * self,
                                        guint32 fs_offset,
                                        GumCpuReg src_reg)
{
  gum_code_writer_put_byte (self, 0x64);
  gum_code_writer_put_mov_imm_ptr_reg (self, GSIZE_TO_POINTER (fs_offset),
      src_reg);
}

void
gum_code_writer_put_mov_reg_fs_u32_ptr (GumCodeWriter * self,
                                        GumCpuReg dst_reg,
                                        guint32 fs_offset)
{
  gum_code_writer_put_byte (self, 0x64);
  gum_code_writer_put_mov_reg_imm_ptr (self, dst_reg,
      GSIZE_TO_POINTER (fs_offset));
}

void
gum_code_writer_put_movq_xmm0_esp_offset_ptr (GumCodeWriter * self,
                                              gint8 offset)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x0f;
  self->code[2] = 0x7e;
  self->code[3] = 0x44;
  self->code[4] = 0x24;
  self->code[5] = offset;
  self->code += 6;
}

void
gum_code_writer_put_movq_eax_offset_ptr_xmm0 (GumCodeWriter * self,
                                              gint8 offset)
{
  self->code[0] = 0x66;
  self->code[1] = 0x0f;
  self->code[2] = 0xd6;
  self->code[3] = 0x40;
  self->code[4] = offset;
  self->code += 5;
}

void
gum_code_writer_put_movdqu_xmm0_esp_offset_ptr (GumCodeWriter * self,
                                                gint8 offset)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x0f;
  self->code[2] = 0x6f;
  self->code[3] = 0x44;
  self->code[4] = 0x24;
  self->code[5] = offset;
  self->code += 6;
}

void
gum_code_writer_put_movdqu_eax_offset_ptr_xmm0 (GumCodeWriter * self,
                                                gint8 offset)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x0f;
  self->code[2] = 0x7f;
  self->code[3] = 0x40;
  self->code[4] = offset;
  self->code += 5;
}

void
gum_code_writer_put_push_u32 (GumCodeWriter * self,
                              guint32 imm_value)
{
  self->code[0] = 0x68;
  *((guint32 *) (self->code + 1)) = imm_value;
  self->code += 5;
}

void
gum_code_writer_put_push_reg (GumCodeWriter * self,
                              GumCpuReg reg)
{
  self->code[0] = 0x50 + reg;
  self->code++;
}

void
gum_code_writer_put_pop_reg (GumCodeWriter * self,
                             GumCpuReg reg)
{
  self->code[0] = 0x58 + reg;
  self->code++;
}

void
gum_code_writer_put_push_imm_ptr (GumCodeWriter * self,
                                  gconstpointer imm_ptr)
{
  self->code[0] = 0xff;
  self->code[1] = 0x35;
  *((gconstpointer *) (self->code + 2)) = imm_ptr;
  self->code += 6;
}

void
gum_code_writer_put_pushad (GumCodeWriter * self)
{
  self->code[0] = 0x60;
  self->code++;
}

void
gum_code_writer_put_popad (GumCodeWriter * self)
{
  self->code[0] = 0x61;
  self->code++;
}

void
gum_code_writer_put_pushfd (GumCodeWriter * self)
{
  self->code[0] = 0x9c;
  self->code++;
}

void
gum_code_writer_put_popfd (GumCodeWriter * self)
{
  self->code[0] = 0x9d;
  self->code++;
}

void
gum_code_writer_put_test_reg_reg (GumCodeWriter * self,
                                  GumCpuReg reg_a,
                                  GumCpuReg reg_b)
{
  self->code[0] = 0x85;
  self->code[1] = 0xc0 | (reg_b << 3) | reg_a;
  self->code += 2;
}

void
gum_code_writer_put_cmp_reg_i32 (GumCodeWriter * self,
                                 GumCpuReg reg,
                                 gint32 imm_value)
{
  if (reg == GUM_REG_EAX)
  {
    *self->code++ = 0x3d;
  }
  else
  {
    self->code[0] = 0x81;
    self->code[1] = 0xf8 | reg;
    self->code += 2;
  }

  *((gint32 *) self->code) = imm_value;
  self->code += 4;
}

void
gum_code_writer_put_cmp_imm_ptr_imm_u32 (GumCodeWriter * self,
                                         gconstpointer imm_ptr,
                                         guint32 imm_value)
{
  self->code[0] = 0x81;
  self->code[1] = 0x3d;
  *((gconstpointer *) (self->code + 2)) = imm_ptr;
  *((guint32 *) (self->code + 6)) = imm_value;
  self->code += 10;
}

void
gum_code_writer_put_pause (GumCodeWriter * self)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x90;
  self->code += 2;
}

void
gum_code_writer_put_nop (GumCodeWriter * self)
{
  self->code[0] = 0x90;
  self->code++;
}

void
gum_code_writer_put_int3 (GumCodeWriter * self)
{
  self->code[0] = 0xcc;
  self->code++;
}

void
gum_code_writer_put_byte (GumCodeWriter * self,
                          guint8 b)
{
  self->code[0] = b;
  self->code++;
}

void
gum_code_writer_put_bytes (GumCodeWriter * self,
                           const guint8 * data,
                           guint n)
{
  memcpy (self->code, data, n);
  self->code += n;
}

static gboolean
gum_cpu_reg_is_wide (GumCpuReg reg)
{
  return (reg >= GUM_REG_RAX && reg <= GUM_REG_RDI);
}

static GumMetaReg
gum_meta_reg_from_cpu_reg (GumCpuReg reg)
{
  if (reg >= GUM_REG_EAX && reg <= GUM_REG_EDI)
    return (GumMetaReg) (GUM_META_REG_XAX + reg - GUM_REG_EAX);
  else if (reg >= GUM_REG_RAX && reg <= GUM_REG_RDI)
    return (GumMetaReg) (GUM_META_REG_XAX + reg - GUM_REG_RAX);
  else
    g_assert_not_reached ();
}
