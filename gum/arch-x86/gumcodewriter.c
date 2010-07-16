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
  GUM_META_REG_R8,
  GUM_META_REG_R9,
  GUM_META_REG_R10,
  GUM_META_REG_R11,
  GUM_META_REG_R12,
  GUM_META_REG_R13,
  GUM_META_REG_R14,
  GUM_META_REG_R15
} GumMetaReg;

typedef struct _GumCpuRegInfo GumCpuRegInfo;

struct _GumCpuRegInfo
{
  GumMetaReg meta;
  guint width;
  guint index;
  gboolean index_is_extended;
};

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

static guint8 * gum_code_writer_lookup_address_for_label_id (
    GumCodeWriter * self, gconstpointer id);
static void gum_code_writer_describe_cpu_reg (GumCodeWriter * self,
    GumCpuReg reg, GumCpuRegInfo * ri);

static GumMetaReg gum_meta_reg_from_cpu_reg (GumCpuReg reg);

static void gum_code_writer_put_prefix_for_reg_info (GumCodeWriter * self,
    const GumCpuRegInfo * ri, guint operand_index);

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
#if GLIB_SIZEOF_VOID_P == 4
  writer->target_cpu = GUM_CPU_IA32;
#else
  writer->target_cpu = GUM_CPU_AMD64;
#endif

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

void
gum_code_writer_set_target_cpu (GumCodeWriter * writer,
                                GumCpuType cpu_type)
{
  writer->target_cpu = cpu_type;
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
gum_code_writer_put_call_with_arguments (GumCodeWriter * self,
                                         gpointer func,
                                         guint n_args,
                                         ...)
{
  GPtrArray * args;
  va_list vl;
  gint arg_index;

  g_return_if_fail (n_args > 0 && n_args <= 4);

  args = g_ptr_array_sized_new (n_args);
  va_start (vl, n_args);
  for (arg_index = 0; arg_index != n_args; arg_index++)
    g_ptr_array_add (args, va_arg (vl, gpointer));
  va_end (vl);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    for (arg_index = args->len - 1; arg_index >= 0; arg_index--)
    {
      gum_code_writer_put_push_u32 (self,
          (guint32) g_ptr_array_index (args, arg_index));
    }
    gum_code_writer_put_call (self, func);
    gum_code_writer_put_add_reg_i8 (self, GUM_REG_ESP,
        (gint8) n_args * sizeof (guint32));
  }
  else
  {
    GumCpuReg reg_for_arg[4] = {
      GUM_REG_RCX,
      GUM_REG_RDX,
      GUM_REG_R8,
      GUM_REG_R9
    };
    guint arglist_size;

    arglist_size = n_args * sizeof (guint64);
    if ((arglist_size + 8) % 16 != 0)
    {
      arglist_size = (((arglist_size + 8) + (16 - 1)) & ~(16 - 1)) - 8;
    }

    for (arg_index = args->len - 1; arg_index >= 0; arg_index--)
    {
      gum_code_writer_put_mov_reg_u64 (self, reg_for_arg[arg_index],
          (guint64) g_ptr_array_index (args, arg_index));
    }
    gum_code_writer_put_sub_reg_i8 (self, GUM_REG_RSP, arglist_size);
    gum_code_writer_put_call (self, func);
    gum_code_writer_put_add_reg_i8 (self, GUM_REG_RSP, arglist_size);
  }

  g_ptr_array_free (args, TRUE);
}

void
gum_code_writer_put_call (GumCodeWriter * self,
                          gconstpointer target)
{
  gint64 distance;
  gboolean distance_fits_in_i32;

  distance = (gint64) target - (gint64) (self->code + 5);
  distance_fits_in_i32 = (distance >= G_MININT32 && distance <= G_MAXINT32);

  if (distance_fits_in_i32)
  {
    self->code[0] = 0xe8;
    *((gint32 *) (self->code + 1)) = distance;
    self->code += 5;
  }
  else
  {
    g_assert (self->target_cpu == GUM_CPU_AMD64);

    gum_code_writer_put_mov_reg_u64 (self, GUM_REG_RAX, (guint64) target);
    gum_code_writer_put_call_reg (self, GUM_REG_RAX);
  }
}

void
gum_code_writer_put_call_reg (GumCodeWriter * self,
                              GumCpuReg reg)
{
  GumCpuRegInfo ri;

  gum_code_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (ri.width == 32 && !ri.index_is_extended);
  else
    g_return_if_fail (ri.width == 64);

  if (ri.index_is_extended)
    *self->code++ = 0x41;
  self->code[0] = 0xff;
  self->code[1] = 0xd0 | ri.index;
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
gum_code_writer_put_jmp_reg (GumCodeWriter * self,
                             GumCpuReg reg)
{
  GumCpuRegInfo ri;

  gum_code_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (ri.width == 32 && !ri.index_is_extended);
  else
    g_return_if_fail (ri.width == 64);

  if (ri.index_is_extended)
    *self->code++ = 0x41;
  self->code[0] = 0xff;
  self->code[1] = 0xe0 | ri.index;
  self->code += 2;
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
  GumCpuRegInfo ri;

  gum_code_writer_describe_cpu_reg (self, reg, &ri);

  gum_code_writer_put_prefix_for_reg_info (self, &ri, 0);

  self->code[0] = 0x83;
  self->code[1] = 0xc0 | ri.index;
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
  GumCpuRegInfo ri;

  gum_code_writer_describe_cpu_reg (self, reg, &ri);

  gum_code_writer_put_prefix_for_reg_info (self, &ri, 0);

  self->code[0] = 0x83;
  self->code[1] = 0xe8 | ri.index;
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
  GumCpuRegInfo dst, src;

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_code_writer_describe_cpu_reg (self, src_reg, &src);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (dst.width == 32);
  else
    g_return_if_fail (dst.width == 64);
  g_return_if_fail (!dst.index_is_extended);
  g_return_if_fail (src.width == 32 && !src.index_is_extended);

  self->code[0] = 0xf0; /* lock prefix */
  self->code[1] = 0x0f;
  self->code[2] = 0xb1;
  self->code[3] = 0x00 | (src.index << 3) | dst.index;
  self->code += 4;

  if (dst.meta == GUM_META_REG_XSP)
  {
    *self->code++ = 0x24;
  }
  else if (dst.meta == GUM_META_REG_XBP)
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
gum_code_writer_put_xor_reg_reg (GumCodeWriter * self,
                                 GumCpuReg dst_reg,
                                 GumCpuReg src_reg)
{
  GumCpuRegInfo dst, src;

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_code_writer_describe_cpu_reg (self, src_reg, &src);

  g_return_if_fail (dst.width == src.width);
  g_return_if_fail (!dst.index_is_extended && !src.index_is_extended);

  gum_code_writer_put_prefix_for_reg_info (self, &dst, 0);

  self->code[0] = 0x31;
  self->code[1] = 0xc0 | (src.index << 3) | dst.index;
  self->code += 2;
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
  GumCpuRegInfo dst;

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);

  g_return_if_fail (dst.width == 32);

  gum_code_writer_put_prefix_for_reg_info (self, &dst, 0);

  self->code[0] = 0xb8 | dst.index;
  *((guint32 *) (self->code + 1)) = imm_value;
  self->code += 5;
}

void
gum_code_writer_put_mov_reg_u64 (GumCodeWriter * self,
                                 GumCpuReg dst_reg,
                                 guint64 imm_value)
{
  GumCpuRegInfo dst;

  g_return_if_fail (self->target_cpu == GUM_CPU_AMD64);

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);

  g_return_if_fail (dst.width == 64);

  gum_code_writer_put_prefix_for_reg_info (self, &dst, 0);

  self->code[0] = 0xb8 | dst.index;
  *((guint64 *) (self->code + 1)) = imm_value;
  self->code += 9;
}

void
gum_code_writer_put_mov_reg_address (GumCodeWriter * self,
                                     GumCpuReg dst_reg,
                                     GumAddress address)
{
  GumCpuRegInfo dst;

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (dst.width == 32)
    gum_code_writer_put_mov_reg_u32 (self, dst_reg, (guint32) address);
  else
    gum_code_writer_put_mov_reg_u64 (self, dst_reg, (guint64) address);
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
  GumCpuRegInfo dst, src;

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_code_writer_describe_cpu_reg (self, src_reg, &src);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (dst.width == 32 && src.width == 32);
  else
    g_return_if_fail (dst.width == 64);

  gum_code_writer_put_prefix_for_reg_info (self, &src, 1);

  *self->code++ = 0x89;

  if (dst_offset == 0 && dst.meta != GUM_META_REG_XBP)
  {
    *self->code++ = 0x00 | (src.index << 3) | dst.index;
    if (dst.meta == GUM_META_REG_XSP)
      *self->code++ = 0x24;
  }
  else
  {
    *self->code++ = 0x40 | (src.index << 3) | dst.index;
    if (dst.meta == GUM_META_REG_XSP)
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
  GumCpuRegInfo dst, src;

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_code_writer_describe_cpu_reg (self, src_reg, &src);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (dst.width == 32 && src.width == 32);
  else
    g_return_if_fail (src.width == 64);
  g_return_if_fail (IS_WITHIN_UINT8_RANGE (src_offset));

  gum_code_writer_put_prefix_for_reg_info (self, &dst, 0);

  self->code[0] = 0x8b;
  self->code[1] = 0x40 | (dst.index << 3) | src.index;
  self->code += 2;

  if (src.meta == GUM_META_REG_XSP)
    *self->code++ = 0x24;
  *((gint8 *) self->code) = src_offset;
  self->code++;
}

static void
gum_code_writer_put_mov_reg_imm_ptr (GumCodeWriter * self,
                                     GumCpuReg dst_reg,
                                     guint32 address)
{
  if (dst_reg == GUM_REG_EAX)
  {
    self->code[0] = 0xa1;
    *((guint32 *) (self->code + 1)) = address;
    self->code += 5;
  }
  else
  {
    self->code[0] = 0x8b;
    self->code[1] = 0x05 | (dst_reg << 3);
    *((guint32 *) (self->code + 2)) = address;
    self->code += 6;
  }
}

static void
gum_code_writer_put_mov_imm_ptr_reg (GumCodeWriter * self,
                                     guint32 address,
                                     GumCpuReg src_reg)
{
  if (src_reg == GUM_REG_EAX)
  {
    self->code[0] = 0xa3;
    *((guint32 *) (self->code + 1)) = address;
    self->code += 5;
  }
  else
  {
    self->code[0] = 0x89;
    self->code[1] = (src_reg << 3) | 0x5;
    *((guint32 *) (self->code + 2)) = address;
    self->code += 6;
  }
}

void
gum_code_writer_put_mov_fs_u32_ptr_reg (GumCodeWriter * self,
                                        guint32 fs_offset,
                                        GumCpuReg src_reg)
{
  gum_code_writer_put_byte (self, 0x64);
  gum_code_writer_put_mov_imm_ptr_reg (self, fs_offset, src_reg);
}

void
gum_code_writer_put_mov_reg_fs_u32_ptr (GumCodeWriter * self,
                                        GumCpuReg dst_reg,
                                        guint32 fs_offset)
{
  gum_code_writer_put_byte (self, 0x64);
  gum_code_writer_put_mov_reg_imm_ptr (self, dst_reg, fs_offset);
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
gum_code_writer_put_lea_reg_reg_offset (GumCodeWriter * self,
                                        GumCpuReg dst_reg,
                                        GumCpuReg src_reg,
                                        gssize src_offset)
{
  GumCpuRegInfo dst, src;

  gum_code_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_code_writer_describe_cpu_reg (self, src_reg, &src);

  g_return_if_fail (!dst.index_is_extended && !src.index_is_extended);

  if (self->target_cpu == GUM_CPU_AMD64)
  {
    if (src.width == 32)
      *self->code++ = 0x67;
    if (dst.width == 64)
      *self->code++ = 0x48;
  }

  self->code[0] = 0x8d;
  self->code[1] = 0x80 | (dst.index << 3) | src.index;
  self->code += 2;

  if (src.meta == GUM_META_REG_XSP)
    *self->code++ = 0x24;

  *((gint32 *) self->code) = src_offset;
  self->code += 4;
}

void
gum_code_writer_put_xchg_reg_reg_ptr (GumCodeWriter * self,
                                      GumCpuReg left_reg,
                                      GumCpuReg right_reg)
{
  GumCpuRegInfo left, right;

  gum_code_writer_describe_cpu_reg (self, left_reg, &left);
  gum_code_writer_describe_cpu_reg (self, right_reg, &right);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (right.width == 32);
  else
    g_return_if_fail (right.width == 64);

  gum_code_writer_put_prefix_for_reg_info (self, &left, 1);

  self->code[0] = 0x87;
  self->code[1] = 0x00 | (left.index << 3) | right.index;
  self->code += 2;

  if (right.meta == GUM_META_REG_XSP)
  {
    *self->code++ = 0x24;
  }
  else if (right.meta == GUM_META_REG_XBP)
  {
    self->code[-1] |= 0x40;
    *self->code++ = 0x00;
  }
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
  GumCpuRegInfo ri;

  gum_code_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (ri.width == 32);
  else
    g_return_if_fail (ri.width == 64);

  gum_code_writer_put_prefix_for_reg_info (self, &ri, 0);

  *self->code++ = 0x50 | ri.index;
}

void
gum_code_writer_put_pop_reg (GumCodeWriter * self,
                             GumCpuReg reg)
{
  GumCpuRegInfo ri;

  gum_code_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
    g_return_if_fail (ri.width == 32);
  else
    g_return_if_fail (ri.width == 64);

  gum_code_writer_put_prefix_for_reg_info (self, &ri, 0);

  *self->code++ = 0x58 | ri.index;
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
gum_code_writer_put_pushax (GumCodeWriter * self)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    self->code[0] = 0x60;
    self->code++;
  }
  else
  {
    gum_code_writer_put_push_reg (self, GUM_REG_R15);
    gum_code_writer_put_push_reg (self, GUM_REG_R14);
    gum_code_writer_put_push_reg (self, GUM_REG_R13);
    gum_code_writer_put_push_reg (self, GUM_REG_R12);
    gum_code_writer_put_push_reg (self, GUM_REG_R11);
    gum_code_writer_put_push_reg (self, GUM_REG_R10);
    gum_code_writer_put_push_reg (self, GUM_REG_R9);
    gum_code_writer_put_push_reg (self, GUM_REG_R8);

    gum_code_writer_put_push_reg (self, GUM_REG_RBP);
    gum_code_writer_put_push_reg (self, GUM_REG_RDI);
    gum_code_writer_put_push_reg (self, GUM_REG_RSI);
    gum_code_writer_put_push_reg (self, GUM_REG_RDX);
    gum_code_writer_put_push_reg (self, GUM_REG_RCX);
    gum_code_writer_put_push_reg (self, GUM_REG_RBX);
    gum_code_writer_put_push_reg (self, GUM_REG_RAX);
    gum_code_writer_put_push_reg (self, GUM_REG_RSP);
  }
}

void
gum_code_writer_put_popax (GumCodeWriter * self)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    self->code[0] = 0x61;
    self->code++;
  }
  else
  {
    gum_code_writer_put_pop_reg (self, GUM_REG_RSP);
    gum_code_writer_put_pop_reg (self, GUM_REG_RAX);
    gum_code_writer_put_pop_reg (self, GUM_REG_RBX);
    gum_code_writer_put_pop_reg (self, GUM_REG_RCX);
    gum_code_writer_put_pop_reg (self, GUM_REG_RDX);
    gum_code_writer_put_pop_reg (self, GUM_REG_RSI);
    gum_code_writer_put_pop_reg (self, GUM_REG_RDI);
    gum_code_writer_put_pop_reg (self, GUM_REG_RBP);

    gum_code_writer_put_pop_reg (self, GUM_REG_R8);
    gum_code_writer_put_pop_reg (self, GUM_REG_R9);
    gum_code_writer_put_pop_reg (self, GUM_REG_R10);
    gum_code_writer_put_pop_reg (self, GUM_REG_R11);
    gum_code_writer_put_pop_reg (self, GUM_REG_R12);
    gum_code_writer_put_pop_reg (self, GUM_REG_R13);
    gum_code_writer_put_pop_reg (self, GUM_REG_R14);
    gum_code_writer_put_pop_reg (self, GUM_REG_R15);
  }
}

void
gum_code_writer_put_pushfx (GumCodeWriter * self)
{
  self->code[0] = 0x9c;
  self->code++;
}

void
gum_code_writer_put_popfx (GumCodeWriter * self)
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

static void
gum_code_writer_describe_cpu_reg (GumCodeWriter * self,
                                  GumCpuReg reg,
                                  GumCpuRegInfo * ri)
{
  if (reg >= GUM_REG_XAX && reg <= GUM_REG_XDI)
  {
    if (self->target_cpu == GUM_CPU_IA32)
      reg = (GumCpuReg) (GUM_REG_EAX + reg - GUM_REG_XAX);
    else
      reg = (GumCpuReg) (GUM_REG_RAX + reg - GUM_REG_XAX);
  }

  ri->meta = gum_meta_reg_from_cpu_reg (reg);

  if (reg >= GUM_REG_RAX && reg <= GUM_REG_R15)
  {
    ri->width = 64;

    if (reg < GUM_REG_R8)
    {
      ri->index = reg - GUM_REG_RAX;
      ri->index_is_extended = FALSE;
    }
    else
    {
      ri->index = reg - GUM_REG_R8;
      ri->index_is_extended = TRUE;
    }
  }
  else
  {
    ri->width = 32;

    if (reg < GUM_REG_R8D)
    {
      ri->index = reg - GUM_REG_EAX;
      ri->index_is_extended = FALSE;
    }
    else
    {
      ri->index = reg - GUM_REG_R8D;
      ri->index_is_extended = TRUE;
    }
  }
}

static GumMetaReg
gum_meta_reg_from_cpu_reg (GumCpuReg reg)
{
  if (reg >= GUM_REG_EAX && reg <= GUM_REG_R15D)
    return (GumMetaReg) (GUM_META_REG_XAX + reg - GUM_REG_EAX);
  else if (reg >= GUM_REG_RAX && reg <= GUM_REG_R15)
    return (GumMetaReg) (GUM_META_REG_XAX + reg - GUM_REG_RAX);
  else
    g_assert_not_reached ();
}

static void
gum_code_writer_put_prefix_for_reg_info (GumCodeWriter * self,
                                         const GumCpuRegInfo * ri,
                                         guint operand_index)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    g_return_if_fail (ri->width == 32 && !ri->index_is_extended);
  }
  else
  {
    guint mask;

    mask = 1 << (operand_index * 2);

    if (ri->width == 32)
    {
      if (ri->index_is_extended)
        *self->code++ = 0x40 | mask;
    }
    else
    {
      *self->code++ = (ri->index_is_extended) ? 0x48 | mask : 0x48;
    }
  }
}
