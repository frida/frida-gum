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

#ifndef __GUM_THUMB_WRITER_H__
#define __GUM_THUMB_WRITER_H__

#include "gumarm.h"

#include <gum/gumarray.h>

G_BEGIN_DECLS

typedef struct _GumThumbWriter GumThumbWriter;
typedef struct _GumThumbLabelMapping GumThumbLabelMapping;
typedef struct _GumThumbLabelRef GumThumbLabelRef;
typedef struct _GumThumbU32Ref GumThumbU32Ref;

struct _GumThumbWriter
{
  guint16 * base;
  guint16 * code;

  GumThumbLabelMapping * id_to_address;
  guint id_to_address_len;

  GumThumbLabelRef * label_refs;
  guint label_refs_len;

  GumThumbU32Ref * u32_refs;
  guint u32_refs_len;
};

void gum_thumb_writer_init (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_reset (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_free (GumThumbWriter * writer);

gpointer gum_thumb_writer_cur (GumThumbWriter * self);
guint gum_thumb_writer_offset (GumThumbWriter * self);
void gum_thumb_writer_skip (GumThumbWriter * self, guint n_bytes);

void gum_thumb_writer_flush (GumThumbWriter * self);

void gum_thumb_writer_put_label (GumThumbWriter * self, gconstpointer id);

void gum_thumb_writer_put_bx_reg (GumThumbWriter * self, GumArmReg reg);
void gum_thumb_writer_put_blx_reg (GumThumbWriter * self, GumArmReg reg);
void gum_thumb_writer_put_cbz_reg_label (GumThumbWriter * self, GumArmReg reg,
    gconstpointer label_id);
void gum_thumb_writer_put_cbnz_reg_label (GumThumbWriter * self, GumArmReg reg,
    gconstpointer label_id);

void gum_thumb_writer_put_push_regs (GumThumbWriter * self, guint n_regs, GumArmReg first_reg, ...);
void gum_thumb_writer_put_pop_regs (GumThumbWriter * self, guint n_regs, GumArmReg first_reg, ...);
void gum_thumb_writer_put_ldr_reg_address (GumThumbWriter * self, GumArmReg reg, GumAddress address);
void gum_thumb_writer_put_ldr_reg_u32 (GumThumbWriter * self, GumArmReg reg, guint32 val);
void gum_thumb_writer_put_ldr_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_ldr_reg_reg_offset (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg, guint8 src_offset);
void gum_thumb_writer_put_str_reg_reg (GumThumbWriter * self, GumArmReg src_reg, GumArmReg dst_reg);
void gum_thumb_writer_put_str_reg_reg_offset (GumThumbWriter * self, GumArmReg src_reg, GumArmReg dst_reg, guint8 dst_offset);
void gum_thumb_writer_put_mov_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_mov_reg_u8 (GumThumbWriter * self, GumArmReg dst_reg, guint8 imm_value);
void gum_thumb_writer_put_add_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, gssize imm_value);
void gum_thumb_writer_put_add_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_add_reg_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, GumArmReg right_reg);
void gum_thumb_writer_put_add_reg_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, gssize right_value);
void gum_thumb_writer_put_sub_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, gssize imm_value);
void gum_thumb_writer_put_sub_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_sub_reg_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, GumArmReg right_reg);
void gum_thumb_writer_put_sub_reg_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, gssize right_value);

void gum_thumb_writer_put_nop (GumThumbWriter * self);
void gum_thumb_writer_put_bkpt_imm (GumThumbWriter * self, guint8 imm);
void gum_thumb_writer_put_breakpoint (GumThumbWriter * self);

void gum_thumb_writer_put_bytes (GumThumbWriter * self, const guint8 * data, guint n);

G_END_DECLS

#endif
