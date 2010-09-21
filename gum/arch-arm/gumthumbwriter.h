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

#include "gumdefs.h"
#include "gumarray.h"

G_BEGIN_DECLS

typedef struct _GumThumbWriter GumThumbWriter;
typedef enum _GumThumbReg       GumThumbReg;

struct _GumThumbWriter
{
  guint16 * base;
  guint16 * code;

  GumArray * u32_refs;
};

enum _GumThumbReg
{
  GUM_TREG_R0,
  GUM_TREG_R1,
  GUM_TREG_R2,
  GUM_TREG_R3,
  GUM_TREG_R4,
  GUM_TREG_R5,
  GUM_TREG_R6,
  GUM_TREG_R7,

  GUM_TREG_SP = 13,
  GUM_TREG_LR,
  GUM_TREG_PC,

  GUM_TREG_NONE,
};

void gum_thumb_writer_init (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_reset (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_free (GumThumbWriter * writer);

gpointer gum_thumb_writer_cur (GumThumbWriter * self);
guint gum_thumb_writer_offset (GumThumbWriter * self);

void gum_thumb_writer_flush (GumThumbWriter * self);

void gum_thumb_writer_put_bx_reg (GumThumbWriter * self, GumThumbReg reg);
void gum_thumb_writer_put_blx_reg (GumThumbWriter * self, GumThumbReg reg);

void gum_thumb_writer_put_push_regs (GumThumbWriter * self, guint n_regs, GumThumbReg first_reg, ...);
void gum_thumb_writer_put_pop_regs (GumThumbWriter * self, guint n_regs, GumThumbReg first_reg, ...);
void gum_thumb_writer_put_ldr_u32 (GumThumbWriter * self, GumThumbReg reg, guint32 val);
void gum_thumb_writer_put_mov_reg_reg (GumThumbWriter * self, GumThumbReg dst_reg, GumThumbReg src_reg);
void gum_thumb_writer_put_mov_reg_u8 (GumThumbWriter * self, GumThumbReg dst_reg, guint8 imm_value);
void gum_thumb_writer_put_add_reg_imm (GumThumbWriter * self, GumThumbReg dst_reg, gssize imm_value);
void gum_thumb_writer_put_add_reg_reg_reg (GumThumbWriter * self, GumThumbReg dst_reg, GumThumbReg left_reg, GumThumbReg right_reg);
void gum_thumb_writer_put_add_reg_reg_imm (GumThumbWriter * self, GumThumbReg dst_reg, GumThumbReg left_reg, gssize right_value);
void gum_thumb_writer_put_sub_reg_imm (GumThumbWriter * self, GumThumbReg dst_reg, gssize imm_value);
void gum_thumb_writer_put_sub_reg_reg_reg (GumThumbWriter * self, GumThumbReg dst_reg, GumThumbReg left_reg, GumThumbReg right_reg);
void gum_thumb_writer_put_sub_reg_reg_imm (GumThumbWriter * self, GumThumbReg dst_reg, GumThumbReg left_reg, gssize right_value);

void gum_thumb_writer_put_nop (GumThumbWriter * self);

G_END_DECLS

#endif
