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

#ifndef __GUM_ARM_WRITER_H__
#define __GUM_ARM_WRITER_H__

#include "gumarm.h"
#include "gumarray.h"

G_BEGIN_DECLS

typedef struct _GumArmWriter GumArmWriter;

struct _GumArmWriter
{
  guint32 * base;
  guint32 * code;

  GumArray * u32_refs;
};

void gum_arm_writer_init (GumArmWriter * writer, gpointer code_address);
void gum_arm_writer_reset (GumArmWriter * writer, gpointer code_address);
void gum_arm_writer_free (GumArmWriter * writer);

gpointer gum_arm_writer_cur (GumArmWriter * self);
guint gum_arm_writer_offset (GumArmWriter * self);

void gum_arm_writer_flush (GumArmWriter * self);

void gum_arm_writer_put_nop (GumArmWriter * self);

void gum_arm_writer_put_bytes (GumArmWriter * self, const guint8 * data, guint n);

G_END_DECLS

#endif
