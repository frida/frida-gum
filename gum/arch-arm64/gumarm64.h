/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_ARM64_H__
#define __GUM_ARM64_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef enum _GumArm64Mnemonic GumArm64Mnemonic;
typedef enum _GumArm64Reg GumArm64Reg;
typedef struct _GumArm64Instruction GumArm64Instruction;

enum _GumArm64Mnemonic
{
  GUM_ARM64_UNKNOWN,

  GUM_ARM64_ADR,
  GUM_ARM64_ADRP
};

enum _GumArm64Reg
{
  GUM_A64REG_X0,
  GUM_A64REG_X1,
  GUM_A64REG_X2,
  GUM_A64REG_X3,
  GUM_A64REG_X4,
  GUM_A64REG_X5,
  GUM_A64REG_X6,
  GUM_A64REG_X7,
  GUM_A64REG_X8,
  GUM_A64REG_X9,
  GUM_A64REG_X10,
  GUM_A64REG_X11,
  GUM_A64REG_X12,
  GUM_A64REG_X13,
  GUM_A64REG_X14,
  GUM_A64REG_X15,
  GUM_A64REG_X16,
  GUM_A64REG_X17,
  GUM_A64REG_X18,
  GUM_A64REG_X19,
  GUM_A64REG_X20,
  GUM_A64REG_X21,
  GUM_A64REG_X22,
  GUM_A64REG_X23,
  GUM_A64REG_X24,
  GUM_A64REG_X25,
  GUM_A64REG_X26,
  GUM_A64REG_X27,
  GUM_A64REG_X28,
  GUM_A64REG_X29,
  GUM_A64REG_X30,

  GUM_A64REG_FP = 29,
  GUM_A64REG_LR = 30,
  GUM_A64REG_SP = 31,
  GUM_A64REG_ZR = 31,

  GUM_A64REG_W0,
  GUM_A64REG_W1,
  GUM_A64REG_W2,
  GUM_A64REG_W3,
  GUM_A64REG_W4,
  GUM_A64REG_W5,
  GUM_A64REG_W6,
  GUM_A64REG_W7,
  GUM_A64REG_W8,
  GUM_A64REG_W9,
  GUM_A64REG_W10,
  GUM_A64REG_W11,
  GUM_A64REG_W12,
  GUM_A64REG_W13,
  GUM_A64REG_W14,
  GUM_A64REG_W15,
  GUM_A64REG_W16,
  GUM_A64REG_W17,
  GUM_A64REG_W18,
  GUM_A64REG_W19,
  GUM_A64REG_W20,
  GUM_A64REG_W21,
  GUM_A64REG_W22,
  GUM_A64REG_W23,
  GUM_A64REG_W24,
  GUM_A64REG_W25,
  GUM_A64REG_W26,
  GUM_A64REG_W27,
  GUM_A64REG_W28,
  GUM_A64REG_W29,
  GUM_A64REG_W30,

  GUM_A64REG_PC,

  GUM_A64REG_NONE
};

struct _GumArm64Instruction
{
  GumArm64Mnemonic mnemonic;

  gconstpointer address;
  guint length;
  GumAddress pc;
};

G_END_DECLS

#endif
