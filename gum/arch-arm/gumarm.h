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

#ifndef __GUM_ARM_H__
#define __GUM_ARM_H__

#include "gumdefs.h"

G_BEGIN_DECLS

typedef enum _GumArmMnemonic GumArmMnemonic;
typedef enum _GumArmReg GumArmReg;
typedef struct _GumArmInstruction GumArmInstruction;

enum _GumArmMnemonic
{
  GUM_ARM_ADD_PC,
  GUM_ARM_ADD_SP,
  GUM_ARM_SUB,
  GUM_ARM_PUSH,
  GUM_ARM_POP,
  GUM_ARM_LDR_PC
};

enum _GumArmReg
{
  GUM_AREG_R0,
  GUM_AREG_R1,
  GUM_AREG_R2,
  GUM_AREG_R3,
  GUM_AREG_R4,
  GUM_AREG_R5,
  GUM_AREG_R6,
  GUM_AREG_R7,

  GUM_AREG_SP = 13,
  GUM_AREG_LR,
  GUM_AREG_PC,

  GUM_AREG_NONE,
};

struct _GumArmInstruction
{
  GumArmMnemonic mnemonic;

  gconstpointer address;
};

G_END_DECLS

#endif
