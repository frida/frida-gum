/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM_H__
#define __GUM_ARM_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef enum _GumArmMnemonic GumArmMnemonic;
typedef enum _GumArmReg GumArmReg;
typedef struct _GumArmInstruction GumArmInstruction;

enum _GumArmMnemonic
{
  GUM_ARM_UNKNOWN,

  GUM_ARM_BX_REG,
  GUM_ARM_B_IMM_A1,
  GUM_ARM_B_IMM_T2,
  GUM_ARM_B_IMM_T4,
  GUM_ARM_BL_IMM_A1,
  GUM_ARM_BL_IMM_T1,
  GUM_ARM_BLX_IMM_A2,
  GUM_ARM_BLX_IMM_T2,
  GUM_ARM_CBZ,
  GUM_ARM_CBNZ,
  GUM_ARM_ADDH,
  GUM_ARM_ADDPC,
  GUM_ARM_ADDSP,
  GUM_ARM_SUB,
  GUM_ARM_PUSH,
  GUM_ARM_POP,
  GUM_ARM_LDRPC_T1,
  GUM_ARM_LDRPC_T2,
  GUM_ARM_MOV,
  GUM_ARM_LDR
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

  GUM_AREG_R8,
  GUM_AREG_R9,
  GUM_AREG_R10,
  GUM_AREG_R11,
  GUM_AREG_R12,

  GUM_AREG_SP,
  GUM_AREG_LR,
  GUM_AREG_PC,

  GUM_AREG_NONE,
};

struct _GumArmInstruction
{
  GumArmMnemonic mnemonic;

  gconstpointer address;
  guint length;
  GumAddress pc;
};

G_END_DECLS

#endif
