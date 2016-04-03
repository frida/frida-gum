/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM_REG_H__
#define __GUM_ARM_REG_H__

#include <capstone.h>
#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef guint GumArmMetaReg;
typedef struct _GumArmRegInfo GumArmRegInfo;

enum _GumArmMetaReg
{
  GUM_ARM_MREG_R0,
  GUM_ARM_MREG_R1,
  GUM_ARM_MREG_R2,
  GUM_ARM_MREG_R3,
  GUM_ARM_MREG_R4,
  GUM_ARM_MREG_R5,
  GUM_ARM_MREG_R6,
  GUM_ARM_MREG_R7,
  GUM_ARM_MREG_R8,
  GUM_ARM_MREG_R9,
  GUM_ARM_MREG_R10,
  GUM_ARM_MREG_R11,
  GUM_ARM_MREG_R12,
  GUM_ARM_MREG_R13,
  GUM_ARM_MREG_R14,
  GUM_ARM_MREG_R15,

  GUM_ARM_MREG_SP = GUM_ARM_MREG_R13,
  GUM_ARM_MREG_LR = GUM_ARM_MREG_R14,

  GUM_ARM_MREG_PC = GUM_ARM_MREG_R15
};

struct _GumArmRegInfo
{
  GumArmMetaReg meta;
  guint width;
  guint index;
};

void gum_arm_reg_describe (arm_reg reg, GumArmRegInfo * ri);

G_END_DECLS

#endif
