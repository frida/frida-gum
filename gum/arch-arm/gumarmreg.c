/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarmreg.h"

void
gum_arm_reg_describe (arm_reg reg,
                      GumArmRegInfo * ri)
{
  if (reg >= ARM_REG_R0 && reg <= ARM_REG_R12)
  {
    ri->meta = GUM_ARM_MREG_R0 + (reg - ARM_REG_R0);
    ri->width = 32;
    ri->index = ri->meta - GUM_ARM_MREG_R0;
  }
  else if (reg == ARM_REG_SP)
  {
    ri->meta = GUM_ARM_MREG_SP;
    ri->width = 32;
    ri->index = ri->meta - GUM_ARM_MREG_R0;
  }
  else if (reg == ARM_REG_LR)
  {
    ri->meta = GUM_ARM_MREG_LR;
    ri->width = 32;
    ri->index = ri->meta - GUM_ARM_MREG_R0;
  }
  else if (reg == ARM_REG_PC)
  {
    ri->meta = GUM_ARM_MREG_PC;
    ri->width = 32;
    ri->index = ri->meta - GUM_ARM_MREG_R0;
  }
  else if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31)
  {
    ri->meta = GUM_ARM_MREG_S0 + (reg - ARM_REG_S0);
    ri->width = 32;
    ri->index = ri->meta - GUM_ARM_MREG_S0;
  }
  else if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31)
  {
    ri->meta = GUM_ARM_MREG_D0 + (reg - ARM_REG_D0);
    ri->width = 64;
    ri->index = ri->meta - GUM_ARM_MREG_D0;
  }
  else
  {
    g_assert_not_reached ();
  }
}

void
gum_arm_cond_describe (arm_cc cc,
                       guint8 * code)
{
  switch (cc)
  {
    case ARM_CC_EQ:
      *code = 0;
      break;
    case ARM_CC_NE:
      *code = 1;
      break;
    case ARM_CC_HS:
      *code = 2;
      break;
    case ARM_CC_LO:
      *code = 3;
      break;
    case ARM_CC_MI:
      *code = 4;
      break;
    case ARM_CC_PL:
      *code = 5;
      break;
    case ARM_CC_VS:
      *code = 6;
      break;
    case ARM_CC_VC:
      *code = 7;
      break;
    case ARM_CC_HI:
      *code = 8;
      break;
    case ARM_CC_LS:
      *code = 9;
      break;
    case ARM_CC_GE:
      *code = 10;
      break;
    case ARM_CC_LT:
      *code = 11;
      break;
    case ARM_CC_GT:
      *code = 12;
      break;
    case ARM_CC_LE:
      *code = 13;
      break;
    case ARM_CC_AL:
      *code = 14;
      break;
    default:
      g_assert_not_reached ();
      break;
  }
}

void
gum_arm_shifter_describe (arm_shifter shifter,
                          guint8 * scode)
{
  switch (shifter)
  {
    case ARM_SFT_ASR:
      *scode = 2;
      break;
    case ARM_SFT_LSL:
      *scode = 0;
      break;
    case ARM_SFT_LSR:
      *scode = 1;
      break;
    case ARM_SFT_ROR:
      *scode = 3;
      break;
    case ARM_SFT_INVALID:
      *scode = 0;
      break;
    default:
      g_assert_not_reached ();
      break;
  }
}
