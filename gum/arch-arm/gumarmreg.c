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
  }
  else if (reg == ARM_REG_SP)
  {
    ri->meta = GUM_ARM_MREG_SP;
    ri->width = 32;
  }
  else if (reg == ARM_REG_LR)
  {
    ri->meta = GUM_ARM_MREG_LR;
    ri->width = 32;
  }
  else if (reg == ARM_REG_PC)
  {
    ri->meta = GUM_ARM_MREG_PC;
    ri->width = 32;
  }
  else
  {
    g_assert_not_reached ();
  }
  ri->index = ri->meta - GUM_ARM_MREG_R0;
}
