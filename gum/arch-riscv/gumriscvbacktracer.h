/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

 #ifndef __GUM_RISCV_BACKTRACER_H__
 #define __GUM_RISCV_BACKTRACER_H__
 
 #include <gum/gumbacktracer.h>
 
 G_BEGIN_DECLS
 
 #define GUM_TYPE_RISCV_BACKTRACER (gum_riscv_backtracer_get_type ())
 G_DECLARE_FINAL_TYPE (GumRiscvBacktracer, gum_riscv_backtracer, GUM, RISCV_BACKTRACER,
                       GObject)
 
 GUM_API GumBacktracer * gum_riscv_backtracer_new (void);
 
 G_END_DECLS
 
 #endif