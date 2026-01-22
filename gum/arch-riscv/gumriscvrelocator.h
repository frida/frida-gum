/*
 * Copyright (C) 2014-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

 #ifndef __GUM_RISCV_RELOCATOR_H__
 #define __GUM_RISCV_RELOCATOR_H__
 
 #include "gumriscvwriter.h"
 
 #include <capstone.h>
 
 G_BEGIN_DECLS
 
 typedef struct _GumRiscvRelocator GumRiscvRelocator;
 
 struct _GumRiscvRelocator
 {
   volatile gint ref_count;
 
   csh capstone;
 
   const guint8 * input_start;
   const guint8 * input_cur;
   GumAddress input_pc;
   cs_insn ** input_insns;
   GumRiscvWriter * output;
 
   guint inpos;
   guint outpos;
 
   gboolean eob;
   gboolean eoi;
 };
 
 GUM_API GumRiscvRelocator * gum_riscv_relocator_new (gconstpointer input_code,
     GumRiscvWriter * output);
 GUM_API GumRiscvRelocator * gum_riscv_relocator_ref (
     GumRiscvRelocator * relocator);
 GUM_API void gum_riscv_relocator_unref (GumRiscvRelocator * relocator);

 GUM_API void gum_riscv_relocator_init (GumRiscvRelocator * relocator,
     gconstpointer input_code, GumRiscvWriter * output);
 GUM_API void gum_riscv_relocator_clear (GumRiscvRelocator * relocator);
 
 GUM_API void gum_riscv_relocator_reset (GumRiscvRelocator * relocator,
     gconstpointer input_code, GumRiscvWriter * output);
 
 GUM_API guint gum_riscv_relocator_read_one (GumRiscvRelocator * self,
     const cs_insn ** instruction);
 
 GUM_API cs_insn * gum_riscv_relocator_peek_next_write_insn (
     GumRiscvRelocator * self);
 GUM_API gpointer gum_riscv_relocator_peek_next_write_source (
     GumRiscvRelocator * self);
 GUM_API void gum_riscv_relocator_skip_one (GumRiscvRelocator * self);
 GUM_API gboolean gum_riscv_relocator_write_one (GumRiscvRelocator * self);
 GUM_API void gum_riscv_relocator_write_all (GumRiscvRelocator * self);
 
 GUM_API gboolean gum_riscv_relocator_eob (GumRiscvRelocator * self);
 GUM_API gboolean gum_riscv_relocator_eoi (GumRiscvRelocator * self);
 
 GUM_API gboolean gum_riscv_relocator_can_relocate (gpointer address,
     guint min_bytes, GumRelocationScenario scenario, guint * maximum,
     riscv_reg * available_scratch_reg);
 GUM_API guint gum_riscv_relocator_relocate (gpointer from, guint min_bytes,
     gpointer to);
 
 G_END_DECLS
 
 #endif