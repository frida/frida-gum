/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthumbrelocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const cs_insn * insn;
  cs_arm * detail;
  GumAddress pc;

  GumThumbWriter * output;
};

static gboolean gum_arm_branch_is_unconditional (const cs_insn * insn);

static gboolean gum_thumb_relocator_rewrite_ldr (GumThumbRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_add (GumThumbRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_b (GumThumbRelocator * self,
    cs_mode target_mode, 
    GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_b_cond (GumThumbRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_bl (GumThumbRelocator * self,
    cs_mode target_mode, GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_cbz (GumThumbRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_it_block_start (
    GumThumbRelocator * self,
    GumCodeGenCtx * ctx);
static void gum_thumb_relocator_rewrite_it_block_else (
    GumThumbRelocator * self,
    GumThumbITBlock * it_block);
static void gum_thumb_relocator_rewrite_it_block_end (GumThumbRelocator * self,
    GumThumbITBlock * it_block);
static gboolean gum_thumb_relocator_fetch_instruction (
    GumThumbRelocator * self,
    const cs_insn ** insn);

GumThumbRelocator *
gum_thumb_relocator_new (gconstpointer input_code,
                         GumThumbWriter * output)
{
  GumThumbRelocator * relocator;

  relocator = g_slice_new (GumThumbRelocator);

  gum_thumb_relocator_init (relocator, input_code, output);

  return relocator;
}

GumThumbRelocator *
gum_thumb_relocator_ref (GumThumbRelocator * relocator)
{
  g_atomic_int_inc (&relocator->ref_count);

  return relocator;
}

void
gum_thumb_relocator_unref (GumThumbRelocator * relocator)
{
  if (g_atomic_int_dec_and_test (&relocator->ref_count))
  {
    gum_thumb_relocator_clear (relocator);

    g_slice_free (GumThumbRelocator, relocator);
  }
}

void
gum_thumb_relocator_init (GumThumbRelocator * relocator,
                          gconstpointer input_code,
                          GumThumbWriter * output)
{
  relocator->ref_count = 1;

  cs_open (CS_ARCH_ARM, CS_MODE_THUMB, &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_thumb_relocator_reset (relocator, input_code, output);
}

void
gum_thumb_relocator_clear (GumThumbRelocator * relocator)
{
  guint i;

  gum_thumb_relocator_reset (relocator, NULL, NULL);

  for (i = 0; i != GUM_MAX_INPUT_INSN_COUNT; i++)
  {
    cs_insn * insn = relocator->input_insns[i];
    if (insn != NULL)
    {
      cs_free (insn, 1);
      relocator->input_insns[i] = NULL;
    }
  }
  g_free (relocator->input_insns);

  cs_close (&relocator->capstone);
}

void
gum_thumb_relocator_reset (GumThumbRelocator * relocator,
                           gconstpointer input_code,
                           GumThumbWriter * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);

  if (output != NULL)
    gum_thumb_writer_ref (output);
  if (relocator->output != NULL)
    gum_thumb_writer_unref (relocator->output);
  relocator->output = output;
  relocator->output_it_block.in_it_block = FALSE;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

static guint
gum_thumb_relocator_inpos (GumThumbRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_thumb_relocator_outpos (GumThumbRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_thumb_relocator_increment_inpos (GumThumbRelocator * self)
{
  self->inpos++;
  g_assert (self->inpos > self->outpos);
}

static void
gum_thumb_relocator_increment_outpos (GumThumbRelocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

static guint8 
gum_thumb_relocator_get_it_scope (guint16 code) 
{
  guint mask = code;

  if (mask & 0x1)
    return 4;
  else if (mask & 0x2)
    return 3;
  else if (mask & 0x4)
    return 2;
  else
    return 1;
}

guint
gum_thumb_relocator_read_one (GumThumbRelocator * self,
                              const cs_insn ** instruction)
{
  const guint8 * input_start = self->input_start;
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;
  gint it_block_size = 0;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_thumb_relocator_inpos (self)];

  if (*insn_ptr == NULL)
    *insn_ptr = cs_malloc (self->capstone);

  code = self->input_cur;
  size = 4;
  address = self->input_pc;
  insn = *insn_ptr;

  if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
    return 0;

  switch (insn->id)
  {
    case ARM_INS_B:
    case ARM_INS_BX:
      self->eob = TRUE;
      self->eoi = gum_arm_branch_is_unconditional (insn);
      break;
    case ARM_INS_BL:
    case ARM_INS_BLX:
      self->eob = TRUE;
      self->eoi = FALSE;
      break;
    case ARM_INS_POP:
      if (cs_reg_read (self->capstone, insn, ARM_REG_PC))
      {
        self->eob = TRUE;
        self->eoi = TRUE;
      }
      else
      {
        self->eob = FALSE;
      }
      break;
    case ARM_INS_IT:
    {
      it_block_size = gum_thumb_relocator_get_it_scope (
          GUINT16_FROM_LE (*((guint16 *) self->input_cur)));
      self->eob = FALSE;
      break;
    }
    default:
      self->eob = FALSE;
      break;
  }

  gum_thumb_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->size;
  self->input_pc += insn->size;

  while (it_block_size--)
    gum_thumb_relocator_read_one (self, NULL);

  return self->input_cur - input_start;
}

cs_insn *
gum_thumb_relocator_peek_next_write_insn (GumThumbRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_thumb_relocator_outpos (self)];
}

gpointer
gum_thumb_relocator_peek_next_write_source (GumThumbRelocator * self)
{
  cs_insn * next;

  next = gum_thumb_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (next->address);
}

void
gum_thumb_relocator_skip_one (GumThumbRelocator * self)
{
  gum_thumb_relocator_peek_next_write_insn (self);
  gum_thumb_relocator_increment_outpos (self);
}

gboolean
gum_thumb_relocator_write_one (GumThumbRelocator * self)
{
  const cs_insn * insn;
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;
  GumThumbITBlock * it_block = &self->output_it_block;

  gboolean succ = gum_thumb_relocator_fetch_instruction(self, &insn);
  if(!succ)
    return FALSE;

  ctx.insn = insn;
  ctx.detail = &insn->detail->arm;
  ctx.pc = insn->address + 4;
  ctx.output = self->output;

  switch (insn->id)
  {
    case ARM_INS_LDR:
      rewritten = gum_thumb_relocator_rewrite_ldr (self, &ctx);
      break;
    case ARM_INS_ADD:
      rewritten = gum_thumb_relocator_rewrite_add (self, &ctx);
      break;
    case ARM_INS_B:
      if (it_block->in_it_block || gum_arm_branch_is_unconditional (ctx.insn))
        rewritten = gum_thumb_relocator_rewrite_b (self, CS_MODE_THUMB, &ctx);
      else
        rewritten = gum_thumb_relocator_rewrite_b_cond (self, &ctx);
      break;
    case ARM_INS_BX:
      rewritten = gum_thumb_relocator_rewrite_b (self, CS_MODE_ARM, &ctx);
      break;
    case ARM_INS_BL:
      rewritten = gum_thumb_relocator_rewrite_bl (self, CS_MODE_THUMB, &ctx);
      break;
    case ARM_INS_BLX:
      rewritten = gum_thumb_relocator_rewrite_bl (self, CS_MODE_ARM, &ctx);
      break;
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
      rewritten = gum_thumb_relocator_rewrite_cbz (self, &ctx);
      break;
    case ARM_INS_IT:
      rewritten = gum_thumb_relocator_rewrite_it_block_start(self, &ctx);
      break;
  }

  if (!rewritten)
    gum_thumb_writer_put_bytes (ctx.output, insn->bytes, insn->size);

  return TRUE;
}

void
gum_thumb_relocator_write_all (GumThumbRelocator * self)
{
  guint count = 0;

  while (gum_thumb_relocator_write_one (self))
    count++;

  g_assert (count > 0);
}

gboolean
gum_thumb_relocator_eob (GumThumbRelocator * self)
{
  return self->eob;
}

gboolean
gum_thumb_relocator_eoi (GumThumbRelocator * self)
{
  return self->eoi;
}

gboolean
gum_thumb_relocator_can_relocate (gpointer address,
                                  guint min_bytes,
                                  GumRelocationScenario scenario,
                                  guint * maximum)
{
  guint n = 0;
  guint8 * buf;
  GumThumbWriter cw;
  GumThumbRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_thumb_writer_init (&cw, buf);

  gum_thumb_relocator_init (&rl, address, &cw);

  do
  {
    const cs_insn * insn;
    gboolean safe_to_relocate_further;

    reloc_bytes = gum_thumb_relocator_read_one (&rl, &insn);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;

    if (scenario == GUM_SCENARIO_ONLINE)
    {
      switch (insn->id)
      {
        case ARM_INS_BL:
        case ARM_INS_BLX:
        case ARM_INS_SVC:
          safe_to_relocate_further = FALSE;
          break;
        default:
          safe_to_relocate_further = TRUE;
          break;
      }
    }
    else
    {
      safe_to_relocate_further = TRUE;
    }

    if (!safe_to_relocate_further)
      break;
  }
  while (reloc_bytes < min_bytes);

  if (rl.eoi)
  {
    if (n < min_bytes)
    {
      gboolean followed_by_nop;

      followed_by_nop = rl.input_cur[0] == 0x00 && rl.input_cur[1] == 0xbf;
      if (followed_by_nop)
        n += 2;
    }
  }
  else
  {
    csh capstone;
    const gsize max_code_size = 1024;
    cs_insn * insn;
    size_t count, i;
    gboolean eoi;

    cs_open (CS_ARCH_ARM, CS_MODE_THUMB, &capstone);
    cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

    gum_ensure_code_readable (rl.input_cur, max_code_size);

    count = cs_disasm (capstone, rl.input_cur, max_code_size, rl.input_pc, 0,
        &insn);
    g_assert (insn != NULL);

    eoi = FALSE;
    for (i = 0; i != count && !eoi; i++)
    {
      guint id = insn[i].id;
      cs_arm * d = &insn[i].detail->arm;

      switch (id)
      {
        case ARM_INS_B:
        case ARM_INS_BX:
        case ARM_INS_BL:
        case ARM_INS_BLX:
        {
          cs_arm_op * op = &d->operands[0];
          if (op->type == ARM_OP_IMM)
          {
            gssize offset =
                (gssize) op->imm - (gssize) GPOINTER_TO_SIZE (address);
            if (offset > 0 && offset < (gssize) n)
              n = offset;
          }
          if (id == ARM_INS_B || id == ARM_INS_BX)
            eoi = d->cc == ARM_CC_INVALID || d->cc == ARM_CC_AL;
          break;
        }
        case ARM_INS_POP:
          eoi = cs_reg_read (capstone, insn, ARM_REG_PC);
          break;
        default:
          break;
      }
    }

    cs_free (insn, count);

    cs_close (&capstone);
  }

  gum_thumb_relocator_clear (&rl);

  gum_thumb_writer_clear (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}

guint
gum_thumb_relocator_relocate (gpointer from,
                              guint min_bytes,
                              gpointer to)
{
  GumThumbWriter cw;
  GumThumbRelocator rl;
  guint reloc_bytes;

  gum_thumb_writer_init (&cw, to);

  gum_thumb_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_thumb_relocator_read_one (&rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < min_bytes);

  gum_thumb_relocator_write_all (&rl);

  gum_thumb_relocator_clear (&rl);
  gum_thumb_writer_clear (&cw);

  return reloc_bytes;
}

static gboolean
gum_arm_branch_is_unconditional (const cs_insn * insn)
{
  switch (insn->detail->arm.cc)
  {
    case ARM_CC_INVALID:
    case ARM_CC_AL:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_thumb_relocator_rewrite_ldr (GumThumbRelocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * src = &ctx->detail->operands[1];
  GumAddress absolute_pc;

  if (src->type != ARM_OP_MEM || src->mem.base != ARM_REG_PC)
    return FALSE;

  absolute_pc = ctx->pc & ~((GumAddress) (4 - 1));
  absolute_pc += src->mem.disp;

  gum_thumb_writer_put_ldr_reg_address (ctx->output, dst->reg, absolute_pc);
  gum_thumb_writer_put_ldr_reg_reg (ctx->output, dst->reg, dst->reg);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_add (GumThumbRelocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * src = &ctx->detail->operands[1];
  arm_reg temp_reg;

  if (ctx->detail->op_count != 2)
    return FALSE;
  else if (src->type != ARM_OP_REG || src->reg != ARM_REG_PC)
    return FALSE;

  if (dst->reg != ARM_REG_R0)
    temp_reg = ARM_REG_R0;
  else
    temp_reg = ARM_REG_R1;

  gum_thumb_writer_put_push_regs (ctx->output, 1, temp_reg);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, temp_reg, ctx->pc);
  gum_thumb_writer_put_add_reg_reg (ctx->output, dst->reg, temp_reg);
  gum_thumb_writer_put_pop_regs (ctx->output, 1, temp_reg);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_b (GumThumbRelocator * self,
                               cs_mode target_mode,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * target = &ctx->detail->operands[0];

  if (target->type != ARM_OP_IMM)
    return FALSE;

  gum_thumb_writer_put_push_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_push_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, ARM_REG_R0,
      (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
  gum_thumb_writer_put_str_reg_reg_offset (ctx->output, ARM_REG_R0,
      ARM_REG_SP, 4);
  gum_thumb_writer_put_pop_regs (ctx->output, 2, ARM_REG_R0, ARM_REG_PC);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_b_cond (GumThumbRelocator * self,
                                    GumCodeGenCtx * ctx)
{
  const cs_arm_op * target = &ctx->detail->operands[0];
  gsize unique_id = GPOINTER_TO_SIZE (ctx->output->code) << 1;
  gconstpointer is_true = GSIZE_TO_POINTER (unique_id | 1);
  gconstpointer is_false = GSIZE_TO_POINTER (unique_id | 0);

  if (target->type != ARM_OP_IMM)
    return FALSE;

  gum_thumb_writer_put_b_cond_label (ctx->output, ctx->detail->cc, is_true);
  gum_thumb_writer_put_b_label (ctx->output, is_false);

  gum_thumb_writer_put_label (ctx->output, is_true);
  gum_thumb_writer_put_push_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_push_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, ARM_REG_R0,
      target->imm | 1);
  gum_thumb_writer_put_str_reg_reg_offset (ctx->output, ARM_REG_R0,
      ARM_REG_SP, 4);
  gum_thumb_writer_put_pop_regs (ctx->output, 2, ARM_REG_R0, ARM_REG_PC);

  gum_thumb_writer_put_label (ctx->output, is_false);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_bl (GumThumbRelocator * self,
                                cs_mode target_mode,
                                GumCodeGenCtx * ctx)
{
  const cs_arm_op * target = &ctx->detail->operands[0];

  if (target->type != ARM_OP_IMM)
    return FALSE;

  gum_thumb_writer_put_push_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, ARM_REG_R0,
      (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
  gum_thumb_writer_put_mov_reg_reg (ctx->output, ARM_REG_LR, ARM_REG_R0);
  gum_thumb_writer_put_pop_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_blx_reg (ctx->output, ARM_REG_LR);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_cbz (GumThumbRelocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm_op * source = &ctx->detail->operands[0];
  const cs_arm_op * target = &ctx->detail->operands[1];
  gsize unique_id = GPOINTER_TO_SIZE (ctx->output->code) << 1;
  gconstpointer is_true = GSIZE_TO_POINTER (unique_id | 1);
  gconstpointer is_false = GSIZE_TO_POINTER (unique_id | 0);

  if (ctx->insn->id == ARM_INS_CBZ)
    gum_thumb_writer_put_cbz_reg_label (ctx->output, source->reg, is_true);
  else
    gum_thumb_writer_put_cbnz_reg_label (ctx->output, source->reg, is_true);
  gum_thumb_writer_put_b_label (ctx->output, is_false);

  gum_thumb_writer_put_label (ctx->output, is_true);
  gum_thumb_writer_put_push_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_push_regs (ctx->output, 1, ARM_REG_R0);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, ARM_REG_R0,
      target->imm | 1);
  gum_thumb_writer_put_str_reg_reg_offset (ctx->output, ARM_REG_R0,
      ARM_REG_SP, 4);
  gum_thumb_writer_put_pop_regs (ctx->output, 2, ARM_REG_R0, ARM_REG_PC);

  gum_thumb_writer_put_label (ctx->output, is_false);

  return TRUE;
}

static void 
gum_thumb_relocator_patch_it_b_instrument (GumThumbITBlockPatch * patch, 
                                           GumAddress target_addr)
{
  gint16 distance;
  distance = target_addr - patch->pc - 4;
  g_assert (distance > 0 && distance < 256);
  *patch->code = (*patch->code & 0xff00) | distance / 2;
}

static void
gum_thumb_relocator_reset_it_b_patch (GumThumbITBlockPatch * patch, 
                                      guint16 * code, 
                                      GumAddress pc)
{
  patch->code = code;
  patch->pc = pc;
}

static void
gum_thumb_relocator_reorder_it_block_insn (GumThumbRelocator * self, 
                                           GumThumbITBlock * it_block,
                                           guint16 it_code) 
{
  guint8 then_bit;
  guint8 index;
  const cs_insn * then_insn[4];
  guint8 then_insn_count;

  /* it instrument format: 10111111ccccpppp 
    cccc:condition pppp:sub instrument state */
  it_block->insn_count = gum_thumb_relocator_get_it_scope (it_code);
  it_block->else_insn_count = 0;
  it_block->curr_insn_pos = 0;

  then_bit = (it_code >> 4) & 1;
  then_insn_count = 0;

  for (index=0;index<it_block->insn_count;index++) 
  {
    guint8 cond_bit;
    const cs_insn * sub_insn;
    
    sub_insn = gum_thumb_relocator_peek_next_write_insn (self);
    g_assert (sub_insn != NULL);
    gum_thumb_relocator_increment_outpos (self);

    cond_bit = (it_code >> (4-index)) & 1;

    if (cond_bit != then_bit) 
    {
      it_block->insns[it_block->else_insn_count] = sub_insn;
      it_block->else_insn_count++;
    } 
    else 
    {
      then_insn[then_insn_count] = sub_insn;
      then_insn_count++;
    }
  }

  for (index=it_block->else_insn_count;index<it_block->insn_count;index++) 
    it_block->insns[index] = then_insn[index-it_block->else_insn_count];
}

static gboolean 
gum_thumb_relocator_rewrite_it_block_start (GumThumbRelocator * self, 
                                            GumCodeGenCtx * ctx) 
{
  guint16 it_code;
  guint8 it_cond;
  GumThumbITBlock * it_block;
  
  it_block = &self->output_it_block;
  it_code = GUINT16_FROM_LE (*((guint16 *) ctx->insn->bytes));
  
  gum_thumb_relocator_reorder_it_block_insn (self, it_block, it_code);

  gum_thumb_relocator_reset_it_b_patch(&it_block->if_b_code, 
      gum_thumb_writer_cur (self->output), 
      gum_thumb_writer_cur_pc (self->output));
  gum_thumb_relocator_reset_it_b_patch(&it_block->else_b_code, NULL,
      (GumAddress)NULL);
  
  it_cond = (it_code >> 4) & 0xf;
  gum_thumb_writer_put_instruction (self->output, 0xd000 | (it_cond << 8));

  it_block->in_it_block = TRUE;
  return TRUE;
}

static void
gum_thumb_relocator_rewrite_it_block_else (GumThumbRelocator * self, 
                                           GumThumbITBlock * it_block) 
{
  GumAddress pc; 

  gum_thumb_relocator_reset_it_b_patch (&it_block->else_b_code, 
    gum_thumb_writer_cur (self->output),
    gum_thumb_writer_cur_pc (self->output));

  gum_thumb_writer_put_instruction (self->output, 0xe000);

  pc = gum_thumb_writer_cur_pc (self->output);
  gum_thumb_relocator_patch_it_b_instrument (&it_block->if_b_code, pc);
  gum_thumb_relocator_reset_it_b_patch (&it_block->if_b_code, NULL,
      (GumAddress)NULL);
}

static void
gum_thumb_relocator_rewrite_it_block_end (GumThumbRelocator * self, 
                                          GumThumbITBlock * it_block) 
{
  GumAddress pc = gum_thumb_writer_cur_pc (self->output);

  if (it_block->if_b_code.pc != (GumAddress)NULL) 
    gum_thumb_relocator_patch_it_b_instrument (&it_block->if_b_code, pc);

  if (it_block->else_b_code.pc != (GumAddress)NULL)
    gum_thumb_relocator_patch_it_b_instrument (&it_block->else_b_code, pc);
}

static gboolean
gum_thumb_relocator_fetch_instruction (GumThumbRelocator * self, 
                                       const cs_insn ** insn)
{
  GumThumbITBlock * it_block = &self->output_it_block;
  
  if (it_block->in_it_block)
  {
    if (it_block->curr_insn_pos < it_block->insn_count)
    {
      if (it_block->curr_insn_pos == it_block->else_insn_count)
        gum_thumb_relocator_rewrite_it_block_else (self, it_block);
      
      *insn = it_block->insns[it_block->curr_insn_pos];
      it_block->curr_insn_pos++;
      return TRUE;
    }
    else
    {
      gum_thumb_relocator_rewrite_it_block_end (self, it_block);
      it_block->in_it_block = FALSE;
    }
  } 
  
  if ((*insn = gum_thumb_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  
  gum_thumb_relocator_increment_outpos (self);

  return TRUE;
}
