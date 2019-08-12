/*
 * Copyright (C) 2009-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumx86relocator.h"

#include "gumlibc.h"
#include "gummemory.h"
#include "gumx86reader.h"

#include <string.h>

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  cs_insn * insn;
  guint8 * start;
  guint8 * end;
  guint len;

  GumX86Writer * code_writer;
};

static gboolean gum_x86_relocator_write_one_instruction (GumX86Relocator * self);
static void gum_x86_relocator_put_label_for (GumX86Relocator * self,
    cs_insn * insn);

static gboolean gum_x86_relocator_rewrite_unconditional_branch (
    GumX86Relocator * self, GumCodeGenCtx * ctx);
static gboolean gum_x86_relocator_rewrite_conditional_branch (GumX86Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_x86_relocator_rewrite_if_rip_relative (GumX86Relocator * self,
    GumCodeGenCtx * ctx);

static gboolean gum_x86_call_is_to_next_instruction (cs_insn * insn);
static gboolean gum_x86_call_try_parse_get_pc_thunk (cs_insn * insn,
    GumCpuType cpu_type, GumCpuReg * pc_reg);

GumX86Relocator *
gum_x86_relocator_new (gconstpointer input_code,
                       GumX86Writer * output)
{
  GumX86Relocator * relocator;

  relocator = g_slice_new (GumX86Relocator);

  gum_x86_relocator_init (relocator, input_code, output);

  return relocator;
}

GumX86Relocator *
gum_x86_relocator_ref (GumX86Relocator * relocator)
{
  g_atomic_int_inc (&relocator->ref_count);

  return relocator;
}

void
gum_x86_relocator_unref (GumX86Relocator * relocator)
{
  if (g_atomic_int_dec_and_test (&relocator->ref_count))
  {
    gum_x86_relocator_clear (relocator);

    g_slice_free (GumX86Relocator, relocator);
  }
}

void
gum_x86_relocator_init (GumX86Relocator * relocator,
                        gconstpointer input_code,
                        GumX86Writer * output)
{
  relocator->ref_count = 1;

  cs_open (CS_ARCH_X86,
      (output->target_cpu == GUM_CPU_AMD64) ? CS_MODE_64 : CS_MODE_32,
      &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_x86_relocator_reset (relocator, input_code, output);
}

void
gum_x86_relocator_clear (GumX86Relocator * relocator)
{
  guint i;

  gum_x86_relocator_reset (relocator, NULL, NULL);

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
gum_x86_relocator_reset (GumX86Relocator * relocator,
                         gconstpointer input_code,
                         GumX86Writer * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;

  if (output != NULL)
    gum_x86_writer_ref (output);
  if (relocator->output != NULL)
    gum_x86_writer_unref (relocator->output);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

static guint
gum_x86_relocator_inpos (GumX86Relocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_x86_relocator_outpos (GumX86Relocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_x86_relocator_increment_inpos (GumX86Relocator * self)
{
  self->inpos++;
  g_assert (self->inpos > self->outpos);
}

static void
gum_x86_relocator_increment_outpos (GumX86Relocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

guint
gum_x86_relocator_read_one (GumX86Relocator * self,
                            const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_x86_relocator_inpos (self)];

  if (*insn_ptr == NULL)
    *insn_ptr = cs_malloc (self->capstone);

  code = self->input_cur;
  size = 16;
  address = GPOINTER_TO_SIZE (self->input_cur);
  insn = *insn_ptr;

  if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
    return 0;

  switch (insn->id)
  {
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
      self->eob = TRUE;
      break;

    case X86_INS_JMP:
    case X86_INS_RET:
    case X86_INS_RETF:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;

    case X86_INS_CALL:
      self->eob = !gum_x86_call_is_to_next_instruction (insn) &&
          !gum_x86_call_try_parse_get_pc_thunk (insn, self->output->target_cpu,
              NULL);
      self->eoi = FALSE;
      break;

    default:
      if (gum_x86_reader_insn_is_jcc (insn))
        self->eob = TRUE;
      else
        self->eob = FALSE;
      break;
  }

  gum_x86_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->size;

  return self->input_cur - self->input_start;
}

cs_insn *
gum_x86_relocator_peek_next_write_insn (GumX86Relocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_x86_relocator_outpos (self)];
}

gpointer
gum_x86_relocator_peek_next_write_source (GumX86Relocator * self)
{
  cs_insn * next;

  next = gum_x86_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (next->address);
}

void
gum_x86_relocator_skip_one (GumX86Relocator * self)
{
  cs_insn * next;

  next = gum_x86_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_x86_relocator_increment_outpos (self);

  gum_x86_relocator_put_label_for (self, next);
}

void
gum_x86_relocator_skip_one_no_label (GumX86Relocator * self)
{
  gum_x86_relocator_peek_next_write_insn (self);
  gum_x86_relocator_increment_outpos (self);
}

gboolean
gum_x86_relocator_write_one (GumX86Relocator * self)
{
  cs_insn * cur;

  if ((cur = gum_x86_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  gum_x86_relocator_put_label_for (self, cur);

  return gum_x86_relocator_write_one_instruction (self);
}

gboolean
gum_x86_relocator_write_one_no_label (GumX86Relocator * self)
{
  return gum_x86_relocator_write_one_instruction (self);
}

static gboolean
gum_x86_relocator_write_one_instruction (GumX86Relocator * self)
{
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;

  if ((ctx.insn = gum_x86_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_x86_relocator_increment_outpos (self);

  ctx.len = ctx.insn->size;
  ctx.start = (guint8 *) GSIZE_TO_POINTER (ctx.insn->address);
  ctx.end = ctx.start + ctx.len;

  ctx.code_writer = self->output;

  switch (ctx.insn->id)
  {
    case X86_INS_CALL:
    case X86_INS_JMP:
      rewritten = gum_x86_relocator_rewrite_unconditional_branch (self, &ctx);
      break;

    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
      rewritten = gum_x86_relocator_rewrite_conditional_branch (self, &ctx);
      break;

    default:
      if (gum_x86_reader_insn_is_jcc (ctx.insn))
        rewritten = gum_x86_relocator_rewrite_conditional_branch (self, &ctx);
      else if (self->output->target_cpu == GUM_CPU_AMD64)
        rewritten = gum_x86_relocator_rewrite_if_rip_relative (self, &ctx);
      break;
  }

  if (!rewritten)
    gum_x86_writer_put_bytes (ctx.code_writer, ctx.start, ctx.len);

  return TRUE;
}

void
gum_x86_relocator_write_all (GumX86Relocator * self)
{
  guint count = 0;

  while (gum_x86_relocator_write_one (self))
    count++;

  g_assert (count > 0);
}

gboolean
gum_x86_relocator_eob (GumX86Relocator * self)
{
  return self->eob;
}

gboolean
gum_x86_relocator_eoi (GumX86Relocator * self)
{
  return self->eoi;
}

static void
gum_x86_relocator_put_label_for (GumX86Relocator * self,
                                 cs_insn * insn)
{
  gum_x86_writer_put_label (self->output, GSIZE_TO_POINTER (insn->address));
}

gboolean
gum_x86_relocator_can_relocate (gpointer address,
                                guint min_bytes,
                                guint * maximum)
{
  guint n = 0;
  guint8 * buf;
  GumX86Writer cw;
  GumX86Relocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_x86_writer_init (&cw, buf);

  gum_x86_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;
  }
  while (reloc_bytes < min_bytes);

  gum_x86_relocator_clear (&rl);

  gum_x86_writer_clear (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}

guint
gum_x86_relocator_relocate (gpointer from,
                            guint min_bytes,
                            gpointer to)
{
  GumX86Writer cw;
  GumX86Relocator rl;
  guint reloc_bytes;

  gum_x86_writer_init (&cw, to);

  gum_x86_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (&rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < min_bytes);

  gum_x86_relocator_write_all (&rl);

  gum_x86_relocator_clear (&rl);
  gum_x86_writer_clear (&cw);

  return reloc_bytes;
}

static gboolean
gum_x86_relocator_rewrite_unconditional_branch (GumX86Relocator * self,
                                                GumCodeGenCtx * ctx)
{
  cs_x86_op * op = &ctx->insn->detail->x86.operands[0];
  GumX86Writer * cw = ctx->code_writer;

  if (ctx->insn->id == X86_INS_CALL)
  {
    GumCpuReg pc_reg;

    if (gum_x86_call_is_to_next_instruction (ctx->insn))
    {
      if (cw->target_cpu == GUM_CPU_AMD64)
      {
        gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
        gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
            GUM_ADDRESS (ctx->end));
        gum_x86_writer_put_xchg_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XSP);
      }
      else
      {
        gum_x86_writer_put_push_u32 (cw, GPOINTER_TO_SIZE (ctx->end));
      }

      return TRUE;
    }
    else if (gum_x86_call_try_parse_get_pc_thunk (ctx->insn,
        self->output->target_cpu, &pc_reg))
    {
      gum_x86_writer_put_mov_reg_u32 (cw, pc_reg, GPOINTER_TO_SIZE (ctx->end));
      return TRUE;
    }
  }

  if (op->type == X86_OP_IMM)
  {
    if (ctx->insn->id == X86_INS_CALL)
      gum_x86_writer_put_call_address (cw, op->imm);
    else
      gum_x86_writer_put_jmp_address (cw, op->imm);

    return TRUE;
  }
  else if (((ctx->insn->id == X86_INS_CALL || ctx->insn->id == X86_INS_JMP)
          && op->type == X86_OP_MEM) ||
      (ctx->insn->id == X86_INS_JMP && op->type == X86_OP_IMM && op->size == 8))
  {
    return FALSE;
  }
  else if (op->type == X86_OP_REG)
  {
    return FALSE;
  }
  else
  {
    /* FIXME */
    g_abort ();
  }
}

static gboolean
gum_x86_relocator_rewrite_conditional_branch (GumX86Relocator * self,
                                              GumCodeGenCtx * ctx)
{
  cs_x86_op * op = &ctx->insn->detail->x86.operands[0];

  if (op->type == X86_OP_IMM)
  {
    const guint8 * target = GSIZE_TO_POINTER (op->imm);

    if (target >= self->input_start && target < self->input_cur)
    {
      gum_x86_writer_put_jcc_short_label (ctx->code_writer, ctx->insn->id,
          target, GUM_NO_HINT);
    }
    else if (ctx->insn->id == X86_INS_JECXZ || ctx->insn->id == X86_INS_JRCXZ)
    {
      gsize unique_id = GPOINTER_TO_SIZE (ctx->code_writer->code) << 1;
      gconstpointer is_true = GSIZE_TO_POINTER (unique_id | 1);
      gconstpointer is_false = GSIZE_TO_POINTER (unique_id | 0);

      gum_x86_writer_put_jcc_short_label (ctx->code_writer, ctx->insn->id,
          is_true, GUM_NO_HINT);
      gum_x86_writer_put_jmp_short_label (ctx->code_writer, is_false);

      gum_x86_writer_put_label (ctx->code_writer, is_true);
      gum_x86_writer_put_jmp_address (ctx->code_writer, GUM_ADDRESS (target));

      gum_x86_writer_put_label (ctx->code_writer, is_false);
    }
    else
    {
      gum_x86_writer_put_jcc_near (ctx->code_writer, ctx->insn->id, target,
          GUM_NO_HINT);
    }
  }
  else
  {
    /* FIXME */
    g_abort ();
  }

  return TRUE;
}

static gboolean
gum_x86_relocator_rewrite_if_rip_relative (GumX86Relocator * self,
                                           GumCodeGenCtx * ctx)
{
  cs_insn * insn = ctx->insn;
  cs_x86 * x86 = &insn->detail->x86;
  guint mod, reg, rm;
  gboolean is_rip_relative;
  GumCpuReg cpu_regs[7] = {
    GUM_REG_RAX, GUM_REG_RCX, GUM_REG_RDX, GUM_REG_RBX, GUM_REG_RBP,
    GUM_REG_RSI, GUM_REG_RDI
  };
  x86_reg cs_regs[7] = {
    X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX, X86_REG_RBP,
    X86_REG_RSI, X86_REG_RDI
  };
  gint rip_reg_index, i;
  GumCpuReg other_reg, rip_reg;
  GumAbiType target_abi = self->output->target_abi;
  guint8 code[16];

  if (x86->encoding.modrm_offset == 0)
    return FALSE;

  mod = (x86->modrm & 0xc0) >> 6;
  reg = (x86->modrm & 0x38) >> 3;
  rm  = (x86->modrm & 0x07) >> 0;

  is_rip_relative = (mod == 0 && rm == 5);
  if (!is_rip_relative)
    return FALSE;

  other_reg = (GumCpuReg) (GUM_REG_RAX + reg);

  rip_reg_index = -1;
  for (i = 0; i != G_N_ELEMENTS (cs_regs) && rip_reg_index == -1; i++)
  {
    /*
     * FIXME: These first two checks shouldn't be necessary.
     *        Need to have a closer look at capstone's mappings.
     */
    if (cpu_regs[i] == other_reg)
      continue;
    else if (insn->id == X86_INS_CMPXCHG && cpu_regs[i] == GUM_REG_RAX)
      continue;
    else if (cs_reg_read (self->capstone, ctx->insn, cs_regs[i]))
      continue;
    else if (cs_reg_write (self->capstone, ctx->insn, cs_regs[i]))
      continue;
    rip_reg_index = i;
  }
  g_assert (rip_reg_index != -1);
  rip_reg = cpu_regs[rip_reg_index];

  mod = 2;
  rm = rip_reg - GUM_REG_RAX;

  if (insn->id == X86_INS_PUSH)
  {
    gum_x86_writer_put_push_reg (ctx->code_writer, GUM_REG_RAX);
  }

  if (target_abi == GUM_ABI_UNIX)
  {
    gum_x86_writer_put_lea_reg_reg_offset (ctx->code_writer, GUM_REG_RSP,
        GUM_REG_RSP, -GUM_RED_ZONE_SIZE);
  }
  gum_x86_writer_put_push_reg (ctx->code_writer, rip_reg);
  gum_x86_writer_put_mov_reg_address (ctx->code_writer, rip_reg,
      GUM_ADDRESS (ctx->end));

  if (insn->id == X86_INS_PUSH)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (ctx->code_writer, rip_reg,
        rip_reg, x86->disp);
    gum_x86_writer_put_mov_reg_offset_ptr_reg (ctx->code_writer,
        GUM_REG_RSP,
        0x08 + ((target_abi == GUM_ABI_UNIX) ? GUM_RED_ZONE_SIZE : 0),
        rip_reg);
  }
  else
  {
    gum_memcpy (code, ctx->start, ctx->len);
    code[x86->encoding.modrm_offset] = (mod << 6) | (reg << 3) | rm;
    gum_x86_writer_put_bytes (ctx->code_writer, code, ctx->len);
  }

  gum_x86_writer_put_pop_reg (ctx->code_writer, rip_reg);
  if (target_abi == GUM_ABI_UNIX)
  {
    gum_x86_writer_put_lea_reg_reg_offset (ctx->code_writer, GUM_REG_RSP,
        GUM_REG_RSP, GUM_RED_ZONE_SIZE);
  }

  return TRUE;
}

static gboolean
gum_x86_call_is_to_next_instruction (cs_insn * insn)
{
  cs_x86_op * op = &insn->detail->x86.operands[0];

  return (op->type == X86_OP_IMM
      && (uint64_t) op->imm == insn->address + insn->size);
}

static gboolean
gum_x86_call_try_parse_get_pc_thunk (cs_insn * insn,
                                     GumCpuType cpu_type,
                                     GumCpuReg * pc_reg)
{
  cs_x86_op * op;
  guint8 * p;
  gboolean is_thunk;

  if (cpu_type != GUM_CPU_IA32)
    return FALSE;

  op = &insn->detail->x86.operands[0];
  if (op->type != X86_OP_IMM)
    return FALSE;
  p = (guint8 *) GSIZE_TO_POINTER (op->imm);

  is_thunk =
      ( p[0]         == 0x8b) &&
      ((p[1] & 0xc7) == 0x04) &&
      ( p[2]         == 0x24) &&
      ( p[3]         == 0xc3);
  if (!is_thunk)
    return FALSE;

  if (pc_reg != NULL)
    *pc_reg = (GumCpuReg) ((p[1] & 0x38) >> 3);
  return TRUE;
}
