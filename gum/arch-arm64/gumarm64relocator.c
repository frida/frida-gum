/*
 * Copyright (C) 2014-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2026 Haiwei Wang <haiwei.wang1109@gmail.com>
 * Copyright (C) 2026 inforcqb <fanjiawei080615@qq.com>
 * Copyright (C) 2026 Jiska Classen <jclassen@seemoo.tu-darmstadt.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

/* Useful reference: C4.1 A64 instruction index by encoding */

#include "gumarm64relocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)
#define GUM_MAX_LIVENESS_INSN_COUNT (64)
#define GUM_MAX_LIVENESS_PATH_COUNT (8)
#define GUM_MAX_RESUME_EXTENSION_INSN_COUNT (16)

#define GUM_GPR_BIT(n) (G_GUINT64_CONSTANT (1) << (n))
#define GUM_GPR_RANGE(first, last) \
    ((GUM_GPR_BIT ((last) + 1) - 1) & ~(GUM_GPR_BIT (first) - 1))
#define GUM_ALL_GPRS GUM_GPR_RANGE (0, 30)
#define GUM_IP_GPRS (GUM_GPR_BIT (16) | GUM_GPR_BIT (17))

typedef struct _GumCodeGenCtx GumCodeGenCtx;
typedef struct _GumLivenessPath GumLivenessPath;
typedef struct _GumReadState GumReadState;

struct _GumCodeGenCtx
{
  const cs_insn * insn;
  cs_arm64 * detail;

  GumArm64Writer * output;
};

struct _GumLivenessPath
{
  GumAddress pc;
  guint64 undecided;
};

struct _GumReadState
{
  const guint8 * input_cur;
  GumAddress input_pc;
  guint inpos;
  gboolean eob;
  gboolean eoi;
};

static gboolean gum_arm64_relocator_insn_is_safe_to_relocate (
    const cs_insn * insn, GumRelocationScenario scenario);
static arm64_reg gum_arm64_relocator_choose_scratch_reg (
    GumArm64Relocator * self, GumAddress pc, GumRelocationScenario scenario,
    arm64_reg requested_reg);
static gboolean gum_arm64_relocator_try_scratch_reg (GumArm64Relocator * self,
    arm64_reg reg, GumRelocationScenario scenario);
static gboolean gum_arm64_relocator_exits_have_regs (GumArm64Relocator * self);
static arm64_reg gum_arm64_relocator_pick_exit_reg_at (
    GumArm64Relocator * self, GumAddress target, guint position);
static gboolean gum_arm64_relocator_touches_reg_before (
    GumArm64Relocator * self, arm64_reg reg, guint position);
static void gum_arm64_relocator_analyze_liveness (GumArm64Relocator * self,
    GumAddress pc, guint64 * dead, guint64 * live);
static void gum_arm64_relocator_describe_gpr_access (GumArm64Relocator * self,
    const cs_insn * insn, guint64 * read, guint64 * written);
static gboolean gum_arm64_relocator_insn_is_trap (const cs_insn * insn);
static gboolean gum_arm64_relocator_insn_is_control_flow (
    GumArm64Relocator * self, const cs_insn * insn);
static gboolean gum_arm64_relocator_code_range_contains (
    GumArm64Relocator * self, GumAddress pc);
static const guint8 * gum_arm64_relocator_peek_code (GumArm64Relocator * self,
    GumAddress pc, size_t * size);
static guint64 gum_arm64_gpr_mask (arm64_reg reg);
static gpointer gum_arm64_relocator_extract_branch_target (
    const cs_insn * insn);

static gboolean gum_arm64_branch_is_unconditional (const cs_insn * insn);

static gboolean gum_arm64_relocator_rewrite_ldr (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_adr (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_b (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_b_cond (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_bl (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_cbz (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_tbz (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static void gum_arm64_relocator_put_exit (GumArm64Relocator * self,
    GumCodeGenCtx * ctx, GumAddress target);

static const arm64_reg gum_scratch_reg_candidates[] = {
  ARM64_REG_X16, ARM64_REG_X17,
  ARM64_REG_X9, ARM64_REG_X10, ARM64_REG_X11, ARM64_REG_X12, ARM64_REG_X13,
  ARM64_REG_X14, ARM64_REG_X15,
  ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_X4,
  ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7, ARM64_REG_X8,
  ARM64_REG_X19, ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_X23,
  ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_X27, ARM64_REG_X28,
};

GumArm64Relocator *
gum_arm64_relocator_new (gconstpointer input_code,
                         GumArm64Writer * output)
{
  GumArm64Relocator * relocator;

  relocator = g_slice_new (GumArm64Relocator);

  gum_arm64_relocator_init (relocator, input_code, output);

  return relocator;
}

GumArm64Relocator *
gum_arm64_relocator_ref (GumArm64Relocator * relocator)
{
  g_atomic_int_inc (&relocator->ref_count);

  return relocator;
}

void
gum_arm64_relocator_unref (GumArm64Relocator * relocator)
{
  if (g_atomic_int_dec_and_test (&relocator->ref_count))
  {
    gum_arm64_relocator_clear (relocator);

    g_slice_free (GumArm64Relocator, relocator);
  }
}

void
gum_arm64_relocator_init (GumArm64Relocator * relocator,
                          gconstpointer input_code,
                          GumArm64Writer * output)
{
  relocator->ref_count = 1;

  cs_arch_register_arm64 ();
  cs_open (CS_ARCH_ARM64, GUM_DEFAULT_CS_ENDIAN, &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_arm64_relocator_reset (relocator, input_code, output);
}

void
gum_arm64_relocator_clear (GumArm64Relocator * relocator)
{
  guint i;

  gum_arm64_relocator_reset (relocator, NULL, NULL);

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
gum_arm64_relocator_reset (GumArm64Relocator * relocator,
                           gconstpointer input_code,
                           GumArm64Writer * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);

  if (output != NULL)
    gum_arm64_writer_ref (output);
  if (relocator->output != NULL)
    gum_arm64_writer_unref (relocator->output);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;

  relocator->scratch_reg = ARM64_REG_X16;
  relocator->code_range.base_address = 0;
  relocator->code_range.size = 0;
}

void
gum_arm64_relocator_set_scratch_reg (GumArm64Relocator * relocator,
                                     arm64_reg reg)
{
  relocator->scratch_reg = reg;
}

void
gum_arm64_relocator_set_code_range (GumArm64Relocator * relocator,
                                    const GumMemoryRange * range)
{
  if (range != NULL)
    relocator->code_range = *range;
  else
    relocator->code_range.base_address = relocator->code_range.size = 0;
}

static guint
gum_arm64_relocator_inpos (GumArm64Relocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_arm64_relocator_outpos (GumArm64Relocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_arm64_relocator_increment_inpos (GumArm64Relocator * self)
{
  self->inpos++;
  g_assert (self->inpos > self->outpos);
}

static void
gum_arm64_relocator_increment_outpos (GumArm64Relocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

guint
gum_arm64_relocator_read_one (GumArm64Relocator * self,
                              const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  if (self->eoi)
    return 0;

  if (!gum_arm64_relocator_code_range_contains (self, self->input_pc))
    return 0;

  insn_ptr = &self->input_insns[gum_arm64_relocator_inpos (self)];

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
    case ARM64_INS_B:
      self->eob = TRUE;
      self->eoi = gum_arm64_branch_is_unconditional (insn);
      break;
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
    case ARM64_INS_RET:
    case ARM64_INS_RETAA:
    case ARM64_INS_RETAB:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
      self->eob = TRUE;
      self->eoi = FALSE;
      break;
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      self->eob = TRUE;
      self->eoi = FALSE;
      break;
    default:
      self->eob = FALSE;
      break;
  }

  gum_arm64_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur = code;
  self->input_pc = address;

  return self->input_cur - self->input_start;
}

gboolean
gum_arm64_relocator_read_until_resumable (GumArm64Relocator * self,
                                          GumRelocationScenario scenario)
{
  guint i;

  for (i = 0; i != GUM_MAX_RESUME_EXTENSION_INSN_COUNT; i++)
  {
    const cs_insn * insn;

    if (self->eoi || gum_arm64_relocator_pick_exit_reg (self,
          self->input_pc) != ARM64_REG_INVALID)
    {
      return TRUE;
    }

    if (gum_arm64_relocator_read_one (self, &insn) == 0 ||
        !gum_arm64_relocator_insn_is_safe_to_relocate (insn, scenario))
    {
      return FALSE;
    }
  }

  return FALSE;
}

arm64_reg
gum_arm64_relocator_pick_exit_reg (GumArm64Relocator * self,
                                   GumAddress target)
{
  return gum_arm64_relocator_pick_exit_reg_at (self, target, self->inpos);
}

cs_insn *
gum_arm64_relocator_peek_next_write_insn (GumArm64Relocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_arm64_relocator_outpos (self)];
}

gpointer
gum_arm64_relocator_peek_next_write_source (GumArm64Relocator * self)
{
  cs_insn * next;

  next = gum_arm64_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (next->address);
}

void
gum_arm64_relocator_skip_one (GumArm64Relocator * self)
{
  gum_arm64_relocator_increment_outpos (self);
}

gboolean
gum_arm64_relocator_write_one (GumArm64Relocator * self)
{
  const cs_insn * insn;
  GumCodeGenCtx ctx;
  gboolean rewritten;

  if ((insn = gum_arm64_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_arm64_relocator_increment_outpos (self);
  ctx.insn = insn;
  ctx.detail = &ctx.insn->detail->arm64;
  ctx.output = self->output;

  switch (insn->id)
  {
    case ARM64_INS_LDR:
    case ARM64_INS_LDRSW:
      rewritten = gum_arm64_relocator_rewrite_ldr (self, &ctx);
      break;
    case ARM64_INS_ADR:
    case ARM64_INS_ADRP:
      rewritten = gum_arm64_relocator_rewrite_adr (self, &ctx);
      break;
    case ARM64_INS_B:
      if (gum_arm64_branch_is_unconditional (ctx.insn))
        rewritten = gum_arm64_relocator_rewrite_b (self, &ctx);
      else
        rewritten = gum_arm64_relocator_rewrite_b_cond (self, &ctx);
      break;
    case ARM64_INS_BL:
      rewritten = gum_arm64_relocator_rewrite_bl (self, &ctx);
      break;
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
      rewritten = gum_arm64_relocator_rewrite_cbz (self, &ctx);
      break;
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      rewritten = gum_arm64_relocator_rewrite_tbz (self, &ctx);
      break;
    default:
      rewritten = FALSE;
      break;
  }

  if (!rewritten)
    gum_arm64_writer_put_bytes (ctx.output, insn->bytes, insn->size);

  return TRUE;
}

void
gum_arm64_relocator_write_all (GumArm64Relocator * self)
{
  G_GNUC_UNUSED guint count = 0;

  while (gum_arm64_relocator_write_one (self))
    count++;

  g_assert (count > 0);
}

gboolean
gum_arm64_relocator_eob (GumArm64Relocator * self)
{
  return self->eob;
}

gboolean
gum_arm64_relocator_eoi (GumArm64Relocator * self)
{
  return self->eoi;
}

gboolean
gum_arm64_relocator_can_relocate (gpointer address,
                                  guint min_bytes,
                                  GumRelocationScenario scenario,
                                  GumRelocationPolicy policy,
                                  guint * maximum,
                                  arm64_reg * available_scratch_reg)
{
  return gum_arm64_relocator_can_relocate_within (address,
      GUM_ADDRESS (address), min_bytes, scenario, policy, NULL, maximum,
      available_scratch_reg);
}

gboolean
gum_arm64_relocator_can_relocate_within (gpointer address,
                                         GumAddress pc,
                                         guint min_bytes,
                                         GumRelocationScenario scenario,
                                         GumRelocationPolicy policy,
                                         const GumMemoryRange * code_range,
                                         guint * maximum,
                                         arm64_reg * available_scratch_reg)
{
  guint n = 0;
  guint8 * buf;
  GumArm64Writer cw;
  GumArm64Relocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_arm64_writer_init (&cw, buf);

  gum_arm64_relocator_init (&rl, address, &cw);
  rl.input_pc = pc;
  gum_arm64_relocator_set_code_range (&rl, code_range);

  do
  {
    const cs_insn * insn;

    reloc_bytes = gum_arm64_relocator_read_one (&rl, &insn);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;

    if (!gum_arm64_relocator_insn_is_safe_to_relocate (insn, scenario))
      break;
  }
  while (reloc_bytes < min_bytes);

  if (policy == GUM_RELOCATION_CHECKED && !rl.eoi)
  {
    GHashTable * checked_targets, * targets_to_check;
    csh capstone;
    cs_insn * insn;
    GumAddress current_pc;
    gboolean have_pc;
    gpointer target;
    GHashTableIter iter;
    guint insn_index;
    guint num_insns;

    checked_targets = g_hash_table_new (NULL, NULL);
    targets_to_check = g_hash_table_new (NULL, NULL);

    /*
     * Relocated conditional/unconditional branches are rewritten as absolute
     * jumps back to the original target address. If that target lies inside the
     * range we are about to overwrite, the rewritten branch would land in the
     * middle of the redirect patch. Shrink the range so every such target falls
     * outside it. Also keep out-of-range targets queued for reachability checks
     * below, since those paths must not jump back into the patch either.
     */
    num_insns = n / 4;
    for (insn_index = 0; insn_index != num_insns; insn_index++)
    {
      const cs_insn * input_insn = rl.input_insns[insn_index];
      gssize offset;

      if (input_insn == NULL)
        break;

      /* Instruction was cut out by an earlier shrink. */
      if (insn_index * 4 >= n)
        break;

      target = gum_arm64_relocator_extract_branch_target (input_insn);
      if (target == NULL)
        continue;

      offset = (gssize) (GUM_ADDRESS (target) - pc);
      if (offset > 0 && offset < (gssize) n)
        n = (guint) offset;
      else if (offset >= (gssize) n)
        g_hash_table_add (targets_to_check, target);
    }

    /*
     * If an internal branch forced us to shrink n, rewind so the reachability
     * scan below starts at the new relocatable boundary rather than wherever
     * read_one() stopped when trying to satisfy min_bytes.
     */
    rl.input_cur = (const guint8 *) address + n;
    rl.input_pc = pc + n;
    rl.inpos = n / 4;

    cs_open (CS_ARCH_ARM64, GUM_DEFAULT_CS_ENDIAN, &capstone);
    cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

    insn = cs_malloc (capstone);
    current_pc = rl.input_pc;

    do
    {
      const uint8_t * current_code;
      size_t current_code_size;
      uint64_t current_address;
      gboolean carry_on = TRUE;

      g_hash_table_add (checked_targets, GSIZE_TO_POINTER (current_pc));

      current_code_size = 1024;
      current_code = gum_arm64_relocator_peek_code (&rl, current_pc,
          &current_code_size);
      current_address = current_pc;

      while (carry_on && current_code != NULL &&
          cs_disasm_iter (capstone, &current_code, &current_code_size,
            &current_address, insn))
      {
        cs_arm64 * d = &insn->detail->arm64;

        switch (insn->id)
        {
          case ARM64_INS_B:
          {
            target = gum_arm64_relocator_extract_branch_target (insn);
            g_assert (target != NULL);
            if (!g_hash_table_contains (checked_targets, target))
              g_hash_table_add (targets_to_check, target);

            carry_on = d->cc != ARM64_CC_INVALID && d->cc != ARM64_CC_AL &&
                d->cc != ARM64_CC_NV;

            break;
          }
          case ARM64_INS_CBZ:
          case ARM64_INS_CBNZ:
          case ARM64_INS_TBZ:
          case ARM64_INS_TBNZ:
          {
            target = gum_arm64_relocator_extract_branch_target (insn);
            g_assert (target != NULL);
            if (!g_hash_table_contains (checked_targets, target))
              g_hash_table_add (targets_to_check, target);

            break;
          }
          case ARM64_INS_RET:
          case ARM64_INS_RETAA:
          case ARM64_INS_RETAB:
          {
            carry_on = FALSE;
            break;
          }
          case ARM64_INS_BR:
          case ARM64_INS_BRAA:
          case ARM64_INS_BRAAZ:
          case ARM64_INS_BRAB:
          case ARM64_INS_BRABZ:
          {
            carry_on = FALSE;
            break;
          }
          default:
            break;
        }
      }

      g_hash_table_iter_init (&iter, targets_to_check);
      have_pc = g_hash_table_iter_next (&iter, &target, NULL);
      if (have_pc)
      {
        current_pc = GUM_ADDRESS (target);
        g_hash_table_iter_remove (&iter);
      }
    }
    while (have_pc);

    g_hash_table_iter_init (&iter, checked_targets);
    while (g_hash_table_iter_next (&iter, &target, NULL))
    {
      gssize offset = (gssize) (GUM_ADDRESS (target) - pc);
      if (offset > 0 && offset < (gssize) n)
      {
        n = offset;
        if (n == 4)
          break;
      }
    }

    cs_free (insn, 1);

    cs_close (&capstone);

    g_hash_table_unref (targets_to_check);
    g_hash_table_unref (checked_targets);
  }

  if (available_scratch_reg != NULL)
  {
    *available_scratch_reg = gum_arm64_relocator_choose_scratch_reg (&rl, pc,
        scenario, *available_scratch_reg);
  }

  gum_arm64_relocator_clear (&rl);

  gum_arm64_writer_clear (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}

static gboolean
gum_arm64_relocator_insn_is_safe_to_relocate (const cs_insn * insn,
                                              GumRelocationScenario scenario)
{
  if (scenario == GUM_SCENARIO_OFFLINE)
    return TRUE;

  switch (insn->id)
  {
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_SVC:
      return FALSE;
    default:
      return TRUE;
  }
}

static arm64_reg
gum_arm64_relocator_choose_scratch_reg (GumArm64Relocator * self,
                                        GumAddress pc,
                                        GumRelocationScenario scenario,
                                        arm64_reg requested_reg)
{
  guint num_block_insns = self->inpos;
  guint64 dead, live;
  arm64_reg attempts[3 * G_N_ELEMENTS (gum_scratch_reg_candidates)];
  guint num_attempts, i;

  gum_arm64_relocator_analyze_liveness (self, pc, &dead, &live);

  if (requested_reg != ARM64_REG_INVALID)
  {
    if ((live & gum_arm64_gpr_mask (requested_reg)) == 0 &&
        gum_arm64_relocator_try_scratch_reg (self, requested_reg, scenario))
      return requested_reg;

    return ARM64_REG_INVALID;
  }

  num_attempts = 0;

  for (i = 0; i != G_N_ELEMENTS (gum_scratch_reg_candidates); i++)
  {
    arm64_reg reg = gum_scratch_reg_candidates[i];

    if ((dead & gum_arm64_gpr_mask (reg)) != 0 &&
        !gum_arm64_relocator_touches_reg_before (self, reg, num_block_insns))
      attempts[num_attempts++] = reg;
  }

  if ((live & GUM_GPR_BIT (16)) == 0)
    attempts[num_attempts++] = ARM64_REG_X16;
  if ((live & GUM_GPR_BIT (17)) == 0)
    attempts[num_attempts++] = ARM64_REG_X17;

  for (i = 0; i != G_N_ELEMENTS (gum_scratch_reg_candidates); i++)
  {
    arm64_reg reg = gum_scratch_reg_candidates[i];

    if ((dead & gum_arm64_gpr_mask (reg)) != 0)
      attempts[num_attempts++] = reg;
  }

  for (i = 0; i != num_attempts; i++)
  {
    if (gum_arm64_relocator_try_scratch_reg (self, attempts[i], scenario))
      return attempts[i];
  }

  return ARM64_REG_INVALID;
}

static gboolean
gum_arm64_relocator_try_scratch_reg (GumArm64Relocator * self,
                                     arm64_reg reg,
                                     GumRelocationScenario scenario)
{
  GumReadState state = {
    .input_cur = self->input_cur,
    .input_pc = self->input_pc,
    .inpos = self->inpos,
    .eob = self->eob,
    .eoi = self->eoi
  };

  gum_arm64_relocator_set_scratch_reg (self, reg);

  if (gum_arm64_relocator_read_until_resumable (self, scenario) &&
      gum_arm64_relocator_exits_have_regs (self))
  {
    return TRUE;
  }

  self->input_cur = state.input_cur;
  self->input_pc = state.input_pc;
  self->inpos = state.inpos;
  self->eob = state.eob;
  self->eoi = state.eoi;

  return FALSE;
}

static gboolean
gum_arm64_relocator_exits_have_regs (GumArm64Relocator * self)
{
  guint i;

  for (i = 0; i != self->inpos; i++)
  {
    gpointer target;

    target = gum_arm64_relocator_extract_branch_target (self->input_insns[i]);
    if (target != NULL && gum_arm64_relocator_pick_exit_reg_at (self,
          GUM_ADDRESS (target), i) == ARM64_REG_INVALID)
    {
      return FALSE;
    }
  }

  return TRUE;
}

static arm64_reg
gum_arm64_relocator_pick_exit_reg_at (GumArm64Relocator * self,
                                      GumAddress target,
                                      guint position)
{
  guint64 dead, live;
  guint i;

  if (self->scratch_reg != ARM64_REG_INVALID &&
      !gum_arm64_relocator_touches_reg_before (self, self->scratch_reg,
        position))
  {
    return self->scratch_reg;
  }

  gum_arm64_relocator_analyze_liveness (self, target, &dead, &live);

  for (i = 0; i != G_N_ELEMENTS (gum_scratch_reg_candidates); i++)
  {
    arm64_reg reg = gum_scratch_reg_candidates[i];

    if ((dead & gum_arm64_gpr_mask (reg)) != 0)
      return reg;
  }

  return ARM64_REG_INVALID;
}

static gboolean
gum_arm64_relocator_touches_reg_before (GumArm64Relocator * self,
                                        arm64_reg reg,
                                        guint position)
{
  guint64 mask = gum_arm64_gpr_mask (reg);
  guint first, i;

  first = (position > GUM_MAX_INPUT_INSN_COUNT)
      ? position - GUM_MAX_INPUT_INSN_COUNT
      : 0;

  for (i = first; i != position; i++)
  {
    guint64 read, written;

    gum_arm64_relocator_describe_gpr_access (self,
        self->input_insns[i % GUM_MAX_INPUT_INSN_COUNT], &read, &written);

    if (((read | written) & mask) != 0)
      return TRUE;
  }

  return FALSE;
}

static void
gum_arm64_relocator_analyze_liveness (GumArm64Relocator * self,
                                      GumAddress pc,
                                      guint64 * dead,
                                      guint64 * live)
{
  GumLivenessPath paths[GUM_MAX_LIVENESS_PATH_COUNT];
  guint num_paths, budget;
  guint64 unknown;
  cs_insn * insn;

  *live = 0;
  unknown = 0;

  paths[0].pc = pc;
  paths[0].undecided = GUM_ALL_GPRS;
  num_paths = 1;
  budget = GUM_MAX_LIVENESS_INSN_COUNT;

  insn = cs_malloc (self->capstone);

  while (num_paths != 0)
  {
    GumLivenessPath path = paths[--num_paths];

    while (path.undecided != 0)
    {
      const uint8_t * code;
      size_t size;
      uint64_t address;
      guint64 read, written;
      gpointer target;

      if (budget == 0)
        break;
      budget--;

      size = 4;
      code = gum_arm64_relocator_peek_code (self, path.pc, &size);
      if (code == NULL)
        break;
      address = path.pc;

      if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
        break;

      if (gum_arm64_relocator_insn_is_trap (insn))
      {
        path.undecided = 0;
        break;
      }

      gum_arm64_relocator_describe_gpr_access (self, insn, &read, &written);
      *live |= read & path.undecided;
      path.undecided &= ~(read | written);

      if (!gum_arm64_relocator_insn_is_control_flow (self, insn))
      {
        path.pc += 4;
        continue;
      }

      target = gum_arm64_relocator_extract_branch_target (insn);
      if (target == NULL)
        break;

      if (!gum_arm64_relocator_code_range_contains (self, GUM_ADDRESS (target)))
      {
        if (gum_arm64_branch_is_unconditional (insn) &&
            insn->id == ARM64_INS_B)
        {
          path.undecided &= ~GUM_IP_GPRS;
          break;
        }

        unknown |= path.undecided & ~GUM_IP_GPRS;
        path.pc += 4;
        continue;
      }

      if (insn->id == ARM64_INS_B && gum_arm64_branch_is_unconditional (insn))
      {
        path.pc = GUM_ADDRESS (target);
        continue;
      }

      if (num_paths == GUM_MAX_LIVENESS_PATH_COUNT)
        break;

      paths[num_paths].pc = GUM_ADDRESS (target);
      paths[num_paths].undecided = path.undecided;
      num_paths++;

      path.pc += 4;
    }

    unknown |= path.undecided;
  }

  cs_free (insn, 1);

  *dead = GUM_ALL_GPRS & ~*live & ~unknown;
}

static void
gum_arm64_relocator_describe_gpr_access (GumArm64Relocator * self,
                                         const cs_insn * insn,
                                         guint64 * read,
                                         guint64 * written)
{
  cs_regs regs_read, regs_written;
  uint8_t num_regs_read, num_regs_written, i;
  gboolean may_be_compare_alias;

  *read = 0;
  *written = 0;

  switch (insn->id)
  {
    case ARM64_INS_SVC:
      *read = GUM_GPR_RANGE (0, 8) | GUM_GPR_BIT (16);
      return;
    case ARM64_INS_HVC:
    case ARM64_INS_SMC:
      *read = GUM_GPR_RANGE (0, 17);
      return;
    default:
      break;
  }

  if (cs_regs_access (self->capstone, insn, regs_read, &num_regs_read,
        regs_written, &num_regs_written) != CS_ERR_OK)
  {
    *read = GUM_ALL_GPRS;
    return;
  }

  for (i = 0; i != num_regs_read; i++)
    *read |= gum_arm64_gpr_mask (regs_read[i]);

  may_be_compare_alias = FALSE;
  for (i = 0; i != num_regs_written; i++)
  {
    if (regs_written[i] == ARM64_REG_NZCV)
      may_be_compare_alias = TRUE;
  }

  for (i = 0; i != num_regs_written; i++)
  {
    guint64 mask = gum_arm64_gpr_mask (regs_written[i]);

    if (may_be_compare_alias)
      *read |= mask;
    else
      *written |= mask;
  }
}

static gboolean
gum_arm64_relocator_insn_is_trap (const cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM64_INS_BRK:
    case ARM64_INS_HLT:
    case ARM64_INS_UDF:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_arm64_relocator_insn_is_control_flow (GumArm64Relocator * self,
                                          const cs_insn * insn)
{
  return cs_insn_group (self->capstone, insn, CS_GRP_JUMP) ||
      cs_insn_group (self->capstone, insn, CS_GRP_CALL) ||
      cs_insn_group (self->capstone, insn, CS_GRP_RET) ||
      cs_insn_group (self->capstone, insn, CS_GRP_BRANCH_RELATIVE);
}

static gboolean
gum_arm64_relocator_code_range_contains (GumArm64Relocator * self,
                                         GumAddress pc)
{
  const GumMemoryRange * range = &self->code_range;

  if (range->size == 0)
    return TRUE;

  return pc >= range->base_address && pc < range->base_address + range->size;
}

static const guint8 *
gum_arm64_relocator_peek_code (GumArm64Relocator * self,
                               GumAddress pc,
                               size_t * size)
{
  const GumMemoryRange * range = &self->code_range;
  const guint8 * code;

  if (range->size != 0)
  {
    GumAddress end = range->base_address + range->size;

    if (pc < range->base_address || pc >= end)
      return NULL;

    *size = MIN (*size, end - pc);
  }

  code = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (self->input_cur) - self->input_pc + pc);

  gum_ensure_code_readable (code, *size);

  return code;
}

static guint64
gum_arm64_gpr_mask (arm64_reg reg)
{
  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
    return GUM_GPR_BIT (reg - ARM64_REG_X0);

  if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28)
    return GUM_GPR_BIT (reg - ARM64_REG_W0);

  if (reg == ARM64_REG_X29 || reg == ARM64_REG_W29)
    return GUM_GPR_BIT (29);

  if (reg == ARM64_REG_X30 || reg == ARM64_REG_W30)
    return GUM_GPR_BIT (30);

  return 0;
}

static gpointer
gum_arm64_relocator_extract_branch_target (const cs_insn * insn)
{
  const cs_arm64 * d = &insn->detail->arm64;
  const cs_arm64_op * op;

  switch (insn->id)
  {
    case ARM64_INS_B:
      op = &d->operands[0];
      break;
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
      op = &d->operands[1];
      break;
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      op = &d->operands[2];
      break;
    default:
      return NULL;
  }

  if (op->type != ARM64_OP_IMM)
    return NULL;

  return GSIZE_TO_POINTER (op->imm);
}

guint
gum_arm64_relocator_relocate (gpointer from,
                              guint min_bytes,
                              gpointer to)
{
  GumArm64Writer cw;
  GumArm64Relocator rl;
  guint reloc_bytes;

  gum_arm64_writer_init (&cw, to);

  gum_arm64_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_arm64_relocator_read_one (&rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < min_bytes);

  gum_arm64_relocator_write_all (&rl);

  gum_arm64_relocator_clear (&rl);
  gum_arm64_writer_clear (&cw);

  return reloc_bytes;
}

static gboolean
gum_arm64_branch_is_unconditional (const cs_insn * insn)
{
  switch (insn->detail->arm64.cc)
  {
    case ARM64_CC_INVALID:
    case ARM64_CC_AL:
    case ARM64_CC_NV:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_arm64_relocator_rewrite_ldr (GumArm64Relocator * self,
                                 GumCodeGenCtx * ctx)
{
  arm64_insn insn_id = ctx->insn->id;
  const cs_arm64_op * dst = &ctx->detail->operands[0];
  const cs_arm64_op * src = &ctx->detail->operands[1];
  gboolean dst_reg_is_fp_or_simd;
  arm64_reg tmp_reg;

  if (src->type != ARM64_OP_IMM)
    return FALSE;

  dst_reg_is_fp_or_simd =
      (dst->reg >= ARM64_REG_S0 && dst->reg <= ARM64_REG_S31) ||
      (dst->reg >= ARM64_REG_D0 && dst->reg <= ARM64_REG_D31) ||
      (dst->reg >= ARM64_REG_Q0 && dst->reg <= ARM64_REG_Q31);

  if (insn_id == ARM64_INS_LDR && !dst_reg_is_fp_or_simd &&
      (gum_arm64_writer_put_ldr_reg_u64_ptr (ctx->output, dst->reg, src->imm) ||
       gum_arm64_writer_put_ldr_reg_u32_ptr (ctx->output, dst->reg, src->imm)))
  {
    return TRUE;
  }

  if (dst_reg_is_fp_or_simd)
  {
    tmp_reg = ARM64_REG_X0;

    gum_arm64_writer_put_push_reg_reg (ctx->output, tmp_reg, ARM64_REG_X1);

    gum_arm64_writer_put_ldr_reg_address (ctx->output, tmp_reg, src->imm);
    g_assert (insn_id == ARM64_INS_LDR);
    gum_arm64_writer_put_ldr_reg_reg_offset (ctx->output, dst->reg, tmp_reg, 0);

    gum_arm64_writer_put_pop_reg_reg (ctx->output, tmp_reg, ARM64_REG_X1);
  }
  else
  {
    if (dst->reg >= ARM64_REG_W0 && dst->reg <= ARM64_REG_W28)
      tmp_reg = ARM64_REG_X0 + (dst->reg - ARM64_REG_W0);
    else if (dst->reg >= ARM64_REG_W29 && dst->reg <= ARM64_REG_W30)
      tmp_reg = ARM64_REG_X29 + (dst->reg - ARM64_REG_W29);
    else
      tmp_reg = dst->reg;

    gum_arm64_writer_put_ldr_reg_address (ctx->output, tmp_reg, src->imm);
    if (insn_id == ARM64_INS_LDR)
    {
      gum_arm64_writer_put_ldr_reg_reg_offset (ctx->output, dst->reg, tmp_reg,
          0);
    }
    else
    {
      gum_arm64_writer_put_ldrsw_reg_reg_offset (ctx->output, dst->reg, tmp_reg,
          0);
    }
  }

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_adr (GumArm64Relocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm64_op * dst = &ctx->detail->operands[0];
  const cs_arm64_op * label = &ctx->detail->operands[1];

  g_assert (label->type == ARM64_OP_IMM);

  if (ctx->insn->id == ARM64_INS_ADRP)
  {
    if (gum_arm64_writer_put_adrp_reg_address (ctx->output, dst->reg,
        label->imm))
    {
      return TRUE;
    }
  }
  else if (gum_arm64_writer_put_adrp_reg_address (ctx->output, dst->reg,
      label->imm & ~G_GUINT64_CONSTANT (0xfff)))
  {
    gum_arm64_writer_put_add_reg_reg_imm (ctx->output, dst->reg, dst->reg,
        label->imm & 0xfff);
    return TRUE;
  }

  gum_arm64_writer_put_ldr_reg_address (ctx->output, dst->reg, label->imm);
  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_b (GumArm64Relocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm64_op * target = &ctx->detail->operands[0];

  gum_arm64_relocator_put_exit (self, ctx, target->imm);

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_b_cond (GumArm64Relocator * self,
                                    GumCodeGenCtx * ctx)
{
  const cs_arm64_op * target = &ctx->detail->operands[0];
  gsize unique_id = GPOINTER_TO_SIZE (ctx->output->code) << 1;
  gconstpointer is_true = GSIZE_TO_POINTER (unique_id | 1);
  gconstpointer is_false = GSIZE_TO_POINTER (unique_id | 0);

  gum_arm64_writer_put_b_cond_label (ctx->output, ctx->detail->cc, is_true);
  gum_arm64_writer_put_b_label (ctx->output, is_false);

  gum_arm64_writer_put_label (ctx->output, is_true);
  gum_arm64_relocator_put_exit (self, ctx, target->imm);

  gum_arm64_writer_put_label (ctx->output, is_false);

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_bl (GumArm64Relocator * self,
                                GumCodeGenCtx * ctx)
{
  const cs_arm64_op * target = &ctx->detail->operands[0];

  if (gum_arm64_writer_put_bl_imm (ctx->output, target->imm))
    return TRUE;

  gum_arm64_writer_put_ldr_reg_address (ctx->output, ARM64_REG_LR,
      gum_arm64_writer_sign (ctx->output, target->imm));
  gum_arm64_writer_put_blr_reg (ctx->output, ARM64_REG_LR);

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_cbz (GumArm64Relocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm64_op * source = &ctx->detail->operands[0];
  const cs_arm64_op * target = &ctx->detail->operands[1];
  gsize unique_id = GPOINTER_TO_SIZE (ctx->output->code) << 1;
  gconstpointer is_true = GSIZE_TO_POINTER (unique_id | 1);
  gconstpointer is_false = GSIZE_TO_POINTER (unique_id | 0);

  if (ctx->insn->id == ARM64_INS_CBZ)
    gum_arm64_writer_put_cbz_reg_label (ctx->output, source->reg, is_true);
  else
    gum_arm64_writer_put_cbnz_reg_label (ctx->output, source->reg, is_true);
  gum_arm64_writer_put_b_label (ctx->output, is_false);

  gum_arm64_writer_put_label (ctx->output, is_true);
  gum_arm64_relocator_put_exit (self, ctx, target->imm);

  gum_arm64_writer_put_label (ctx->output, is_false);

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_tbz (GumArm64Relocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm64_op * source = &ctx->detail->operands[0];
  const cs_arm64_op * bit = &ctx->detail->operands[1];
  const cs_arm64_op * target = &ctx->detail->operands[2];
  gsize unique_id = GPOINTER_TO_SIZE (ctx->output->code) << 1;
  gconstpointer is_true = GSIZE_TO_POINTER (unique_id | 1);
  gconstpointer is_false = GSIZE_TO_POINTER (unique_id | 0);

  if (ctx->insn->id == ARM64_INS_TBZ)
  {
    gum_arm64_writer_put_tbz_reg_imm_label (ctx->output, source->reg, bit->imm,
        is_true);
  }
  else
  {
    gum_arm64_writer_put_tbnz_reg_imm_label (ctx->output, source->reg, bit->imm,
        is_true);
  }
  gum_arm64_writer_put_b_label (ctx->output, is_false);

  gum_arm64_writer_put_label (ctx->output, is_true);
  gum_arm64_relocator_put_exit (self, ctx, target->imm);

  gum_arm64_writer_put_label (ctx->output, is_false);

  return TRUE;
}

static void
gum_arm64_relocator_put_exit (GumArm64Relocator * self,
                              GumCodeGenCtx * ctx,
                              GumAddress target)
{
  GumArm64Writer * cw = ctx->output;
  arm64_reg reg;

  if (gum_arm64_writer_can_branch_directly_between (cw, cw->pc, target))
  {
    gum_arm64_writer_put_b_imm (cw, target);
    return;
  }

  reg = gum_arm64_relocator_pick_exit_reg_at (self, target, self->outpos - 1);
  if (reg == ARM64_REG_INVALID)
    reg = self->scratch_reg;

  gum_arm64_writer_put_ldr_reg_address (cw, reg,
      gum_arm64_writer_sign (cw, target));
  gum_arm64_writer_put_jmp_reg (cw, reg);
}
