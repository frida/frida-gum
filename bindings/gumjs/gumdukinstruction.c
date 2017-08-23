/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukinstruction.h"

#include "gumdukmacros.h"

#if defined (HAVE_I386)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_X86
# if GLIB_SIZEOF_VOID_P == 8
#  define GUM_DEFAULT_CS_MODE CS_MODE_64
# else
#  define GUM_DEFAULT_CS_MODE CS_MODE_32
# endif
#elif defined (HAVE_ARM)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_ARM
# define GUM_DEFAULT_CS_MODE CS_MODE_ARM
#elif defined (HAVE_ARM64)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_ARM64
# define GUM_DEFAULT_CS_MODE CS_MODE_ARM
#elif defined (HAVE_MIPS)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_MIPS
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
#  define GUM_DEFAULT_CS_MODE CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN
# else
#  define GUM_DEFAULT_CS_MODE CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN
# endif
#else
# error Unsupported architecture
#endif

GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_instruction_construct)
GUMJS_DECLARE_FINALIZER (gumjs_instruction_finalize)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_address)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_next)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_size)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_mnemonic)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_op_str)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_operands)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_json)

static void gum_push_operands (duk_context * ctx, const cs_insn * insn,
    GumDukInstruction * module);

#if defined (HAVE_I386)
static void gum_x86_push_memory_operand_value (duk_context * ctx,
    const x86_op_mem * mem, GumDukInstruction * module);
#elif defined (HAVE_ARM)
static void gum_arm_push_memory_operand_value (duk_context * ctx,
    const arm_op_mem * mem, GumDukInstruction * module);
static void gum_arm_push_shift_details (duk_context * ctx, const cs_arm_op * op,
    GumDukInstruction * module);
static const gchar * gum_arm_shifter_to_string (arm_shifter type);
#elif defined (HAVE_ARM64)
static void gum_arm64_push_memory_operand_value (duk_context * ctx,
    const arm64_op_mem * mem, GumDukInstruction * module);
static void gum_arm64_push_shift_details (duk_context * ctx,
    const cs_arm64_op * op, GumDukInstruction * module);
static const gchar * gum_arm64_shifter_to_string (arm64_shifter type);
static const gchar * gum_arm64_extender_to_string (arm64_extender ext);
static const gchar * gum_arm64_vas_to_string (arm64_vas vas);
static const gchar * gum_arm64_vess_to_string (arm64_vess vess);
#elif defined (HAVE_MIPS)
static void gum_mips_push_memory_operand_value (duk_context * ctx,
    const mips_op_mem * mem, GumDukInstruction * module);
#endif

static const duk_function_list_entry gumjs_instruction_module_functions[] =
{
  { "_parse", gumjs_instruction_parse, 1 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_instruction_values[] =
{
  { "address", gumjs_instruction_get_address, NULL },
  { "next", gumjs_instruction_get_next, NULL },
  { "size", gumjs_instruction_get_size, NULL },
  { "mnemonic", gumjs_instruction_get_mnemonic, NULL },
  { "opStr", gumjs_instruction_get_op_str, NULL },
  { "operands", gumjs_instruction_get_operands, NULL },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_instruction_functions[] =
{
  { "toString", gumjs_instruction_to_string, 0 },
  { "toJSON", gumjs_instruction_to_json, 0 },

  { NULL, NULL, 0 }
};

void
_gum_duk_instruction_init (GumDukInstruction * self,
                           GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  _gum_duk_store_module_data (ctx, "instruction", self);

  duk_push_c_function (ctx, gumjs_instruction_construct, 1);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_instruction_finalize, 1);
  duk_set_finalizer (ctx, -2);
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_instruction_values);
  duk_put_function_list (ctx, -1, gumjs_instruction_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->instruction = _gum_duk_require_heapptr (ctx, -1);
  duk_put_function_list (ctx, -1, gumjs_instruction_module_functions);
  duk_put_global_string (ctx, "Instruction");
}

void
_gum_duk_instruction_dispose (GumDukInstruction * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->instruction);
}

void
_gum_duk_instruction_finalize (GumDukInstruction * self)
{
  cs_close (&self->capstone);
}

static GumDukInstruction *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "instruction");
}

GumDukInstructionValue *
_gum_duk_push_instruction (duk_context * ctx,
                           csh capstone,
                           const cs_insn * insn,
                           gboolean is_owned,
                           gconstpointer target,
                           GumDukInstruction * module)
{
  GumDukInstructionValue * value;

  value = g_slice_new (GumDukInstructionValue);
  value->object = NULL;
  if (is_owned)
  {
    value->insn = insn;
  }
  else
  {
    g_assert (capstone != 0);
    value->insn = cs_malloc (capstone);
    memcpy ((void *) value->insn, insn, sizeof (cs_insn));
    if (insn->detail != NULL)
      memcpy (value->insn->detail, insn->detail, sizeof (cs_detail));
  }
  value->target = target;
  value->module = module;

  duk_push_heapptr (ctx, module->instruction);
  duk_push_pointer (ctx, value);
  duk_new (ctx, 1);

  return value;
}

GumDukInstructionValue *
_gum_duk_instruction_new (GumDukInstruction * module)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (module->core);
  duk_context * ctx = scope.ctx;
  GumDukInstructionValue * value;

  value = _gum_duk_push_instruction (ctx, 0, NULL, TRUE, NULL, module);
  _gum_duk_protect (ctx, value->object);
  duk_pop (ctx);

  return value;
}

void
_gum_duk_instruction_release (GumDukInstructionValue * value)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (value->module->core);

  _gum_duk_unprotect (scope.ctx, value->object);
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_parse)
{
  GumDukInstruction * module;
  gpointer target;
  uint64_t address;
  cs_insn * insn;

  module = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "p", &target);

  if (module->capstone == 0)
  {
    cs_err err;

    err = cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &module->capstone);
    g_assert_cmpint (err, ==, CS_ERR_OK);

    err = cs_option (module->capstone, CS_OPT_DETAIL, CS_OPT_ON);
    g_assert_cmpint (err, ==, CS_ERR_OK);
  }

#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (module->capstone, CS_OPT_MODE,
      (GPOINTER_TO_SIZE (target) & 1) == 1 ? CS_MODE_THUMB : CS_MODE_ARM);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  if (cs_disasm (module->capstone, (uint8_t *) GSIZE_TO_POINTER (address), 16,
      address, 1, &insn) == 0)
    _gum_duk_throw (ctx, "invalid instruction");

  _gum_duk_push_instruction (ctx, module->capstone, insn, TRUE, target, module);
  return 1;
}

static GumDukInstructionValue *
gumjs_instruction_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukInstructionValue * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  if (self->insn == NULL)
    _gum_duk_throw (ctx, "invalid operation");

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_instruction_construct)
{
  GumDukInstructionValue * self;

  self = duk_require_pointer (ctx, 0);

  duk_push_this (ctx);
  self->object = duk_require_heapptr (ctx, -1);
  _gum_duk_put_data (ctx, -1, self);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_instruction_finalize)
{
  GumDukInstructionValue * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  if (self->insn != NULL)
    cs_free ((cs_insn *) self->insn, 1);

  g_slice_free (GumDukInstructionValue, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_address)
{
  GumDukInstructionValue * self = gumjs_instruction_from_args (args);

  _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (self->insn->address),
      args->core);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_next)
{
  GumDukInstructionValue * self = gumjs_instruction_from_args (args);

  _gum_duk_push_native_pointer (ctx,
      GSIZE_TO_POINTER (GPOINTER_TO_SIZE (self->target) + self->insn->size),
      args->core);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_size)
{
  GumDukInstructionValue * self = gumjs_instruction_from_args (args);

  duk_push_number (ctx, self->insn->size);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_mnemonic)
{
  GumDukInstructionValue * self = gumjs_instruction_from_args (args);

  duk_push_string (ctx, self->insn->mnemonic);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_op_str)
{
  GumDukInstructionValue * self = gumjs_instruction_from_args (args);

  duk_push_string (ctx, self->insn->op_str);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_operands)
{
  GumDukInstructionValue * self = gumjs_instruction_from_args (args);

  gum_push_operands (ctx, self->insn, self->module);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_string)
{
  GumDukInstructionValue * self;
  const cs_insn * insn;

  self = gumjs_instruction_from_args (args);
  insn = self->insn;

  if (insn->op_str[0] == '\0')
  {
    duk_push_string (ctx, insn->mnemonic);
  }
  else
  {
    gchar * str;

    str = g_strconcat (insn->mnemonic, " ", insn->op_str, NULL);
    duk_push_string (ctx, str);
    g_free (str);
  }
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_json)
{
  const GumDukPropertyEntry * entry;

  duk_push_object (ctx);

  duk_push_this (ctx);

  for (entry = gumjs_instruction_values; entry->name != NULL; entry++)
  {
    duk_get_prop_string (ctx, -1, entry->name);
    duk_put_prop_string (ctx, -3, entry->name);
  }

  duk_pop (ctx);

  return 1;
}

#if defined (HAVE_I386)

static void
gum_push_operands (duk_context * ctx,
                   const cs_insn * insn,
                   GumDukInstruction * module)
{
  GumDukCore * core = module->core;
  csh capstone = module->capstone;
  const cs_x86 * x86 = &insn->detail->x86;
  uint8_t op_count, op_index;

  duk_push_array (ctx);

  op_count = x86->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_x86_op * op = &x86->operands[op_index];

    duk_push_object (ctx);

    switch (op->type)
    {
      case X86_OP_REG:
        duk_push_string (ctx, cs_reg_name (capstone, op->reg));
        duk_push_string (ctx, "reg");
        break;
      case X86_OP_IMM:
        if (op->size <= 4)
          duk_push_int (ctx, op->imm);
        else
          _gum_duk_push_int64 (ctx, op->imm, core);
        duk_push_string (ctx, "imm");
        break;
      case X86_OP_MEM:
        gum_x86_push_memory_operand_value (ctx, &op->mem, module);
        duk_push_string (ctx, "mem");
        break;
      case X86_OP_FP:
        duk_push_number (ctx, op->fp);
        duk_push_string (ctx, "fp");
        break;
      default:
        g_assert_not_reached ();
    }
    duk_put_prop_string (ctx, -3, "type");
    duk_put_prop_string (ctx, -2, "value");

    duk_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_x86_push_memory_operand_value (duk_context * ctx,
                                   const x86_op_mem * mem,
                                   GumDukInstruction * module)
{
  csh capstone = module->capstone;

  duk_push_object (ctx);

  if (mem->segment != X86_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->segment));
    duk_put_prop_string (ctx, -2, "segment");
  }

  if (mem->base != X86_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->base));
    duk_put_prop_string (ctx, -2, "base");
  }

  if (mem->index != X86_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->index));
    duk_put_prop_string (ctx, -2, "index");
  }

  duk_push_int (ctx, mem->scale);
  duk_put_prop_string (ctx, -2, "scale");

  duk_push_int (ctx, mem->disp);
  duk_put_prop_string (ctx, -2, "disp");
}

#elif defined (HAVE_ARM)

static void
gum_push_operands (duk_context * ctx,
                   const cs_insn * insn,
                   GumDukInstruction * module)
{
  csh capstone = module->capstone;
  const cs_arm * arm = &insn->detail->arm;
  uint8_t op_count, op_index;

  duk_push_array (ctx);

  op_count = arm->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_arm_op * op = &arm->operands[op_index];

    duk_push_object (ctx);

    switch (op->type)
    {
      case ARM_OP_REG:
        duk_push_string (ctx, cs_reg_name (capstone, op->reg));
        duk_push_string (ctx, "reg");
        break;
      case ARM_OP_IMM:
        duk_push_int (ctx, op->imm);
        duk_push_string (ctx, "imm");
        break;
      case ARM_OP_MEM:
        gum_arm_push_memory_operand_value (ctx, &op->mem, module);
        duk_push_string (ctx, "mem");
        break;
      case ARM_OP_FP:
        duk_push_number (ctx, op->fp);
        duk_push_string (ctx, "fp");
        break;
      case ARM_OP_CIMM:
        duk_push_int (ctx, op->imm);
        duk_push_string (ctx, "cimm");
        break;
      case ARM_OP_PIMM:
        duk_push_int (ctx, op->imm);
        duk_push_string (ctx, "pimm");
        break;
      case ARM_OP_SETEND:
        duk_push_string (ctx, (op->setend == ARM_SETEND_BE) ? "be" : "le");
        duk_push_string (ctx, "setend");
        break;
      case ARM_OP_SYSREG:
        duk_push_string (ctx, cs_reg_name (capstone, op->reg));
        duk_push_string (ctx, "sysreg");
        break;
      default:
        g_assert_not_reached ();
    }
    duk_put_prop_string (ctx, -3, "type");
    duk_put_prop_string (ctx, -2, "value");

    if (op->shift.type != ARM_SFT_INVALID)
    {
      gum_arm_push_shift_details (ctx, op, module);
      duk_put_prop_string (ctx, -2, "shift");
    }

    if (op->vector_index != -1)
    {
      duk_push_uint (ctx, op->vector_index);
      duk_put_prop_string (ctx, -2, "vectorIndex");
    }

    duk_push_boolean (ctx, op->subtracted);
    duk_put_prop_string (ctx, -2, "subtracted");

    duk_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_arm_push_memory_operand_value (duk_context * ctx,
                                   const arm_op_mem * mem,
                                   GumDukInstruction * module)
{
  csh capstone = module->capstone;

  duk_push_object (ctx);

  if (mem->base != ARM_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->base));
    duk_put_prop_string (ctx, -2, "base");
  }

  if (mem->index != ARM_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->index));
    duk_put_prop_string (ctx, -2, "index");
  }

  duk_push_int (ctx, mem->scale);
  duk_put_prop_string (ctx, -2, "scale");

  duk_push_int (ctx, mem->disp);
  duk_put_prop_string (ctx, -2, "disp");
}

static void
gum_arm_push_shift_details (duk_context * ctx,
                            const cs_arm_op * op,
                            GumDukInstruction * module)
{
  duk_push_object (ctx);

  duk_push_string (ctx, gum_arm_shifter_to_string (op->shift.type));
  duk_put_prop_string (ctx, -2, "type");

  duk_push_uint (ctx, op->shift.value);
  duk_put_prop_string (ctx, -2, "value");
}

static const gchar *
gum_arm_shifter_to_string (arm_shifter type)
{
  switch (type)
  {
    case ARM_SFT_ASR: return "asr";
    case ARM_SFT_LSL: return "lsl";
    case ARM_SFT_LSR: return "lsr";
    case ARM_SFT_ROR: return "ror";
    case ARM_SFT_RRX: return "rrx";
    case ARM_SFT_ASR_REG: return "asr-reg";
    case ARM_SFT_LSL_REG: return "lsl-reg";
    case ARM_SFT_LSR_REG: return "lsr-reg";
    case ARM_SFT_ROR_REG: return "ror-reg";
    case ARM_SFT_RRX_REG: return "rrx-reg";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

#elif defined (HAVE_ARM64)

static void
gum_push_operands (duk_context * ctx,
                   const cs_insn * insn,
                   GumDukInstruction * module)
{
  GumDukCore * core = module->core;
  csh capstone = module->capstone;
  const cs_arm64 * arm64 = &insn->detail->arm64;
  uint8_t op_count, op_index;

  duk_push_array (ctx);

  op_count = arm64->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_arm64_op * op = &arm64->operands[op_index];

    duk_push_object (ctx);

    switch (op->type)
    {
      case ARM64_OP_REG:
        duk_push_string (ctx, cs_reg_name (capstone, op->reg));
        duk_push_string (ctx, "reg");
        break;
      case ARM64_OP_IMM:
        _gum_duk_push_int64 (ctx, op->imm, core);
        duk_push_string (ctx, "imm");
        break;
      case ARM64_OP_MEM:
        gum_arm64_push_memory_operand_value (ctx, &op->mem, module);
        duk_push_string (ctx, "mem");
        break;
      case ARM64_OP_FP:
        duk_push_number (ctx, op->fp);
        duk_push_string (ctx, "fp");
        break;
      case ARM64_OP_CIMM:
        _gum_duk_push_int64 (ctx, op->imm, core);
        duk_push_string (ctx, "cimm");
        break;
      case ARM64_OP_REG_MRS:
        duk_push_string (ctx, cs_reg_name (capstone, op->reg));
        duk_push_string (ctx, "reg-mrs");
        break;
      case ARM64_OP_REG_MSR:
        duk_push_string (ctx, cs_reg_name (capstone, op->reg));
        duk_push_string (ctx, "reg-msr");
        break;
      case ARM64_OP_PSTATE:
        duk_push_uint (ctx, op->pstate);
        duk_push_string (ctx, "pstate");
        break;
      case ARM64_OP_SYS:
        duk_push_uint (ctx, op->sys);
        duk_push_string (ctx, "sys");
        break;
      case ARM64_OP_PREFETCH:
        duk_push_uint (ctx, op->prefetch);
        duk_push_string (ctx, "prefetch");
        break;
      case ARM64_OP_BARRIER:
        duk_push_uint (ctx, op->barrier);
        duk_push_string (ctx, "barrier");
        break;
      default:
        g_assert_not_reached ();
    }
    duk_put_prop_string (ctx, -3, "type");
    duk_put_prop_string (ctx, -2, "value");

    if (op->shift.type != ARM64_SFT_INVALID)
    {
      gum_arm64_push_shift_details (ctx, op, module);
      duk_put_prop_string (ctx, -2, "shift");
    }

    if (op->ext != ARM64_EXT_INVALID)
    {
      duk_push_string (ctx, gum_arm64_extender_to_string (op->ext));
      duk_put_prop_string (ctx, -2, "ext");
    }

    if (op->vas != ARM64_VAS_INVALID)
    {
      duk_push_string (ctx, gum_arm64_vas_to_string (op->vas));
      duk_put_prop_string (ctx, -2, "vas");
    }

    if (op->vess != ARM64_VESS_INVALID)
    {
      duk_push_string (ctx, gum_arm64_vess_to_string (op->vess));
      duk_put_prop_string (ctx, -2, "vess");
    }

    if (op->vector_index != -1)
    {
      duk_push_uint (ctx, op->vector_index);
      duk_put_prop_string (ctx, -2, "vectorIndex");
    }

    duk_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_arm64_push_memory_operand_value (duk_context * ctx,
                                     const arm64_op_mem * mem,
                                     GumDukInstruction * module)
{
  csh capstone = module->capstone;

  duk_push_object (ctx);

  if (mem->base != ARM64_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->base));
    duk_put_prop_string (ctx, -2, "base");
  }

  if (mem->index != ARM64_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->index));
    duk_put_prop_string (ctx, -2, "index");
  }

  duk_push_int (ctx, mem->disp);
  duk_put_prop_string (ctx, -2, "disp");
}

static void
gum_arm64_push_shift_details (duk_context * ctx,
                              const cs_arm64_op * op,
                              GumDukInstruction * module)
{
  duk_push_object (ctx);

  duk_push_string (ctx, gum_arm64_shifter_to_string (op->shift.type));
  duk_put_prop_string (ctx, -2, "type");

  duk_push_uint (ctx, op->shift.value);
  duk_put_prop_string (ctx, -2, "value");
}

static const gchar *
gum_arm64_shifter_to_string (arm64_shifter type)
{
  switch (type)
  {
    case ARM64_SFT_LSL: return "lsl";
    case ARM64_SFT_MSL: return "msl";
    case ARM64_SFT_LSR: return "lsr";
    case ARM64_SFT_ASR: return "asr";
    case ARM64_SFT_ROR: return "ror";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

static const gchar *
gum_arm64_extender_to_string (arm64_extender ext)
{
  switch (ext)
  {
    case ARM64_EXT_UXTB: return "uxtb";
    case ARM64_EXT_UXTH: return "uxth";
    case ARM64_EXT_UXTW: return "uxtw";
    case ARM64_EXT_UXTX: return "uxtx";
    case ARM64_EXT_SXTB: return "sxtb";
    case ARM64_EXT_SXTH: return "sxth";
    case ARM64_EXT_SXTW: return "sxtw";
    case ARM64_EXT_SXTX: return "sxtx";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

static const gchar *
gum_arm64_vas_to_string (arm64_vas vas)
{
  switch (vas)
  {
    case ARM64_VAS_8B:  return "8b";
    case ARM64_VAS_16B: return "16b";
    case ARM64_VAS_4H:  return "4h";
    case ARM64_VAS_8H:  return "8h";
    case ARM64_VAS_2S:  return "2s";
    case ARM64_VAS_4S:  return "4s";
    case ARM64_VAS_1D:  return "1d";
    case ARM64_VAS_2D:  return "2d";
    case ARM64_VAS_1Q:  return "1q";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

static const gchar *
gum_arm64_vess_to_string (arm64_vess vess)
{
  switch (vess)
  {
    case ARM64_VESS_B: return "b";
    case ARM64_VESS_H: return "h";
    case ARM64_VESS_S: return "s";
    case ARM64_VESS_D: return "d";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

#elif defined (HAVE_MIPS)

static void
gum_push_operands (duk_context * ctx,
                   const cs_insn * insn,
                   GumDukInstruction * module)
{
  csh capstone = module->capstone;
  const cs_mips * mips = &insn->detail->mips;
  uint8_t op_count, op_index;

  duk_push_array (ctx);

  op_count = mips->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_mips_op * op = &mips->operands[op_index];

    duk_push_object (ctx);

    switch (op->type)
    {
      case MIPS_OP_REG:
        duk_push_string (ctx, cs_reg_name (capstone, op->reg));
        duk_push_string (ctx, "reg");
        break;
      case MIPS_OP_IMM:
        duk_push_int (ctx, op->imm);
        duk_push_string (ctx, "imm");
        break;
      case MIPS_OP_MEM:
        gum_mips_push_memory_operand_value (ctx, &op->mem, module);
        duk_push_string (ctx, "mem");
        break;
      default:
        g_assert_not_reached ();
    }
    duk_put_prop_string (ctx, -3, "type");
    duk_put_prop_string (ctx, -2, "value");

    duk_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_mips_push_memory_operand_value (duk_context * ctx,
                                    const mips_op_mem * mem,
                                    GumDukInstruction * module)
{
  csh capstone = module->capstone;

  duk_push_object (ctx);

  if (mem->base != MIPS_REG_INVALID)
  {
    duk_push_string (ctx, cs_reg_name (capstone, mem->base));
    duk_put_prop_string (ctx, -2, "base");
  }

  duk_push_int (ctx, mem->disp);
  duk_put_prop_string (ctx, -2, "disp");
}

#endif
