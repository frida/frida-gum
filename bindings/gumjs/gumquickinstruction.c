/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickinstruction.h"

#include "gumquickmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_instruction_construct)
GUMJS_DECLARE_FINALIZER (gumjs_instruction_finalize)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_address)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_next)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_size)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_mnemonic)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_op_str)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_operands)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_regs_read)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_regs_written)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_groups)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_json)

static void gum_push_operands (JSContext * ctx, const cs_insn * insn,
    GumQuickInstruction * module);

#if defined (HAVE_I386)
static void gum_x86_push_memory_operand_value (JSContext * ctx,
    const x86_op_mem * mem, GumQuickInstruction * module);
#elif defined (HAVE_ARM)
static void gum_arm_push_memory_operand_value (JSContext * ctx,
    const arm_op_mem * mem, GumQuickInstruction * module);
static void gum_arm_push_shift_details (JSContext * ctx, const cs_arm_op * op,
    GumQuickInstruction * module);
static const gchar * gum_arm_shifter_to_string (arm_shifter type);
#elif defined (HAVE_ARM64)
static void gum_arm64_push_memory_operand_value (JSContext * ctx,
    const arm64_op_mem * mem, GumQuickInstruction * module);
static void gum_arm64_push_shift_details (JSContext * ctx,
    const cs_arm64_op * op, GumQuickInstruction * module);
static const gchar * gum_arm64_shifter_to_string (arm64_shifter type);
static const gchar * gum_arm64_extender_to_string (arm64_extender ext);
static const gchar * gum_arm64_vas_to_string (arm64_vas vas);
#elif defined (HAVE_MIPS)
static void gum_mips_push_memory_operand_value (JSContext * ctx,
    const mips_op_mem * mem, GumQuickInstruction * module);
#endif

static void gum_push_regs (JSContext * ctx, const uint16_t * regs,
    uint8_t count, GumQuickInstruction * module);

static void gum_push_groups (JSContext * ctx, const uint8_t * groups,
    uint8_t count, GumQuickInstruction * module);

static const JSClassDef gumjs_instruction_def =
{
  .class_name = "Instruction",
  .finalizer = gumjs_instruction_finalize,
};

static const JSCFunctionListEntry gumjs_instruction_module_entries[] =
{
  JS_CFUNC_DEF ("_parse", 0, gumjs_instruction_parse),
};

static const JSCFunctionListEntry gumjs_instruction_entries[] =
{
  JS_CGETSET_DEF ("address", gumjs_instruction_get_address, NULL),
  JS_CGETSET_DEF ("next", gumjs_instruction_get_next, NULL),
  JS_CGETSET_DEF ("size", gumjs_instruction_get_size, NULL),
  JS_CGETSET_DEF ("mnemonic", gumjs_instruction_get_mnemonic, NULL),
  JS_CGETSET_DEF ("opStr", gumjs_instruction_get_op_str, NULL),
  JS_CGETSET_DEF ("operands", gumjs_instruction_get_operands, NULL),
  JS_CGETSET_DEF ("regsRead", gumjs_instruction_get_regs_read, NULL),
  JS_CGETSET_DEF ("regsWritten", gumjs_instruction_get_regs_written, NULL),
  JS_CGETSET_DEF ("groups", gumjs_instruction_get_groups, NULL),
  JS_CFUNC_DEF ("toString", 0, gumjs_instruction_to_string),
  JS_CFUNC_DEF ("toJSON", 0, gumjs_instruction_to_json),
};

void
_gum_quick_instruction_init (GumQuickInstruction * self,
                             JSValue ns,
                             GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue ctor, proto;

  self->core = core;

  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  cs_option (self->capstone, CS_OPT_DETAIL, CS_OPT_ON);

  _gum_quick_core_store_module_data (core, "instruction", self);

  JS_NewClassID (&self->instruction_class);
  JS_NewClass (core->rt, self->instruction_class, &gumjs_instruction_def);
  ctor = JS_NewCFunction2 (ctx, gumjs_instruction_construct,
      gumjs_instruction_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_instruction_module_entries,
      G_N_ELEMENTS (gumjs_instruction_module_entries));
  proto = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_instruction_entries,
      G_N_ELEMENTS (gumjs_instruction_entries));
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetClassProto (ctx, self->instruction_class, proto);
  JS_DefinePropertyValueStr (ctx, ns, gumjs_instruction_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_instruction_dispose (GumQuickInstruction * self)
{
}

void
_gum_quick_instruction_finalize (GumQuickInstruction * self)
{
  cs_close (&self->capstone);
}

static GumQuickInstruction *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "instruction");
}

JSValue
_gum_quick_instruction_new (JSContext * ctx,
                            csh capstone,
                            const cs_insn * insn,
                            gboolean is_owned,
                            gconstpointer target,
                            GumQuickInstruction * parent,
                            GumQuickInstructionValue ** instruction)
{
  JSValue wrapper;
  GumQuickInstructionValue * v;

  wrapper = JS_NewObjectClass (ctx, parent->instruction_class);

  v = g_slice_new (GumQuickInstructionValue);
  v->wrapper = JS_NULL;
  if (is_owned)
  {
    v->insn = insn;
  }
  else
  {
    g_assert (capstone != 0);
    v->insn = cs_malloc (capstone);
    memcpy ((void *) v->insn, insn, sizeof (cs_insn));
    if (insn->detail != NULL)
      memcpy (v->insn->detail, insn->detail, sizeof (cs_detail));
  }
  v->target = target;
  v->parent = parent;

  if (instruction != NULL)
    *instruction = v;

  return wrapper;
}

void
_gum_quick_instruction_release (GumQuickInstructionValue * instruction)
{
  JS_FreeValue (instruction->parent->core->ctx, instruction->wrapper);
}

gboolean
_gum_quick_instruction_get (JSContext * ctx,
                            JSValue val,
                            GumQuickInstruction * parent,
                            GumQuickInstructionValue ** instruction)
{
  GumQuickInstructionValue * v;

  v = JS_GetOpaque2 (ctx, val, parent->instruction_class);
  if (v == NULL)
    return FALSE;

  if (v->insn == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *instruction = v;
  return TRUE;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_parse)
{
  GumQuickInstruction * self;
  gpointer target;
  uint64_t address;
  const gsize max_instruction_size = 16;
  cs_insn * insn;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "p", &target))
    return JS_EXCEPTION;

  target = gum_strip_code_pointer (target);

#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (self->capstone, CS_OPT_MODE,
      (((GPOINTER_TO_SIZE (target) & 1) == 1) ? CS_MODE_THUMB : CS_MODE_ARM) |
      CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  gum_ensure_code_readable (GSIZE_TO_POINTER (address), max_instruction_size);

  if (cs_disasm (self->capstone, (uint8_t *) GSIZE_TO_POINTER (address),
      max_instruction_size, address, 1, &insn) == 0)
  {
    return _gum_quick_throw_literal (ctx, "invalid instruction");
  }

  return _gum_quick_instruction_new (ctx, self->capstone, insn, TRUE, target,
      self, NULL);
}

static gboolean
gum_quick_instruction_get (JSContext * ctx,
                           JSValue val,
                           GumQuickCore * core,
                           GumQuickInstructionValue ** instruction)
{
  return _gum_quick_instruction_get (ctx, val, gumjs_get_parent_module (core),
      instruction);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_instruction_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FINALIZER (gumjs_instruction_finalize)
{
  GumQuickInstructionValue * v;

  v = JS_GetOpaque (val, gumjs_get_parent_module (core)->instruction_class);
  if (v == NULL)
    return;

  if (v->insn != NULL)
    cs_free ((cs_insn *) v->insn, 1);

  g_slice_free (GumQuickInstructionValue, v);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_address)
{
  GumQuickInstructionValue * self;

  if (!gum_quick_instruction_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (self->insn->address), core);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_next)
{
  GumQuickInstructionValue * self;

  if (!gum_quick_instruction_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (GPOINTER_TO_SIZE (self->target) + self->insn->size),
      core);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_size)
{
  GumQuickInstructionValue * self;

  if (!gum_quick_instruction_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt32 (ctx, self->insn->size);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_mnemonic)
{
  GumQuickInstructionValue * self;

  if (!gum_quick_instruction_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewString (ctx, self->insn->mnemonic);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_op_str)
{
  GumQuickInstructionValue * self;

  if (!gum_quick_instruction_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewString (ctx, self->insn->op_str);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_operands)
{
  GumQuickInstructionValue * self = gumjs_instruction_from_args (args);

  gum_push_operands (ctx, self->insn, self->module);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_regs_read)
{
  GumQuickInstructionValue * self;
  const cs_detail * detail;

  self = gumjs_instruction_from_args (args);

  detail = self->insn->detail;

  gum_push_regs (ctx, detail->regs_read, detail->regs_read_count, self->module);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_regs_written)
{
  GumQuickInstructionValue * self;
  const cs_detail * detail;

  self = gumjs_instruction_from_args (args);

  detail = self->insn->detail;

  gum_push_regs (ctx, detail->regs_write, detail->regs_write_count,
      self->module);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_groups)
{
  GumQuickInstructionValue * self;
  const cs_detail * detail;

  self = gumjs_instruction_from_args (args);

  detail = self->insn->detail;

  gum_push_groups (ctx, detail->groups, detail->groups_count, self->module);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_string)
{
  GumQuickInstructionValue * self;
  const cs_insn * insn;

  self = gumjs_instruction_from_args (args);
  insn = self->insn;

  if (insn->op_str[0] == '\0')
  {
    quick_push_string (ctx, insn->mnemonic);
  }
  else
  {
    gchar * str;

    str = g_strconcat (insn->mnemonic, " ", insn->op_str, NULL);
    quick_push_string (ctx, str);
    g_free (str);
  }
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_json)
{
  const GumQuickPropertyEntry * entry;

  quick_push_object (ctx);

  quick_push_this (ctx);

  for (entry = gumjs_instruction_values; entry->name != NULL; entry++)
  {
    quick_get_prop_string (ctx, -1, entry->name);
    quick_put_prop_string (ctx, -3, entry->name);
  }

  quick_pop (ctx);

  return 1;
}

#if defined (HAVE_I386)

static void
gum_push_operands (JSContext * ctx,
                   const cs_insn * insn,
                   GumQuickInstruction * module)
{
  GumQuickCore * core = module->core;
  csh capstone = module->capstone;
  const cs_x86 * x86 = &insn->detail->x86;
  uint8_t op_count, op_index;

  quick_push_array (ctx);

  op_count = x86->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_x86_op * op = &x86->operands[op_index];

    quick_push_object (ctx);

    switch (op->type)
    {
      case X86_OP_REG:
        quick_push_string (ctx, cs_reg_name (capstone, op->reg));
        quick_push_string (ctx, "reg");
        break;
      case X86_OP_IMM:
        if (op->size <= 4)
          quick_push_int (ctx, op->imm);
        else
          _gum_quick_push_int64 (ctx, op->imm, core);
        quick_push_string (ctx, "imm");
        break;
      case X86_OP_MEM:
        gum_x86_push_memory_operand_value (ctx, &op->mem, module);
        quick_push_string (ctx, "mem");
        break;
      default:
        g_assert_not_reached ();
    }

    quick_put_prop_string (ctx, -3, "type");
    quick_put_prop_string (ctx, -2, "value");

    quick_push_uint (ctx, op->size);
    quick_put_prop_string (ctx, -2, "size");

    quick_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_x86_push_memory_operand_value (JSContext * ctx,
                                   const x86_op_mem * mem,
                                   GumQuickInstruction * module)
{
  csh capstone = module->capstone;

  quick_push_object (ctx);

  if (mem->segment != X86_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->segment));
    quick_put_prop_string (ctx, -2, "segment");
  }

  if (mem->base != X86_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->base));
    quick_put_prop_string (ctx, -2, "base");
  }

  if (mem->index != X86_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->index));
    quick_put_prop_string (ctx, -2, "index");
  }

  quick_push_int (ctx, mem->scale);
  quick_put_prop_string (ctx, -2, "scale");

  quick_push_int (ctx, mem->disp);
  quick_put_prop_string (ctx, -2, "disp");
}

#elif defined (HAVE_ARM)

static void
gum_push_operands (JSContext * ctx,
                   const cs_insn * insn,
                   GumQuickInstruction * module)
{
  csh capstone = module->capstone;
  const cs_arm * arm = &insn->detail->arm;
  uint8_t op_count, op_index;

  quick_push_array (ctx);

  op_count = arm->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_arm_op * op = &arm->operands[op_index];

    quick_push_object (ctx);

    switch (op->type)
    {
      case ARM_OP_REG:
        quick_push_string (ctx, cs_reg_name (capstone, op->reg));
        quick_push_string (ctx, "reg");
        break;
      case ARM_OP_IMM:
        quick_push_int (ctx, op->imm);
        quick_push_string (ctx, "imm");
        break;
      case ARM_OP_MEM:
        gum_arm_push_memory_operand_value (ctx, &op->mem, module);
        quick_push_string (ctx, "mem");
        break;
      case ARM_OP_FP:
        quick_push_number (ctx, op->fp);
        quick_push_string (ctx, "fp");
        break;
      case ARM_OP_CIMM:
        quick_push_int (ctx, op->imm);
        quick_push_string (ctx, "cimm");
        break;
      case ARM_OP_PIMM:
        quick_push_int (ctx, op->imm);
        quick_push_string (ctx, "pimm");
        break;
      case ARM_OP_SETEND:
        quick_push_string (ctx, (op->setend == ARM_SETEND_BE) ? "be" : "le");
        quick_push_string (ctx, "setend");
        break;
      case ARM_OP_SYSREG:
        quick_push_string (ctx, cs_reg_name (capstone, op->reg));
        quick_push_string (ctx, "sysreg");
        break;
      default:
        g_assert_not_reached ();
    }
    quick_put_prop_string (ctx, -3, "type");
    quick_put_prop_string (ctx, -2, "value");

    if (op->shift.type != ARM_SFT_INVALID)
    {
      gum_arm_push_shift_details (ctx, op, module);
      quick_put_prop_string (ctx, -2, "shift");
    }

    if (op->vector_index != -1)
    {
      quick_push_uint (ctx, op->vector_index);
      quick_put_prop_string (ctx, -2, "vectorIndex");
    }

    quick_push_boolean (ctx, op->subtracted);
    quick_put_prop_string (ctx, -2, "subtracted");

    quick_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_arm_push_memory_operand_value (JSContext * ctx,
                                   const arm_op_mem * mem,
                                   GumQuickInstruction * module)
{
  csh capstone = module->capstone;

  quick_push_object (ctx);

  if (mem->base != ARM_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->base));
    quick_put_prop_string (ctx, -2, "base");
  }

  if (mem->index != ARM_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->index));
    quick_put_prop_string (ctx, -2, "index");
  }

  quick_push_int (ctx, mem->scale);
  quick_put_prop_string (ctx, -2, "scale");

  quick_push_int (ctx, mem->disp);
  quick_put_prop_string (ctx, -2, "disp");
}

static void
gum_arm_push_shift_details (JSContext * ctx,
                            const cs_arm_op * op,
                            GumQuickInstruction * module)
{
  quick_push_object (ctx);

  quick_push_string (ctx, gum_arm_shifter_to_string (op->shift.type));
  quick_put_prop_string (ctx, -2, "type");

  quick_push_uint (ctx, op->shift.value);
  quick_put_prop_string (ctx, -2, "value");
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
gum_push_operands (JSContext * ctx,
                   const cs_insn * insn,
                   GumQuickInstruction * module)
{
  GumQuickCore * core = module->core;
  csh capstone = module->capstone;
  const cs_arm64 * arm64 = &insn->detail->arm64;
  uint8_t op_count, op_index;

  quick_push_array (ctx);

  op_count = arm64->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_arm64_op * op = &arm64->operands[op_index];

    quick_push_object (ctx);

    switch (op->type)
    {
      case ARM64_OP_REG:
        quick_push_string (ctx, cs_reg_name (capstone, op->reg));
        quick_push_string (ctx, "reg");
        break;
      case ARM64_OP_IMM:
        _gum_quick_push_int64 (ctx, op->imm, core);
        quick_push_string (ctx, "imm");
        break;
      case ARM64_OP_MEM:
        gum_arm64_push_memory_operand_value (ctx, &op->mem, module);
        quick_push_string (ctx, "mem");
        break;
      case ARM64_OP_FP:
        quick_push_number (ctx, op->fp);
        quick_push_string (ctx, "fp");
        break;
      case ARM64_OP_CIMM:
        _gum_quick_push_int64 (ctx, op->imm, core);
        quick_push_string (ctx, "cimm");
        break;
      case ARM64_OP_REG_MRS:
        quick_push_string (ctx, cs_reg_name (capstone, op->reg));
        quick_push_string (ctx, "reg-mrs");
        break;
      case ARM64_OP_REG_MSR:
        quick_push_string (ctx, cs_reg_name (capstone, op->reg));
        quick_push_string (ctx, "reg-msr");
        break;
      case ARM64_OP_PSTATE:
        quick_push_uint (ctx, op->pstate);
        quick_push_string (ctx, "pstate");
        break;
      case ARM64_OP_SYS:
        quick_push_uint (ctx, op->sys);
        quick_push_string (ctx, "sys");
        break;
      case ARM64_OP_PREFETCH:
        quick_push_uint (ctx, op->prefetch);
        quick_push_string (ctx, "prefetch");
        break;
      case ARM64_OP_BARRIER:
        quick_push_uint (ctx, op->barrier);
        quick_push_string (ctx, "barrier");
        break;
      default:
        g_assert_not_reached ();
    }
    quick_put_prop_string (ctx, -3, "type");
    quick_put_prop_string (ctx, -2, "value");

    if (op->shift.type != ARM64_SFT_INVALID)
    {
      gum_arm64_push_shift_details (ctx, op, module);
      quick_put_prop_string (ctx, -2, "shift");
    }

    if (op->ext != ARM64_EXT_INVALID)
    {
      quick_push_string (ctx, gum_arm64_extender_to_string (op->ext));
      quick_put_prop_string (ctx, -2, "ext");
    }

    if (op->vas != ARM64_VAS_INVALID)
    {
      quick_push_string (ctx, gum_arm64_vas_to_string (op->vas));
      quick_put_prop_string (ctx, -2, "vas");
    }

    if (op->vector_index != -1)
    {
      quick_push_uint (ctx, op->vector_index);
      quick_put_prop_string (ctx, -2, "vectorIndex");
    }

    quick_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_arm64_push_memory_operand_value (JSContext * ctx,
                                     const arm64_op_mem * mem,
                                     GumQuickInstruction * module)
{
  csh capstone = module->capstone;

  quick_push_object (ctx);

  if (mem->base != ARM64_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->base));
    quick_put_prop_string (ctx, -2, "base");
  }

  if (mem->index != ARM64_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->index));
    quick_put_prop_string (ctx, -2, "index");
  }

  quick_push_int (ctx, mem->disp);
  quick_put_prop_string (ctx, -2, "disp");
}

static void
gum_arm64_push_shift_details (JSContext * ctx,
                              const cs_arm64_op * op,
                              GumQuickInstruction * module)
{
  quick_push_object (ctx);

  quick_push_string (ctx, gum_arm64_shifter_to_string (op->shift.type));
  quick_put_prop_string (ctx, -2, "type");

  quick_push_uint (ctx, op->shift.value);
  quick_put_prop_string (ctx, -2, "value");
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

#elif defined (HAVE_MIPS)

static void
gum_push_operands (JSContext * ctx,
                   const cs_insn * insn,
                   GumQuickInstruction * module)
{
  csh capstone = module->capstone;
  const cs_mips * mips = &insn->detail->mips;
  uint8_t op_count, op_index;

  quick_push_array (ctx);

  op_count = mips->op_count;
  for (op_index = 0; op_index != op_count; op_index++)
  {
    const cs_mips_op * op = &mips->operands[op_index];

    quick_push_object (ctx);

    switch (op->type)
    {
      case MIPS_OP_REG:
        quick_push_string (ctx, cs_reg_name (capstone, op->reg));
        quick_push_string (ctx, "reg");
        break;
      case MIPS_OP_IMM:
        quick_push_int (ctx, op->imm);
        quick_push_string (ctx, "imm");
        break;
      case MIPS_OP_MEM:
        gum_mips_push_memory_operand_value (ctx, &op->mem, module);
        quick_push_string (ctx, "mem");
        break;
      default:
        g_assert_not_reached ();
    }
    quick_put_prop_string (ctx, -3, "type");
    quick_put_prop_string (ctx, -2, "value");

    quick_put_prop_index (ctx, -2, op_index);
  }
}

static void
gum_mips_push_memory_operand_value (JSContext * ctx,
                                    const mips_op_mem * mem,
                                    GumQuickInstruction * module)
{
  csh capstone = module->capstone;

  quick_push_object (ctx);

  if (mem->base != MIPS_REG_INVALID)
  {
    quick_push_string (ctx, cs_reg_name (capstone, mem->base));
    quick_put_prop_string (ctx, -2, "base");
  }

  quick_push_int (ctx, mem->disp);
  quick_put_prop_string (ctx, -2, "disp");
}

#endif

static void
gum_push_regs (JSContext * ctx,
               const uint16_t * regs,
               uint8_t count,
               GumQuickInstruction * module)
{
  csh capstone = module->capstone;
  uint8_t reg_index;

  quick_push_array (ctx);

  for (reg_index = 0; reg_index != count; reg_index++)
  {
    quick_push_string (ctx, cs_reg_name (capstone, regs[reg_index]));
    quick_put_prop_index (ctx, -2, reg_index);
  }
}

static void
gum_push_groups (JSContext * ctx,
                 const uint8_t * groups,
                 uint8_t count,
                 GumQuickInstruction * module)
{
  csh capstone = module->capstone;
  uint8_t group_index;

  quick_push_array (ctx);

  for (group_index = 0; group_index != count; group_index++)
  {
    quick_push_string (ctx, cs_group_name (capstone, groups[group_index]));
    quick_put_prop_index (ctx, -2, group_index);
  }
}
