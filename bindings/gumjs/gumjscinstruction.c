/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscinstruction.h"

#include "gumjscmacros.h"

#include <string.h>

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
#else
# error Unsupported architecture
#endif

#define GUMJS_INSTRUCTION(o) \
  ((GumInstruction *) JSObjectGetPrivate (o))

typedef struct _GumInstruction GumInstruction;

struct _GumInstruction
{
  gpointer target;
  cs_insn insn;
};

GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

static JSObjectRef gumjs_instruction_new (JSContextRef ctx, gpointer target,
    const cs_insn * insn, GumJscInstruction * parent);
GUMJS_DECLARE_FINALIZER (gumjs_instruction_finalize)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_address)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_next)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_size)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_mnemonic)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_op_str)
GUMJS_DECLARE_CONVERTER (gumjs_instruction_convert_to_type)

static const JSStaticFunction gumjs_instruction_module_functions[] =
{
  { "_parse", gumjs_instruction_parse, GUMJS_RO },

  { NULL, NULL, 0 }
};

static const JSStaticValue gumjs_instruction_values[] =
{
  { "address", gumjs_instruction_get_address, NULL, GUMJS_RO },
  { "next", gumjs_instruction_get_next, NULL, GUMJS_RO },
  { "size", gumjs_instruction_get_size, NULL, GUMJS_RO },
  { "mnemonic", gumjs_instruction_get_mnemonic, NULL, GUMJS_RO },
  { "opStr", gumjs_instruction_get_op_str, NULL, GUMJS_RO },

  { NULL, NULL, NULL, 0 }
};

void
_gum_jsc_instruction_init (GumJscInstruction * self,
                           GumJscCore * core,
                           JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  cs_err err;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef module;

  self->core = core;

  err = cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  def = kJSClassDefinitionEmpty;
  def.className = "InstructionModule";
  def.staticFunctions = gumjs_instruction_module_functions;
  klass = JSClassCreate (&def);
  module = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Instruction", module);

  def = kJSClassDefinitionEmpty;
  def.className = "Instruction";
  def.staticValues = gumjs_instruction_values;
  def.finalize = gumjs_instruction_finalize;
  def.convertToType = gumjs_instruction_convert_to_type;
  self->instruction = JSClassCreate (&def);
}

void
_gum_jsc_instruction_dispose (GumJscInstruction * self)
{
  g_clear_pointer (&self->instruction, JSClassRelease);
}

void
_gum_jsc_instruction_finalize (GumJscInstruction * self)
{
  cs_close (&self->capstone);
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_parse)
{
  GumJscInstruction * self;
  gpointer target;
  uint64_t address;
  cs_insn * insn;
  JSObjectRef instance;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "p", &target))
    return NULL;

#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (self->capstone, CS_OPT_MODE,
      (GPOINTER_TO_SIZE (target) & 1) == 1 ? CS_MODE_THUMB : CS_MODE_ARM);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  if (cs_disasm (self->capstone, (uint8_t *) GSIZE_TO_POINTER (address), 16,
      address, 1, &insn) == 0)
    goto invalid_instruction;
  instance = gumjs_instruction_new (ctx, target, insn, self);
  cs_free (insn, 1);

  return instance;

invalid_instruction:
  {
    _gumjs_throw (ctx, exception, "invalid instruction");
    return NULL;
  }
}

static JSObjectRef
gumjs_instruction_new (JSContextRef ctx,
                       gpointer target,
                       const cs_insn * insn,
                       GumJscInstruction * parent)
{
  GumInstruction * instruction;

  instruction = g_slice_new (GumInstruction);
  instruction->target = target;
  memcpy (&instruction->insn, insn, sizeof (cs_insn));

  return JSObjectMake (ctx, parent->instruction, instruction);
}

GUMJS_DEFINE_FINALIZER (gumjs_instruction_finalize)
{
  GumInstruction * instruction = GUMJS_INSTRUCTION (object);

  g_slice_free (GumInstruction, instruction);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_address)
{
  GumInstruction * self = GUMJS_INSTRUCTION (object);

  return _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (self->insn.address),
      args->core);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_next)
{
  GumInstruction * self;
  gpointer next;

  self = GUMJS_INSTRUCTION (object);
  next = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (self->target) + self->insn.size);

  return _gumjs_native_pointer_new (ctx, next, args->core);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_size)
{
  GumInstruction * self = GUMJS_INSTRUCTION (object);

  return JSValueMakeNumber (ctx, self->insn.size);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_mnemonic)
{
  GumInstruction * self = GUMJS_INSTRUCTION (object);

  return _gumjs_string_to_value (ctx, self->insn.mnemonic);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_op_str)
{
  GumInstruction * self = GUMJS_INSTRUCTION (object);

  return _gumjs_string_to_value (ctx, self->insn.op_str);
}

GUMJS_DEFINE_CONVERTER (gumjs_instruction_convert_to_type)
{
  GumInstruction * self;
  cs_insn * insn;
  gchar * str;
  JSValueRef result;

  self = GUMJS_INSTRUCTION (object);
  insn = &self->insn;

  str = g_strconcat (insn->mnemonic, " ", insn->op_str, NULL);
  result = _gumjs_string_to_value (ctx, str);
  g_free (str);

  return result;
}
