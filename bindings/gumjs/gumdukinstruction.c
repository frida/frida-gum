/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukinstruction.h"

#include "gumdukmacros.h"

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
  ((GumInstruction *) _gumjs_get_private_data (ctx, o))

typedef struct _GumInstruction GumInstruction;

struct _GumInstruction
{
  gpointer target;
  cs_insn insn;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_instruction_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

static GumDukHeapPtr gumjs_instruction_new (duk_context * ctx, gpointer target,
    const cs_insn * insn, GumDukInstruction * parent);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_instruction_construct)
GUMJS_DECLARE_FINALIZER (gumjs_instruction_finalize)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_address)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_next)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_size)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_mnemonic)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_op_str)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_string)

static const duk_function_list_entry gumjs_instruction_module_functions[] =
{
  { "_parse", gumjs_instruction_parse, 1 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_instruction_values[] =
{
  { "address", gumjs_instruction_get_address, NULL},
  { "next", gumjs_instruction_get_next, NULL},
  { "size", gumjs_instruction_get_size, NULL},
  { "mnemonic", gumjs_instruction_get_mnemonic, NULL},
  { "opStr", gumjs_instruction_get_op_str, NULL},

  { NULL, NULL, NULL}
};

static const duk_function_list_entry gumjs_instruction_functions[] =
{
  { "toString", gumjs_instruction_to_string, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_duk_instruction_init (GumDukInstruction * self,
                           GumDukCore * core)
{
  duk_context * ctx = core->ctx;
  cs_err err;

  self->core = core;

  err = cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  duk_push_c_function (ctx, gumjs_instruction_module_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct proto ]
  duk_put_function_list (ctx, -1, gumjs_instruction_module_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  duk_new (ctx, 0);
  // [ instance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "Instruction");
  // []

  duk_push_c_function (ctx, gumjs_instruction_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct proto ]
  duk_put_function_list (ctx, -1, gumjs_instruction_functions);
  duk_push_c_function (ctx, gumjs_instruction_finalize, 0);
  // [ construct proto finalize ]
  duk_set_finalizer (ctx, -2);
  // [ construct proto ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  self->instruction = _gumjs_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InstructionItem");
  // []
  _gumjs_duk_add_properties_to_class (ctx, "InstructionItem",
      gumjs_instruction_values);
}

void
_gum_duk_instruction_dispose (GumDukInstruction * self)
{
  _gumjs_duk_release_heapptr (self->core->ctx, self->instruction);
}

void
_gum_duk_instruction_finalize (GumDukInstruction * self)
{
  cs_close (&self->capstone);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_instruction_module_construct)
{
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_parse)
{
  GumDukInstruction * self;
  gpointer target;
  uint64_t address;
  cs_insn * insn;
  GumDukHeapPtr instance;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "p", &target))
  {
    duk_push_null (ctx);
    return 1;
  }

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

  duk_push_heapptr (ctx, instance);
  _gumjs_duk_release_heapptr (ctx, instance);
  return 1;

invalid_instruction:
  {
    _gumjs_throw (ctx, "invalid instruction");
    duk_push_null (ctx);
    return 1;
  }
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_instruction_construct)
{
  return 0;
}

static GumDukHeapPtr
gumjs_instruction_new (duk_context * ctx,
                       gpointer target,
                       const cs_insn * insn,
                       GumDukInstruction * parent)
{
  GumInstruction * instruction;
  GumDukHeapPtr result;

  instruction = g_slice_new (GumInstruction);
  instruction->target = target;
  memcpy (&instruction->insn, insn, sizeof (cs_insn));

  duk_push_heapptr (ctx, parent->instruction);
  // [ instruction ]
  duk_new (ctx, 0);
  // [ instance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), instruction);
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []
  return result;
}

GUMJS_DEFINE_FINALIZER (gumjs_instruction_finalize)
{
  GumInstruction * instruction;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "DebugSymbol"))
    return 0;

  instruction = GUMJS_INSTRUCTION (duk_require_heapptr (ctx, 0));

  g_slice_free (GumInstruction, instruction);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_address)
{
  GumInstruction * self;

  self = GUMJS_INSTRUCTION (_gumjs_duk_get_this (ctx));

  _gumjs_native_pointer_push (ctx, GSIZE_TO_POINTER (self->insn.address),
      args->core);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_next)
{
  GumInstruction * self;
  gpointer next;

  self = GUMJS_INSTRUCTION (_gumjs_duk_get_this (ctx));
  next = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (self->target) + self->insn.size);

  _gumjs_native_pointer_push (ctx, next, args->core);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_size)
{
  GumInstruction * self = GUMJS_INSTRUCTION (_gumjs_duk_get_this (ctx));

  duk_push_number (ctx, self->insn.size);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_mnemonic)
{
  GumInstruction * self = GUMJS_INSTRUCTION (_gumjs_duk_get_this (ctx));

  duk_push_string (ctx, self->insn.mnemonic);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_op_str)
{
  GumInstruction * self = GUMJS_INSTRUCTION (_gumjs_duk_get_this (ctx));

  duk_push_string (ctx, self->insn.op_str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_string)
{
  GumInstruction * self = GUMJS_INSTRUCTION (_gumjs_duk_get_this (ctx));
  cs_insn * insn = &self->insn;
  gchar * str;

  str = g_strconcat (insn->mnemonic, " ", insn->op_str, NULL);
  duk_push_string (ctx, str);
  g_free (str);
  return 1;
}
