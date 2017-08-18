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
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_json)

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
