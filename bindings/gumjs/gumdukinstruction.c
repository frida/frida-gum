/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
#else
# error Unsupported architecture
#endif

GUMJS_DECLARE_CONSTRUCTOR (gumjs_instruction_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_instruction_construct)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_string)

static const duk_function_list_entry gumjs_instruction_module_functions[] =
{
  { "_parse", gumjs_instruction_parse, 1 },

  { NULL, NULL, 0 }
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
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_instruction_module_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "Instruction");

  duk_push_c_function (ctx, gumjs_instruction_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_instruction_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->instruction = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
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

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  _gum_duk_require_args (ctx, "p", &target);

#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (self->capstone, CS_OPT_MODE,
      (GPOINTER_TO_SIZE (target) & 1) == 1 ? CS_MODE_THUMB : CS_MODE_ARM);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  if (cs_disasm (self->capstone, (uint8_t *) GSIZE_TO_POINTER (address), 16,
      address, 1, &insn) == 0)
    _gumjs_throw (ctx, "invalid instruction");

  duk_push_heapptr (ctx, self->instruction);
  duk_push_pointer (ctx, insn);
  duk_push_pointer (ctx, target);
  duk_new (ctx, 2);

  cs_free (insn, 1);

  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_instruction_construct)
{
  cs_insn * insn;
  gpointer target;

  if (!duk_is_constructor_call (ctx))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "Constructor call required");
    duk_throw (ctx);
  }

  insn = duk_require_pointer (ctx, 0);
  target = duk_require_pointer (ctx, 1);

  duk_push_this (ctx);

  _gumjs_native_pointer_push (ctx, GSIZE_TO_POINTER (insn->address),
      args->core);
  duk_put_prop_string (ctx, -2, "address");

  _gumjs_native_pointer_push (ctx,
      GSIZE_TO_POINTER (GPOINTER_TO_SIZE (target) + insn->size), args->core);
  duk_put_prop_string (ctx, -2, "next");

  duk_push_number (ctx, insn->size);
  duk_put_prop_string (ctx, -2, "size");

  duk_push_string (ctx, insn->mnemonic);
  duk_put_prop_string (ctx, -2, "mnemonic");

  duk_push_string (ctx, insn->op_str);
  duk_put_prop_string (ctx, -2, "opStr");

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_string)
{
  const gchar * mnemonic, * op_str;
  gchar * result;

  duk_push_this (ctx);

  duk_get_prop_string (ctx, -1, "mnemonic");
  mnemonic = duk_get_string (ctx, -1);

  duk_get_prop_string (ctx, -2, "opStr");
  op_str = duk_get_string (ctx, -1);

  result = g_strconcat (mnemonic, " ", op_str, NULL);

  duk_pop_3 (ctx);

  duk_push_string (ctx, result);

  g_free (result);

  return 1;
}
