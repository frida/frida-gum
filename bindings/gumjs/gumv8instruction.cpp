/*
 * Copyright (C) 2014-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8instruction.h"

#include "gumv8macros.h"

#include <string.h>

#define GUMJS_MODULE_NAME Instruction

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

#define GUM_INSTRUCTION_FOOTPRINT_ESTIMATE 256

using namespace v8;

struct GumInstruction
{
  GumPersistent<v8::Object>::type * wrapper;
  gpointer target;
  cs_insn insn;
  GumV8Instruction * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

static Local<Object> gum_instruction_new (gpointer target, const cs_insn * insn,
    GumV8Instruction * module);
static void gum_instruction_free (GumInstruction * self);
GUMJS_DECLARE_GETTER (gumjs_instruction_get_address)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_next)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_size)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_mnemonic)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_op_str)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_string)
static void gum_instruction_on_weak_notify (
    const WeakCallbackInfo<GumInstruction> & info);

static const GumV8Function gumjs_instruction_module_functions[] =
{
  { "_parse", gumjs_instruction_parse },

  { NULL, NULL }
};

static const GumV8Property gumjs_instruction_values[] =
{
  { "address", gumjs_instruction_get_address, NULL },
  { "next", gumjs_instruction_get_next, NULL },
  { "size", gumjs_instruction_get_size, NULL },
  { "mnemonic", gumjs_instruction_get_mnemonic, NULL },
  { "opStr", gumjs_instruction_get_op_str, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_instruction_functions[] =
{
  { "toString", gumjs_instruction_to_string },

  { NULL, NULL }
};

void
_gum_v8_instruction_init (GumV8Instruction * self,
                          GumV8Core * core,
                          Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto err =
      cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  auto module = External::New (isolate, self);

  auto api = _gum_v8_create_module ("Instruction", scope, isolate);
  _gum_v8_module_add (module, api, gumjs_instruction_module_functions, isolate);

  auto value = _gum_v8_create_class ("InstructionValue", nullptr, scope, module,
      isolate);
  _gum_v8_class_add (value, gumjs_instruction_values, module, isolate);
  _gum_v8_class_add (value, gumjs_instruction_functions, module, isolate);
  self->constructor =
      new GumPersistent<FunctionTemplate>::type (isolate, value);
}

void
_gum_v8_instruction_realize (GumV8Instruction * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  self->instructions = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_instruction_free);

  auto constructor = Local<FunctionTemplate>::New (isolate, *self->constructor);
  auto object = constructor->GetFunction ()->NewInstance (context, 0, nullptr)
      .ToLocalChecked ();
  self->template_object = new GumPersistent<Object>::type (isolate, object);
}

void
_gum_v8_instruction_dispose (GumV8Instruction * self)
{
  g_hash_table_unref (self->instructions);
  self->instructions = NULL;

  delete self->template_object;
  self->template_object = nullptr;

  delete self->constructor;
  self->constructor = nullptr;
}

void
_gum_v8_instruction_finalize (GumV8Instruction * self)
{
  cs_close (&self->capstone);
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_parse)
{
  gpointer target;
  if (!_gum_v8_args_parse (args, "p", &target))
    return;

  uint64_t address;
#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (module->capstone, CS_OPT_MODE,
      (GPOINTER_TO_SIZE (target) & 1) == 1 ? CS_MODE_THUMB : CS_MODE_ARM);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  cs_insn * insn;
  if (cs_disasm (module->capstone, (uint8_t *) GSIZE_TO_POINTER (address), 16,
      address, 1, &insn) == 0)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid instruction");
    return;
  }

  info.GetReturnValue ().Set (gum_instruction_new (target, insn, module));

  cs_free (insn, 1);
}

static Local<Object>
gum_instruction_new (gpointer target,
                     const cs_insn * insn,
                     GumV8Instruction * module)
{
  auto isolate = module->core->isolate;

  auto template_object = Local<Object>::New (isolate, *module->template_object);
  auto object = template_object->Clone ();

  auto instruction = g_slice_new (GumInstruction);
  instruction->wrapper = new GumPersistent<Object>::type (isolate, object);
  instruction->wrapper->MarkIndependent ();
  instruction->wrapper->SetWeak (instruction, gum_instruction_on_weak_notify,
      WeakCallbackType::kParameter);
  instruction->target = target;
  memcpy (&instruction->insn, insn, sizeof (cs_insn));
  instruction->module = module;

  object->SetAlignedPointerInInternalField (0, instruction);

  isolate->AdjustAmountOfExternalAllocatedMemory (
      GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  g_hash_table_insert (module->instructions, instruction, instruction);

  return object;
}

static void
gum_instruction_free (GumInstruction * self)
{
  self->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  delete self->wrapper;

  g_slice_free (GumInstruction, self);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_address, GumInstruction)
{
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (self->insn.address), core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_next, GumInstruction)
{
  auto next = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (self->target) + self->insn.size);

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (next, core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_size, GumInstruction)
{
  info.GetReturnValue ().Set (self->insn.size);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_mnemonic, GumInstruction)
{
  info.GetReturnValue ().Set (
      _gum_v8_string_new_ascii (isolate, self->insn.mnemonic));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_op_str, GumInstruction)
{
  info.GetReturnValue ().Set (
      _gum_v8_string_new_ascii (isolate, self->insn.op_str));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_instruction_to_string, GumInstruction)
{
  cs_insn * insn = &self->insn;
  auto str = g_strconcat (insn->mnemonic, " ", insn->op_str, (void *) NULL);
  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
  g_free (str);
}

static void
gum_instruction_on_weak_notify (const WeakCallbackInfo<GumInstruction> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->instructions, self);
}
