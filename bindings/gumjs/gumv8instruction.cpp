/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8instruction.h"

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

#define GUM_INSTRUCTION_FOOTPRINT_ESTIMATE 256

using namespace v8;

typedef struct _GumInstruction GumInstruction;

struct _GumInstruction
{
  GumPersistent<v8::Object>::type * instance;
  gpointer target;
  cs_insn insn;
  GumV8Instruction * module;
};

static void gum_v8_instruction_on_parse (
    const FunctionCallbackInfo<Value> & info);

static GumInstruction * gum_instruction_new (Handle<Object> instance,
    gpointer target, const cs_insn * insn, GumV8Instruction * module);
static void gum_instruction_free (GumInstruction * instruction);
static void gum_instruction_on_weak_notify (
    const WeakCallbackInfo<GumInstruction> & info);

static void gum_v8_instruction_on_get_address (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_v8_instruction_on_get_next (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_v8_instruction_on_get_size (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_v8_instruction_on_get_mnemonic (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_v8_instruction_on_get_op_str (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_v8_instruction_on_to_string (
    const FunctionCallbackInfo<Value> & info);

void
_gum_v8_instruction_init (GumV8Instruction * self,
                          GumV8Core * core,
                          Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;
  cs_err err;

  self->core = core;

  err = cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> instruction = ObjectTemplate::New (isolate);
  instruction->Set (String::NewFromUtf8 (isolate, "_parse"),
      FunctionTemplate::New (isolate, gum_v8_instruction_on_parse, data));
  scope->Set (String::NewFromUtf8 (isolate, "Instruction"), instruction);
}

void
_gum_v8_instruction_realize (GumV8Instruction * self)
{
  Isolate * isolate = self->core->isolate;

  self->instructions = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_instruction_free));

  Handle<ObjectTemplate> instruction = ObjectTemplate::New (isolate);
  instruction->SetInternalFieldCount (1);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "address"),
      gum_v8_instruction_on_get_address);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "next"),
      gum_v8_instruction_on_get_next);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "size"),
      gum_v8_instruction_on_get_size);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "mnemonic"),
      gum_v8_instruction_on_get_mnemonic);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "opStr"),
      gum_v8_instruction_on_get_op_str);
  instruction->Set (String::NewFromUtf8 (isolate, "toString"),
      FunctionTemplate::New (isolate, gum_v8_instruction_on_to_string));
  self->value =
      new GumPersistent<Object>::type (isolate, instruction->NewInstance ());
}

void
_gum_v8_instruction_dispose (GumV8Instruction * self)
{
  g_hash_table_unref (self->instructions);
  self->instructions = NULL;

  delete self->value;
  self->value = NULL;
}

void
_gum_v8_instruction_finalize (GumV8Instruction * self)
{
  cs_close (&self->capstone);
}

static void
gum_v8_instruction_on_parse (const FunctionCallbackInfo<Value> & info)
{
  GumV8Instruction * self = static_cast<GumV8Instruction *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  gpointer target;
  if (!_gum_v8_native_pointer_get (info[0], &target, self->core))
    return;

  uint64_t address;
#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (self->capstone, CS_OPT_MODE,
      (GPOINTER_TO_SIZE (target) & 1) == 1 ? CS_MODE_THUMB : CS_MODE_ARM);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  cs_insn * insn;
  if (cs_disasm (self->capstone, (uint8_t *) GSIZE_TO_POINTER (address), 16,
      address, 1, &insn) == 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Instruction.parse: invalid instruction")));
    return;
  }

  Local<Object> value (Local<Object>::New (isolate, *self->value));
  Local<Object> instance (value->Clone ());
  GumInstruction * instruction =
      gum_instruction_new (instance, target, insn, self);
  instance->SetAlignedPointerInInternalField (0, instruction);
  info.GetReturnValue ().Set (instance);

  cs_free (insn, 1);
}

static GumInstruction *
gum_instruction_new (Handle<Object> instance,
                     gpointer target,
                     const cs_insn * insn,
                     GumV8Instruction * module)
{
  GumInstruction * instruction;
  Isolate * isolate = module->core->isolate;

  instruction = g_slice_new (GumInstruction);
  instruction->instance = new GumPersistent<Object>::type (isolate, instance);
  instruction->instance->MarkIndependent ();
  instruction->instance->SetWeak (instruction, gum_instruction_on_weak_notify,
      WeakCallbackType::kParameter);
  instruction->target = target;
  memcpy (&instruction->insn, insn, sizeof (cs_insn));
  instruction->module = module;

  isolate->AdjustAmountOfExternalAllocatedMemory (
      GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  g_hash_table_insert (module->instructions, instruction, instruction);

  return instruction;
}

static void
gum_instruction_free (GumInstruction * instruction)
{
  instruction->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  delete instruction->instance;
  g_slice_free (GumInstruction, instruction);
}

static void
gum_instruction_on_weak_notify (const WeakCallbackInfo<GumInstruction> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GumInstruction * self = info.GetParameter ();
  g_hash_table_remove (self->module->instructions, self);
}

static void
gum_v8_instruction_on_get_address (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (self->insn.address),
          self->module->core));
}

static void
gum_v8_instruction_on_get_next (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  gpointer next = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (self->target) + self->insn.size);
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (next, self->module->core));
}

static void
gum_v8_instruction_on_get_size (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (self->insn.size);
}

static void
gum_v8_instruction_on_get_mnemonic (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (info.GetIsolate (), self->insn.mnemonic));
}

static void
gum_v8_instruction_on_get_op_str (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (info.GetIsolate (), self->insn.op_str));
}

static void
gum_v8_instruction_on_to_string (const FunctionCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  cs_insn * insn = &self->insn;
  gchar * str = g_strconcat (insn->mnemonic, " ", insn->op_str,
      static_cast<void *> (NULL));
  info.GetReturnValue ().Set (String::NewFromUtf8 (info.GetIsolate (), str));
  g_free (str);
}
