/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptinstruction.h"

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
  cs_insn * handle;
  GumScriptInstruction * module;
};

static void gum_script_instruction_on_parse (
    const FunctionCallbackInfo<Value> & info);

static GumInstruction * gum_instruction_new (Handle<Object> instance,
    gpointer target, cs_insn * handle, GumScriptInstruction * module);
static void gum_instruction_free (GumInstruction * instruction);
static void gum_instruction_on_weak_notify (const WeakCallbackData<Object,
    GumInstruction> & data);

static void gum_script_instruction_on_get_address (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_instruction_on_get_next (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_instruction_on_get_size (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_instruction_on_get_mnemonic (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_instruction_on_get_op_str (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_instruction_on_to_string (
    const FunctionCallbackInfo<Value> & info);

void
_gum_script_instruction_init (GumScriptInstruction * self,
                              GumScriptCore * core,
                              Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;
  cs_err err;

  self->core = core;

  err = cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> instruction = ObjectTemplate::New (isolate);
  instruction->Set (String::NewFromUtf8 (isolate, "parse"),
      FunctionTemplate::New (isolate, gum_script_instruction_on_parse, data));
  scope->Set (String::NewFromUtf8 (isolate, "Instruction"), instruction);
}

void
_gum_script_instruction_realize (GumScriptInstruction * self)
{
  Isolate * isolate = self->core->isolate;

  self->instructions = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_instruction_free));

  Handle<ObjectTemplate> instruction = ObjectTemplate::New (isolate);
  instruction->SetInternalFieldCount (1);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "address"),
      gum_script_instruction_on_get_address);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "next"),
      gum_script_instruction_on_get_next);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "size"),
      gum_script_instruction_on_get_size);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "mnemonic"),
      gum_script_instruction_on_get_mnemonic);
  instruction->SetAccessor (String::NewFromUtf8 (isolate, "opStr"),
      gum_script_instruction_on_get_op_str);
  instruction->Set (String::NewFromUtf8 (isolate, "toString"),
      FunctionTemplate::New (isolate, gum_script_instruction_on_to_string));
  self->value =
      new GumPersistent<Object>::type (isolate, instruction->NewInstance ());
}

void
_gum_script_instruction_dispose (GumScriptInstruction * self)
{
  g_hash_table_remove_all (self->instructions);
  g_hash_table_unref (self->instructions);
  self->instructions = NULL;

  delete self->value;
  self->value = NULL;
}

void
_gum_script_instruction_finalize (GumScriptInstruction * self)
{
  cs_close (&self->capstone);
}

static void
gum_script_instruction_on_parse (const FunctionCallbackInfo<Value> & info)
{
  GumScriptInstruction * self = static_cast<GumScriptInstruction *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  gpointer target;
  if (!_gum_script_pointer_get (info[0], &target, self->core))
    return;

  uint64_t address;
#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (self->capstone, CS_OPT_MODE,
      (GPOINTER_TO_SIZE (target) & 1) == 1 ? CS_MODE_THUMB : CS_MODE_ARM);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  cs_insn * handle;
  if (cs_disasm_ex (self->capstone, static_cast<uint8_t *> (target), 16,
      address, 1, &handle) == 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Instruction.parse: invalid instruction")));
    return;
  }

  Local<Object> value (Local<Object>::New (isolate, *self->value));
  Local<Object> instance (value->Clone ());
  GumInstruction * instruction =
      gum_instruction_new (instance, target, handle, self);
  instance->SetAlignedPointerInInternalField (0, instruction);
  info.GetReturnValue ().Set (instance);
}

static GumInstruction *
gum_instruction_new (Handle<Object> instance,
                     gpointer target,
                     cs_insn * handle,
                     GumScriptInstruction * module)
{
  GumInstruction * instruction;
  Isolate * isolate = module->core->isolate;

  instruction = g_slice_new (GumInstruction);
  instruction->instance = new GumPersistent<Object>::type (isolate, instance);
  instruction->instance->MarkIndependent ();
  instruction->instance->SetWeak (instruction, gum_instruction_on_weak_notify);
  instruction->target = target;
  instruction->handle = handle;
  instruction->module = module;

  isolate->AdjustAmountOfExternalAllocatedMemory (
      GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  g_hash_table_insert (module->instructions, handle, instruction);

  return instruction;
}

static void
gum_instruction_free (GumInstruction * instruction)
{
  instruction->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  cs_free (instruction->handle, 1);
  delete instruction->instance;
  g_slice_free (GumInstruction, instruction);
}

static void
gum_instruction_on_weak_notify (const WeakCallbackData<Object,
    GumInstruction> & data)
{
  HandleScope handle_scope (data.GetIsolate ());
  GumInstruction * self = data.GetParameter ();
  g_hash_table_remove (self->module->instructions, self->handle);
}

static void
gum_script_instruction_on_get_address (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (
      _gum_script_pointer_new (GSIZE_TO_POINTER (self->handle->address),
          self->module->core));
}

static void
gum_script_instruction_on_get_next (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  gpointer next = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (self->target) + self->handle->size);
  info.GetReturnValue ().Set (
      _gum_script_pointer_new (next, self->module->core));
}

static void
gum_script_instruction_on_get_size (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (self->handle->size);
}

static void
gum_script_instruction_on_get_mnemonic (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (info.GetIsolate (), self->handle->mnemonic));
}

static void
gum_script_instruction_on_get_op_str (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (info.GetIsolate (), self->handle->op_str));
}

static void
gum_script_instruction_on_to_string (const FunctionCallbackInfo<Value> & info)
{
  GumInstruction * self = static_cast<GumInstruction *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  cs_insn * insn = self->handle;
  gchar * str = g_strconcat (insn->mnemonic, " ", insn->op_str, NULL);
  info.GetReturnValue ().Set (String::NewFromUtf8 (info.GetIsolate (), str));
  g_free (str);
}
