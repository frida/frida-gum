/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptcore.h"

#include "gumjscriptmacros.h"

#include <ffi.h>

#define GUM_SCRIPT_CORE_LOCK(core)   (g_mutex_lock (&(core)->mutex))
#define GUM_SCRIPT_CORE_UNLOCK(core) (g_mutex_unlock (&(core)->mutex))

typedef struct _GumScriptWeakRef GumScipeWeakRef;
typedef struct _GumScriptNativeFunction GumScriptNativeFunction;
typedef struct _GumScriptNativeCallback GumScriptNativeCallback;
typedef union _GumFFIValue GumFFIValue;
typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;

struct _GumScriptWeakRef
{
  guint id;
  GumScriptWeakRef * target;
  JSObjectRef callback;

  GumScriptCore * core;
};

struct _GumScriptScheduledCallback
{
  gint id;
  gboolean repeat;
  JSObjectRef func;
  GSource * source;

  GumScriptCore * core;
};

struct _GumScriptExceptionSink
{
  JSObjectRef callback;
  JSContextRef ctx;
};

struct _GumScriptMessageSink
{
  JSObjectRef callback;
  JSContextRef ctx;
};

struct _GumScriptNativeFunction
{
  GumScriptNativePointer parent;

  gpointer fn;
  ffi_cif cif;
  ffi_type ** atypes;
  gsize arglist_size;
  GSList * data;

  GumScriptCore * core;
};

struct _GumScriptNativeCallback
{
  GumScriptNativePointer parent;

  JSObjectRef func;
  ffi_closure * closure;
  ffi_cif cif;
  ffi_type ** atypes;
  GSList * data;

  GumScriptCore * core;
};

union _GumFFIValue
{
  gpointer v_pointer;
  gint v_sint;
  guint v_uint;
  glong v_slong;
  gulong v_ulong;
  gchar v_schar;
  guchar v_uchar;
  gfloat v_float;
  gdouble v_double;
  gint8 v_sint8;
  guint8 v_uint8;
  gint16 v_sint16;
  guint16 v_uint16;
  gint32 v_sint32;
  guint32 v_uint32;
  gint64 v_sint64;
  guint64 v_uint64;
};

struct _GumFFITypeMapping
{
  const gchar * name;
  ffi_type * type;
};

struct _GumFFIABIMapping
{
  const gchar * name;
  ffi_abi abi;
};

GUMJS_DECLARE_FUNCTION (gumjs_set_timeout)
GUMJS_DECLARE_FUNCTION (gumjs_set_interval)
GUMJS_DECLARE_FUNCTION (gumjs_clear_timer)
GUMJS_DECLARE_FUNCTION (gumjs_gc)
GUMJS_DECLARE_FUNCTION (gumjs_send)
GUMJS_DECLARE_FUNCTION (gumjs_set_unhandled_exception_callback)
GUMJS_DECLARE_FUNCTION (gumjs_set_incoming_message_callback)
GUMJS_DECLARE_FUNCTION (gumjs_wait_for_event)

GUMJS_DECLARE_GETTER (gumjs_script_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_script_get_source_map_data)

GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_bind)
GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_unbind)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_pointer_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_pointer_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_is_null)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_add)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_sub)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_and)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_or)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_xor)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_compare)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_int32)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_match_pattern)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_function_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_function_finalize)
static void gum_script_native_function_finalize (
    GumScriptNativeFunction * func);
GUMJS_DECLARE_FUNCTION (gumjs_native_function_invoke)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_callback_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_callback_finalize)
static void gum_script_native_callback_finalize (
    GumScriptNativeCallback * func);
static void gum_script_native_callback_invoke (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cpu_context_construct)
GUMJS_DECLARE_FINALIZER (gumjs_cpu_context_finalize)
static bool gumjs_cpu_context_set_register (GumScriptCpuContext * self,
    JSContextRef ctx, const GumScriptArgs * args, gsize * reg,
    JSValueRef * exception);

static void gum_clear_weak_ref_entry (guint id, GumScriptWeakRef * ref);
static GumScriptWeakRef * gum_script_weak_ref_new (guint id, JSValueRef target,
    JSObjectRef callback, GumScriptCore * core);
static void gum_script_weak_ref_clear (GumScriptWeakRef * ref);
static void gum_script_weak_ref_free (GumScriptWeakRef * ref);
static void gum_script_weak_ref_on_weak_notify (GumScriptWeakRef * self);

static JSValueRef gum_script_core_schedule_callback (GumScriptCore * self,
    const GumScriptArgs * args, gboolean repeat);
static void gum_script_core_add_scheduled_callback (GumScriptCore * self,
    GumScriptScheduledCallback * cb);
static void gum_script_core_remove_scheduled_callback (GumScriptCore * self,
    GumScriptScheduledCallback * cb);

static GumScriptScheduledCallback * gum_scheduled_callback_new (guint id,
    JSObjectRef func, gboolean repeat, GSource * source, GumScriptCore * core);
static void gum_scheduled_callback_free (GumScriptScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (gpointer user_data);

static GumScriptExceptionSink * gum_script_exception_sink_new (JSContextRef ctx,
    JSObjectRef callback);
static void gum_script_exception_sink_free (GumScriptExceptionSink * sink);
static void gum_script_exception_sink_handle_exception (
    GumScriptExceptionSink * self, JSValueRef exception);

static GumScriptMessageSink * gum_script_message_sink_new (JSContextRef ctx,
    JSObjectRef callback);
static void gum_script_message_sink_free (GumScriptMessageSink * sink);
static void gum_script_message_sink_handle_message (GumScriptMessageSink * self,
    const gchar * message, JSValueRef * exception);

static gboolean gumjs_ffi_type_try_get (JSContextRef ctx, JSValueRef value,
    ffi_type ** type, GSList ** data, JSValueRef * exception);
static gboolean gumjs_ffi_abi_try_get (JSContextRef ctx, const gchar * name,
    ffi_abi * abi, JSValueRef * exception);
static gboolean gumjs_value_to_ffi_type (JSContextRef ctx, JSValueRef svalue,
    const ffi_type * type, GumScriptCore * core, GumFFIValue * value,
    JSValueRef * exception);
static gboolean gumjs_value_from_ffi_type (JSContextRef ctx,
    const GumFFIValue * value, const ffi_type * type, GumScriptCore * core,
    JSValueRef * svalue, JSValueRef * exception);

static const JSStaticValue gumjs_script_values[] =
{
  { "fileName", gumjs_script_get_file_name, NULL, GUMJS_RO },
  { "_sourceMapData", gumjs_script_get_source_map_data, NULL, GUMJS_RO },

  { NULL, NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_weak_ref_functions[] =
{
  { "bind", gumjs_weak_ref_bind, GUMJS_RO },
  { "unbind", gumjs_weak_ref_unbind, GUMJS_RO },

  { NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_native_pointer_functions[] =
{
  { "isNull", gumjs_native_pointer_is_null, GUMJS_RO },
  { "add", gumjs_native_pointer_add, GUMJS_RO },
  { "sub", gumjs_native_pointer_sub, GUMJS_RO },
  { "and", gumjs_native_pointer_and, GUMJS_RO },
  { "or", gumjs_native_pointer_or, GUMJS_RO },
  { "xor", gumjs_native_pointer_xor, GUMJS_RO },
  { "compare", gumjs_native_pointer_compare, GUMJS_RO },
  { "toInt32", gumjs_native_pointer_to_int32, GUMJS_RO },
  { "toString", gumjs_native_pointer_to_string, GUMJS_RO },
  { "toJSON", gumjs_native_pointer_to_json, GUMJS_RO },
  { "toMatchPattern", gumjs_native_pointer_to_match_pattern, GUMJS_RO },

  { NULL, NULL, 0 }
};

#define GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
  { \
    GumScriptCpuContext * self = JSObjectGetPrivate (object); \
    \
    return _gumjs_native_pointer_new (ctx, \
        GSIZE_TO_POINTER (self->handle->R), args->core); \
  } \
  \
  GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
  { \
    GumScriptCpuContext * self = JSObjectGetPrivate (object); \
    \
    return gumjs_cpu_context_set_register (self, ctx, args, \
        (gsize *) &self->handle->R, exception); \
  }
#define GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR(R) \
  GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (R, R)

#define GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  { G_STRINGIFY (A), gumjs_cpu_context_get_##R, gumjs_cpu_context_set_##R, \
    GUMJS_RW }
#define GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR(R) \
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (R, R)

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (eax)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (ecx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (edx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (ebx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (esp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (ebp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (esi)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (edi)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (eip)
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rax)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rcx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rdx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rbx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rsp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rbp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rsi)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rdi)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r8)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r9)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r10)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r11)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r12)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r13)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r14)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r15)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rip)
#elif defined (HAVE_ARM)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (pc)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (sp)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r0, r[0])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r1, r[1])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r2, r[2])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r3, r[3])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r4, r[4])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r5, r[5])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r6, r[6])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r7, r[7])

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (lr)
#elif defined (HAVE_ARM64)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (pc)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (sp)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x0, x[0])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x1, x[1])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x2, x[2])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x3, x[3])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x4, x[4])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x5, x[5])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x6, x[6])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x7, x[7])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x8, x[8])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x9, x[9])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x10, x[10])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x11, x[11])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x12, x[12])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x13, x[13])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x14, x[14])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x15, x[15])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x16, x[16])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x17, x[17])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x18, x[18])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x19, x[19])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x20, x[20])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x21, x[21])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x22, x[22])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x23, x[23])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x24, x[24])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x25, x[25])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x26, x[26])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x27, x[27])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x28, x[28])

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (fp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (lr)
#endif

static const JSStaticValue gumjs_cpu_context_values[] =
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (pc, eip),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (sp, esp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (eax),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (ecx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (edx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (ebx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (esp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (ebp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (esi),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (edi),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (eip),
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (pc, rip),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (sp, rsp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rax),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rcx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rdx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rbx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rsp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rbp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rsi),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rdi),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r8),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r9),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r10),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r11),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r12),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r13),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r14),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r15),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rip),
#elif defined (HAVE_ARM)
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (pc),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (sp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r1),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r2),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r3),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r4),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r5),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r6),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r7),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (lr),
#elif defined (HAVE_ARM64)
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (pc),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (sp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x1),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x2),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x3),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x4),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x5),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x6),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x7),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x8),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x9),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x10),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x11),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x12),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x13),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x14),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x15),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x16),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x17),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x18),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x19),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x20),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x21),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x22),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x23),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x24),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x25),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x26),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x27),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x28),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (fp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (lr),
#endif

  { NULL, NULL, NULL, 0 }
};

void
_gum_script_core_init (GumScriptCore * self,
                       GumScript * script,
                       GumScriptCoreMessageEmitter message_emitter,
                       GumScriptScheduler * scheduler,
                       JSContextRef ctx,
                       JSObjectRef scope)
{
  GumScriptFlavor flavor;
  JSClassDefinition def;
  JSObjectRef frida, obj;
  JSClassRef klass;

  g_object_get (script, "flavor", &flavor, NULL);

  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->ctx = ctx;

  g_mutex_init (&self->mutex);
  g_cond_init (&self->event_cond);

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_script_weak_ref_free);

  self->native_resources = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) _gumjs_native_resource_free);

  JSObjectSetPrivate (scope, self);

  _gumjs_object_set (ctx, scope, "global", scope);

  frida = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_string (ctx, frida, "version", FRIDA_VERSION);
  _gumjs_object_set (ctx, scope, "Frida", frida);

  def = kJSClassDefinitionEmpty;
  def.className = "Script";
  def.staticValues = gumjs_script_values;
  klass = JSClassCreate (&def);
  obj = JSObjectMake (ctx, klass, self);
  _gumjs_object_set_string (ctx, obj, "runtime", "JSC");
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, obj);

  def = kJSClassDefinitionEmpty;
  def.className = "WeakRef";
  def.staticFunctions = gumjs_weak_ref_functions;
  klass = JSClassCreate (&def);
  obj = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, obj);

  _gumjs_object_set_function (ctx, scope, "setTimeout", gumjs_set_timeout);
  _gumjs_object_set_function (ctx, scope, "clearTimeout", gumjs_clear_timer);
  _gumjs_object_set_function (ctx, scope, "setInterval", gumjs_set_interval);
  _gumjs_object_set_function (ctx, scope, "clearInterval", gumjs_clear_timer);
  _gumjs_object_set_function (ctx, scope, "gc", gumjs_gc);
  _gumjs_object_set_function (ctx, scope, "_send", gumjs_send);
  _gumjs_object_set_function (ctx, scope, "_setUnhandledExceptionCallback",
      gumjs_set_unhandled_exception_callback);
  _gumjs_object_set_function (ctx, scope, "_setIncomingMessageCallback",
      gumjs_set_incoming_message_callback);
  _gumjs_object_set_function (ctx, scope, "_waitForEvent",
      gumjs_wait_for_event);

  def = kJSClassDefinitionEmpty;
  def.className = "NativePointer";
  def.staticFunctions = gumjs_native_pointer_functions;
  def.finalize = gumjs_native_pointer_finalize;
  self->native_pointer = JSClassCreate (&def);
  _gumjs_object_set (ctx, scope, def.className, JSObjectMakeConstructor (ctx,
      self->native_pointer, gumjs_native_pointer_construct));

  if (flavor == GUM_SCRIPT_FLAVOR_USER)
  {
    def = kJSClassDefinitionEmpty;
    def.className = "NativeFunction";
    def.parentClass = self->native_pointer;
    def.finalize = gumjs_native_function_finalize;
    def.callAsFunction = gumjs_native_function_invoke;
    self->native_function = JSClassCreate (&def);
    _gumjs_object_set (ctx, scope, def.className, JSObjectMakeConstructor (ctx,
        self->native_function, gumjs_native_function_construct));

    def = kJSClassDefinitionEmpty;
    def.className = "NativeCallback";
    def.parentClass = self->native_pointer;
    def.finalize = gumjs_native_callback_finalize;
    self->native_callback = JSClassCreate (&def);
    _gumjs_object_set (ctx, scope, def.className, JSObjectMakeConstructor (ctx,
        self->native_callback, gumjs_native_callback_construct));
  }

  def = kJSClassDefinitionEmpty;
  def.className = "CpuContext";
  def.staticValues = gumjs_cpu_context_values;
  def.finalize = gumjs_cpu_context_finalize;
  self->cpu_context = JSClassCreate (&def);
  _gumjs_object_set (ctx, scope, def.className, JSObjectMakeConstructor (ctx,
      self->cpu_context, gumjs_cpu_context_construct));

  self->array_buffer =
      (JSObjectRef) _gumjs_object_get (ctx, scope, "ArrayBuffer");
  JSValueProtect (ctx, self->array_buffer);
}

void
_gum_script_core_flush (GumScriptCore * self)
{
  GMainContext * context;

  GUM_SCRIPT_CORE_UNLOCK (self);
  gum_script_scheduler_flush_by_tag (self->scheduler, self);
  GUM_SCRIPT_CORE_LOCK (self);

  context = gum_script_scheduler_get_js_context (self->scheduler);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);

  g_hash_table_foreach (self->weak_refs,
      (GHFunc) gum_clear_weak_ref_entry, NULL);
  g_hash_table_remove_all (self->weak_refs);
}

void
_gum_script_core_dispose (GumScriptCore * self)
{
  g_clear_pointer (&self->native_resources, g_hash_table_unref);

  while (self->scheduled_callbacks != NULL)
  {
    g_source_destroy (((GumScriptScheduledCallback *) (
        self->scheduled_callbacks->data))->source);
    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);
  }

  g_clear_pointer (&self->unhandled_exception_sink,
      gum_script_exception_sink_free);

  g_clear_pointer (&self->incoming_message_sink, gum_script_message_sink_free);

  JSValueUnprotect (self->ctx, self->array_buffer);
  self->array_buffer = NULL;

  g_clear_pointer (&self->cpu_context, JSClassRelease);
  g_clear_pointer (&self->native_callback, JSClassRelease);
  g_clear_pointer (&self->native_function, JSClassRelease);
  g_clear_pointer (&self->native_pointer, JSClassRelease);

  g_clear_pointer (&self->exceptor, g_object_unref);
}

void
_gum_script_core_finalize (GumScriptCore * self)
{
  g_clear_pointer (&self->weak_refs, g_hash_table_unref);

  g_mutex_clear (&self->mutex);
  g_cond_clear (&self->event_cond);
}

void
_gum_script_core_emit_message (GumScriptCore * self,
                               const gchar * message,
                               GBytes * data)
{
  self->message_emitter (self->script, message, data);
}

void
_gum_script_core_post_message (GumScriptCore * self,
                               const gchar * message)
{
  if (self->incoming_message_sink != NULL)
  {
    GumScriptScope scope;

    _gum_script_scope_enter (&scope, self);

    gum_script_message_sink_handle_message (self->incoming_message_sink,
        message, &scope.exception);

    _gum_script_scope_leave (&scope);

    GUM_SCRIPT_CORE_LOCK (self);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    GUM_SCRIPT_CORE_UNLOCK (self);
  }
}

void
_gum_script_core_push_job (GumScriptCore * self,
                           GumScriptJobFunc job_func,
                           gpointer data,
                           GDestroyNotify data_destroy)
{
  gum_script_scheduler_push_job_on_thread_pool (self->scheduler, job_func,
      data, data_destroy, self);
}

void
_gum_script_scope_enter (GumScriptScope * self,
                         GumScriptCore * core)
{
  self->core = core;
  self->exception = NULL;

  GUM_SCRIPT_CORE_LOCK (core);
}

void
_gum_script_scope_flush (GumScriptScope * self)
{
  GumScriptCore * core = self->core;

  if (self->exception != NULL && core->unhandled_exception_sink != NULL)
  {
    gum_script_exception_sink_handle_exception (core->unhandled_exception_sink,
        self->exception);
    self->exception = NULL;
  }
}

void
_gum_script_scope_leave (GumScriptScope * self)
{
  _gum_script_scope_flush (self);

  GUM_SCRIPT_CORE_UNLOCK (self->core);
}

void
_gum_script_yield_begin (GumScriptYield * self,
                         GumScriptCore * core)
{
  self->core = core;

  GUM_SCRIPT_CORE_UNLOCK (core);
}

void
_gum_script_yield_end (GumScriptYield * self)
{
  GUM_SCRIPT_CORE_LOCK (self->core);
}

GUMJS_DEFINE_GETTER (gumjs_script_get_file_name)
{
  GumScriptCore * self = args->core;
  JSValueRef result;
  gchar * name, * file_name;

  g_object_get (self->script, "name", &name, NULL);
  file_name = g_strconcat (name, ".js", NULL);
  result = _gumjs_string_to_value (ctx, file_name);
  g_free (file_name);
  g_free (name);

  return result;
}

GUMJS_DEFINE_GETTER (gumjs_script_get_source_map_data)
{
  /* TODO */

  return JSValueMakeNull (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_bind)
{
  GumScriptCore * self = args->core;
  JSValueRef target;
  JSObjectRef callback;
  guint id;
  GumScriptWeakRef * ref;

  if (!_gumjs_args_parse (args, "VF", &target, &callback))
    return NULL;

  switch (JSValueGetType (ctx, target))
  {
    case kJSTypeString:
    case kJSTypeObject:
      break;
    case kJSTypeUndefined:
    case kJSTypeNull:
    case kJSTypeBoolean:
    case kJSTypeNumber:
      goto invalid_type;
    default:
      g_assert_not_reached ();
  }

  id = ++self->last_weak_ref_id;

  ref = gum_script_weak_ref_new (id, target, callback, self);
  g_hash_table_insert (self->weak_refs, GUINT_TO_POINTER (id), ref);

  return JSValueMakeNumber (ctx, id);

invalid_type:
  {
    _gumjs_throw (ctx, exception, "expected a non-primitive value");
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_unbind)
{
  GumScriptCore * self = args->core;
  guint id;
  gboolean removed;

  if (!_gumjs_args_parse (args, "u", &id))
    return NULL;

  removed = !!g_hash_table_remove (self->weak_refs, GUINT_TO_POINTER (id));

  return JSValueMakeBoolean (ctx, removed);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_timeout)
{
  return gum_script_core_schedule_callback (args->core, args, FALSE);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_interval)
{
  return gum_script_core_schedule_callback (args->core, args, TRUE);
}

GUMJS_DEFINE_FUNCTION (gumjs_clear_timer)
{
  GumScriptCore * self = args->core;
  gint id;
  GumScriptScheduledCallback * callback = NULL;
  GSList * cur;

  if (!_gumjs_args_parse (args, "i", &id))
    return NULL;

  for (cur = self->scheduled_callbacks; cur != NULL; cur = cur->next)
  {
    GumScriptScheduledCallback * cb = cur->data;
    if (cb->id == id)
    {
      callback = cb;
      self->scheduled_callbacks =
          g_slist_delete_link (self->scheduled_callbacks, cur);
      break;
    }
  }

  if (callback != NULL)
    g_source_destroy (callback->source);

  return JSValueMakeBoolean (ctx, callback != NULL);
}

GUMJS_DEFINE_FUNCTION (gumjs_gc)
{
  JSGarbageCollect (ctx);

  return JSValueMakeUndefined (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_send)
{
  gchar * message;
  GBytes * data = NULL;

  if (!_gumjs_args_parse (args, "s|B?", &message, &data))
    return NULL;

  _gum_script_core_emit_message (args->core, message, data);

  g_bytes_unref (data);
  g_free (message);

  return JSValueMakeUndefined (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumScriptCore * self = args->core;
  JSObjectRef callback;

  if (!_gumjs_args_parse (args, "F?", &callback))
    return NULL;

  g_clear_pointer (&self->unhandled_exception_sink,
      gum_script_exception_sink_free);

  if (callback != NULL)
  {
    self->unhandled_exception_sink =
        gum_script_exception_sink_new (self->ctx, callback);
  }

  return JSValueMakeUndefined (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_incoming_message_callback)
{
  GumScriptCore * self = args->core;
  JSObjectRef callback;

  if (!_gumjs_args_parse (args, "F?", &callback))
    return NULL;

  g_clear_pointer (&self->incoming_message_sink, gum_script_message_sink_free);

  if (callback != NULL)
  {
    self->incoming_message_sink = gum_script_message_sink_new (self->ctx,
        callback);
  }

  return JSValueMakeUndefined (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_wait_for_event)
{
  GumScriptCore * self = args->core;
  guint start_count;

  start_count = self->event_count;
  while (self->event_count == start_count)
    g_cond_wait (&self->event_cond, &self->mutex);

  return JSValueMakeUndefined (ctx);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  gsize ptr = 0;

  if (!_gumjs_args_parse (args, "|p~", &ptr))
    return NULL;

  return _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (ptr), args->core);
}

GUMJS_DEFINE_FINALIZER (gumjs_native_pointer_finalize)
{
  GumScriptNativePointer * self = JSObjectGetPrivate (object);

  g_slice_free1 (self->instance_size, self);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_is_null)
{
  return JSValueMakeBoolean (ctx,
      _gumjs_native_pointer_value (this_object) == NULL);
}

#define GUM_DEFINE_NATIVE_POINTER_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
  { \
    gpointer rhs_ptr; \
    gsize lhs, rhs; \
    gpointer result; \
    \
    if (!_gumjs_args_parse (args, "p~", &rhs_ptr)) \
      return NULL; \
    \
    lhs = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (this_object)); \
    rhs = GPOINTER_TO_SIZE (rhs_ptr); \
    \
    result = GSIZE_TO_POINTER (lhs op rhs); \
    \
    return _gumjs_native_pointer_new (ctx, result, args->core); \
  }

GUM_DEFINE_NATIVE_POINTER_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (xor, ^)

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_compare)
{
  gpointer rhs_ptr;
  gsize lhs, rhs;
  gint result;

  if (!_gumjs_args_parse (args, "p~", &rhs_ptr))
    return NULL;

  lhs = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (this_object));
  rhs = GPOINTER_TO_SIZE (rhs_ptr);

  result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  return JSValueMakeNumber (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_int32)
{
  gint32 result;

  result = (gint32)
      GPOINTER_TO_SIZE (_gumjs_native_pointer_value (this_object));

  return JSValueMakeNumber (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_string)
{
  gint radix = -1;
  gboolean radix_specified;
  gsize ptr;
  gchar str[32];

  if (!_gumjs_args_parse (args, "|u", &radix))
    return NULL;
  radix_specified = radix != -1;
  if (!radix_specified)
    radix = 16;
  else if (radix != 10 && radix != 16)
    goto unsupported_radix;

  ptr = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (this_object));

  if (radix == 10)
  {
    sprintf (str, "%" G_GSIZE_MODIFIER "u", ptr);
  }
  else
  {
    if (radix_specified)
      sprintf (str, "%" G_GSIZE_MODIFIER "x", ptr);
    else
      sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);
  }

  return _gumjs_string_to_value (ctx, str);

unsupported_radix:
  {
    _gumjs_throw (ctx, exception, "unsupported radix");
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_json)
{
  gsize ptr;
  gchar str[32];

  ptr = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (this_object));

  sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);

  return _gumjs_string_to_value (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_match_pattern)
{
  gsize ptr;
  gchar str[24];
  gint src, dst;
  const gint num_bits = GLIB_SIZEOF_VOID_P * 8;
  const gchar nibble_to_char[] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'
  };

  ptr = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (this_object));

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  for (src = 0, dst = 0; src != num_bits; src += 8)
#else
  for (src = num_bits - 8, dst = 0; src >= 0; src -= 8)
#endif
  {
    if (dst != 0)
      str[dst++] = ' ';
    str[dst++] = nibble_to_char[(ptr >> (src + 4)) & 0xf];
    str[dst++] = nibble_to_char[(ptr >> (src + 0)) & 0xf];
  }
  str[dst] = '\0';

  return _gumjs_string_to_value (ctx, str);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  JSObjectRef result = NULL;
  GumScriptCore * core = args->core;
  GumScriptNativeFunction * func;
  GumScriptNativePointer * ptr;
  JSValueRef rtype_value;
  ffi_type * rtype;
  JSObjectRef atypes_array;
  guint nargs_fixed, nargs_total, length, i;
  gboolean is_variadic;
  gchar * abi_str = NULL;
  ffi_abi abi;

  func = g_slice_new0 (GumScriptNativeFunction);

  ptr = &func->parent;
  ptr->instance_size = sizeof (GumScriptNativeFunction);

  func->core = core;

  if (!_gumjs_args_parse (args, "pVA|s", &func->fn, &rtype_value, &atypes_array,
      &abi_str))
    goto error;

  ptr->value = func->fn;

  if (!gumjs_ffi_type_try_get (ctx, rtype_value, &rtype, &func->data,
      exception))
    goto error;

  if (!_gumjs_object_try_get_uint (ctx, atypes_array, "length", &length,
      exception))
    goto error;

  nargs_fixed = nargs_total = length;
  is_variadic = FALSE;
  func->atypes = g_new (ffi_type *, nargs_total);
  for (i = 0; i != nargs_total; i++)
  {
    JSValueRef atype_value;
    gchar * name;
    gboolean is_marker;

    atype_value = JSObjectGetPropertyAtIndex (ctx, atypes_array, i, exception);
    if (atype_value == NULL)
      goto error;

    if (_gumjs_string_try_get (ctx, atype_value, &name, NULL))
    {
      is_marker = strcmp (name, "...") == 0;
      g_free (name);
    }
    else
    {
      is_marker = FALSE;
    }

    if (is_marker)
    {
      if (is_variadic)
        goto unexpected_marker;

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else if (!gumjs_ffi_type_try_get (ctx, atype_value,
        &func->atypes[is_variadic ? i - 1 : i], &func->data, exception))
    {
      goto error;
    }
  }
  if (is_variadic)
    nargs_total--;

  if (abi_str != NULL)
  {
    if (!gumjs_ffi_abi_try_get (ctx, abi_str, &abi, exception))
      goto error;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, nargs_fixed, nargs_total, rtype,
        func->atypes) != FFI_OK)
      goto compilation_failed;
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, nargs_total, rtype,
        func->atypes) != FFI_OK)
      goto compilation_failed;
  }

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  result = JSObjectMake (ctx, core->native_function, func);
  goto beach;

unexpected_marker:
  {
    _gumjs_throw (ctx, exception, "only one variadic marker may be specified");
    goto error;
  }
compilation_failed:
  {
    _gumjs_throw (ctx, exception, "failed to compile function call interface");
    goto error;
  }
error:
  {
    gum_script_native_function_finalize (func);
    g_slice_free (GumScriptNativeFunction, func);

    goto beach;
  }
beach:
  {
    g_free (abi_str);

    return result;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_native_function_finalize)
{
  GumScriptNativeFunction * self = JSObjectGetPrivate (object);

  gum_script_native_function_finalize (self);
}

static void
gum_script_native_function_finalize (GumScriptNativeFunction * func)
{
  while (func->data != NULL)
  {
    GSList * head = func->data;
    g_free (head->data);
    func->data = g_slist_delete_link (func->data, head);
  }
  g_free (func->atypes);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_invoke)
{
  GumScriptNativeFunction * self;
  GumScriptCore * core;
  gsize nargs;
  ffi_type * rtype;
  gsize rsize, ralign;
  GumFFIValue * rvalue;
  void ** avalue;
  guint8 * avalues;
  GumScriptYield yield;
  GumExceptorScope scope;
  JSValueRef result;

  self = JSObjectGetPrivate (function);
  core = self->core;
  nargs = self->cif.nargs;
  rtype = self->cif.rtype;

  if (args->count != nargs)
    goto bad_argument_count;

  rsize = MAX (rtype->size, sizeof (gsize));
  ralign = MAX (rtype->alignment, sizeof (gsize));
  rvalue = g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  if (nargs > 0)
  {
    gsize arglist_alignment, offset;

    avalue = g_alloca (nargs * sizeof (void *));

    arglist_alignment = self->cif.arg_types[0]->alignment;
    avalues = g_alloca (self->arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, self->arglist_size);

    offset = 0;
    for (gsize i = 0; i != nargs; i++)
    {
      ffi_type * t;
      GumFFIValue * v;

      t = self->cif.arg_types[i];
      offset = GUM_ALIGN_SIZE (offset, t->alignment);
      v = (GumFFIValue *) (avalues + offset);

      if (!gumjs_value_to_ffi_type (ctx, args->values[i], t, args->core,
          v, exception))
        goto error;
      avalue[i] = v;

      offset += t->size;
    }
  }
  else
  {
    avalue = NULL;
  }

  _gum_script_yield_begin (&yield, core);

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    ffi_call (&self->cif, FFI_FN (self->fn), rvalue, avalue);
  }

  _gum_script_yield_end (&yield);

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    _gumjs_throw_native (ctx, exception, &scope.exception, core);
    goto error;
  }

  if (rtype != &ffi_type_void)
  {
    if (!gumjs_value_from_ffi_type (ctx, rvalue, rtype, core, &result,
        exception))
      goto error;
  }
  else
  {
    result = JSValueMakeUndefined (ctx);
  }

  return result;

bad_argument_count:
  {
    _gumjs_throw (ctx, exception, "bad argument count");
    goto error;
  }
error:
  {
    return NULL;
  }
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_callback_construct)
{
  JSObjectRef result = NULL;
  GumScriptCore * core = args->core;
  GumScriptNativeCallback * callback;
  GumScriptNativePointer * ptr;
  JSValueRef rtype_value;
  ffi_type * rtype;
  JSObjectRef atypes_array;
  guint nargs, i;
  gchar * abi_str = NULL;
  ffi_abi abi;

  callback = g_slice_new0 (GumScriptNativeCallback);

  ptr = &callback->parent;
  ptr->instance_size = sizeof (GumScriptNativeCallback);

  callback->core = core;

  if (!_gumjs_args_parse (args, "FVA|s", &callback->func, &rtype_value,
      &atypes_array, &abi_str))
    goto error;

  if (!gumjs_ffi_type_try_get (ctx, rtype_value, &rtype, &callback->data,
      exception))
    goto error;

  if (!_gumjs_object_try_get_uint (ctx, atypes_array, "length", &nargs,
      exception))
    goto error;

  callback->atypes = g_new (ffi_type *, nargs);
  for (i = 0; i != nargs; i++)
  {
    JSValueRef atype_value;

    atype_value = JSObjectGetPropertyAtIndex (ctx, atypes_array, i, exception);
    if (atype_value == NULL)
      goto error;

    if (!gumjs_ffi_type_try_get (ctx, atype_value, &callback->atypes[i],
        &callback->data, exception))
      goto error;
  }

  if (abi_str != NULL)
  {
    if (!gumjs_ffi_abi_try_get (ctx, abi_str, &abi, exception))
      goto error;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  callback->closure = ffi_closure_alloc (sizeof (ffi_closure), &ptr->value);
  if (callback->closure == NULL)
    goto alloc_failed;

  if (ffi_prep_cif (&callback->cif, abi, nargs, rtype,
      callback->atypes) != FFI_OK)
    goto compilation_failed;

  if (ffi_prep_closure_loc (callback->closure, &callback->cif,
      gum_script_native_callback_invoke, callback, ptr->value) != FFI_OK)
    goto prepare_failed;

  result = JSObjectMake (ctx, core->native_callback, callback);
  _gumjs_object_set (ctx, result, "$func", callback->func);

  goto beach;

alloc_failed:
  {
    _gumjs_throw (ctx, exception, "failed to allocate closure");
    goto error;
  }
compilation_failed:
  {
    _gumjs_throw (ctx, exception, "failed to compile function call interface");
    goto error;
  }
prepare_failed:
  {
    _gumjs_throw (ctx, exception, "failed to prepare closure");
    goto error;
  }
error:
  {
    gum_script_native_callback_finalize (callback);
    g_slice_free (GumScriptNativeCallback, callback);

    goto beach;
  }
beach:
  {
    g_free (abi_str);

    return result;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_native_callback_finalize)
{
  GumScriptNativeCallback * self = JSObjectGetPrivate (object);

  gum_script_native_callback_finalize (self);
}

static void
gum_script_native_callback_finalize (GumScriptNativeCallback * callback)
{
  ffi_closure_free (callback->closure);

  while (callback->data != NULL)
  {
    GSList * head = callback->data;
    g_free (head->data);
    callback->data = g_slist_delete_link (callback->data, head);
  }
  g_free (callback->atypes);
}

static void
gum_script_native_callback_invoke (ffi_cif * cif,
                                   void * return_value,
                                   void ** args,
                                   void * user_data)
{
  GumScriptNativeCallback * self = user_data;
  GumScriptCore * core = self->core;
  GumScriptScope scope;
  JSContextRef ctx = core->ctx;
  ffi_type * rtype = cif->rtype;
  GumFFIValue * retval = return_value;
  JSValueRef * argv;
  guint i;
  JSValueRef result;

  _gum_script_scope_enter (&scope, core);

  if (rtype != &ffi_type_void)
  {
    /*
     * Ensure:
     * - high bits of values smaller than a pointer are cleared to zero
     * - we return something predictable in case of a JS exception
     */
    retval->v_pointer = NULL;
  }

  argv = g_alloca (cif->nargs * sizeof (JSValueRef));
  for (i = 0; i != cif->nargs; i++)
  {
    if (!gumjs_value_from_ffi_type (ctx, args[i], cif->arg_types[i], core,
        &argv[i], &scope.exception))
      goto beach;
  }

  result = JSObjectCallAsFunction (ctx, self->func, NULL, cif->nargs, argv,
      &scope.exception);
  if (cif->rtype != &ffi_type_void && result != NULL)
  {
    gumjs_value_to_ffi_type (ctx, result, cif->rtype, core, retval,
        &scope.exception);
  }

beach:
  _gum_script_scope_leave (&scope);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cpu_context_construct)
{
  _gumjs_throw (ctx, exception, "invalid argument");
  return NULL;
}

GUMJS_DEFINE_FINALIZER (gumjs_cpu_context_finalize)
{
  GumScriptCpuContext * self = JSObjectGetPrivate (object);

  g_slice_free (GumScriptCpuContext, self);
}

static bool
gumjs_cpu_context_set_register (GumScriptCpuContext * self,
                                JSContextRef ctx,
                                const GumScriptArgs * args,
                                gsize * reg,
                                JSValueRef * exception)
{
  gpointer value;

  if (self->access == GUM_CPU_CONTEXT_READONLY)
    goto invalid_operation;

  if (!_gumjs_args_parse (args, "p~", &value))
    return false;

  *reg = GPOINTER_TO_SIZE (value);
  return true;

invalid_operation:
  {
    _gumjs_throw (ctx, exception, "invalid operation");
    return false;
  }
}

static void
gum_clear_weak_ref_entry (guint id,
                          GumScriptWeakRef * ref)
{
  (void) id;

  gum_script_weak_ref_clear (ref);
}

static GumScriptWeakRef *
gum_script_weak_ref_new (guint id,
                         JSValueRef target,
                         JSObjectRef callback,
                         GumScriptCore * core)
{
  JSContextRef ctx = core->ctx;
  GumScriptWeakRef * ref;

  ref = g_slice_new (GumScriptWeakRef);
  ref->id = id;
  ref->target = _gumjs_weak_ref_new (ctx, target,
      (GumScriptWeakNotify) gum_script_weak_ref_on_weak_notify, ref, NULL);
  JSValueProtect (ctx, callback);
  ref->callback = callback;
  ref->core = core;

  return ref;
}

static void
gum_script_weak_ref_clear (GumScriptWeakRef * ref)
{
  g_clear_pointer (&ref->target, _gumjs_weak_ref_free);
}

static void
gum_script_weak_ref_free (GumScriptWeakRef * ref)
{
  GumScriptCore * core = ref->core;
  JSContextRef ctx = core->ctx;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);

  gum_script_weak_ref_clear (ref);

  JSObjectCallAsFunction (ctx, ref->callback, NULL, 0, NULL, &scope.exception);
  JSValueUnprotect (ctx, ref->callback);
  _gum_script_scope_flush (&scope);

  g_slice_free (GumScriptWeakRef, ref);
}

static void
gum_script_weak_ref_on_weak_notify (GumScriptWeakRef * self)
{
  g_hash_table_remove (self->core->weak_refs, GUINT_TO_POINTER (self->id));
}

static JSValueRef
gum_script_core_schedule_callback (GumScriptCore * self,
                                   const GumScriptArgs * args,
                                   gboolean repeat)
{
  JSObjectRef func;
  guint delay, id;
  GSource * source;
  GumScriptScheduledCallback * callback;

  if (!_gumjs_args_parse (args, "Fu", &func, &delay))
    return NULL;

  id = ++self->last_callback_id;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new (delay);

  callback = gum_scheduled_callback_new (id, func, repeat, source, self);
  g_source_set_callback (source, gum_scheduled_callback_invoke, callback,
      (GDestroyNotify) gum_scheduled_callback_free);
  gum_script_core_add_scheduled_callback (self, callback);

  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));

  return JSValueMakeNumber (args->ctx, id);
}

static void
gum_script_core_add_scheduled_callback (GumScriptCore * self,
                                        GumScriptScheduledCallback * cb)
{
  self->scheduled_callbacks =
      g_slist_prepend (self->scheduled_callbacks, cb);
}

static void
gum_script_core_remove_scheduled_callback (GumScriptCore * self,
                                           GumScriptScheduledCallback * cb)
{
  self->scheduled_callbacks =
      g_slist_remove (self->scheduled_callbacks, cb);
}

static GumScriptScheduledCallback *
gum_scheduled_callback_new (guint id,
                            JSObjectRef func,
                            gboolean repeat,
                            GSource * source,
                            GumScriptCore * core)
{
  GumScriptScheduledCallback * callback;

  callback = g_slice_new (GumScriptScheduledCallback);
  callback->id = id;
  JSValueProtect (core->ctx, func);
  callback->func = func;
  callback->repeat = repeat;
  callback->source = source;
  callback->core = core;

  return callback;
}

static void
gum_scheduled_callback_free (GumScriptScheduledCallback * callback)
{
  JSValueUnprotect (callback->core->ctx, callback->func);

  g_slice_free (GumScriptScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (gpointer user_data)
{
  GumScriptScheduledCallback * self = user_data;
  GumScriptCore * core = self->core;
  GumScriptScope scope;

  _gum_script_scope_enter (&scope, self->core);
  JSObjectCallAsFunction (core->ctx, self->func, NULL, 0, NULL,
      &scope.exception);
  _gum_script_scope_leave (&scope);

  if (!self->repeat)
    gum_script_core_remove_scheduled_callback (core, self);

  return self->repeat;
}

static GumScriptExceptionSink *
gum_script_exception_sink_new (JSContextRef ctx,
                               JSObjectRef callback)
{
  GumScriptExceptionSink * sink;

  sink = g_slice_new (GumScriptExceptionSink);
  JSValueProtect (ctx, callback);
  sink->callback = callback;
  sink->ctx = ctx;

  return sink;
}

static void
gum_script_exception_sink_free (GumScriptExceptionSink * sink)
{
  JSValueUnprotect (sink->ctx, sink->callback);

  g_slice_free (GumScriptExceptionSink, sink);
}

static void
gum_script_exception_sink_handle_exception (GumScriptExceptionSink * self,
                                            JSValueRef exception)
{
  JSObjectCallAsFunction (self->ctx, self->callback, NULL, 1, &exception, NULL);
}

static GumScriptMessageSink *
gum_script_message_sink_new (JSContextRef ctx,
                             JSObjectRef callback)
{
  GumScriptMessageSink * sink;

  sink = g_slice_new (GumScriptMessageSink);
  JSValueProtect (ctx, callback);
  sink->callback = callback;
  sink->ctx = ctx;

  return sink;
}

static void
gum_script_message_sink_free (GumScriptMessageSink * sink)
{
  JSValueUnprotect (sink->ctx, sink->callback);

  g_slice_free (GumScriptMessageSink, sink);
}

static void
gum_script_message_sink_handle_message (GumScriptMessageSink * self,
                                        const gchar * message,
                                        JSValueRef * exception)
{
  JSValueRef message_value;

  message_value = _gumjs_string_to_value (self->ctx, message);
  JSObjectCallAsFunction (self->ctx, self->callback, NULL, 1, &message_value,
      exception);
}

static const GumFFITypeMapping gum_ffi_type_mappings[] =
{
  { "void", &ffi_type_void },
  { "pointer", &ffi_type_pointer },
  { "int", &ffi_type_sint },
  { "uint", &ffi_type_uint },
  { "long", &ffi_type_slong },
  { "ulong", &ffi_type_ulong },
  { "char", &ffi_type_schar },
  { "uchar", &ffi_type_uchar },
  { "float", &ffi_type_float },
  { "double", &ffi_type_double },
  { "int8", &ffi_type_sint8 },
  { "uint8", &ffi_type_uint8 },
  { "int16", &ffi_type_sint16 },
  { "uint16", &ffi_type_uint16 },
  { "int32", &ffi_type_sint32 },
  { "uint32", &ffi_type_uint32 },
  { "int64", &ffi_type_sint64 },
  { "uint64", &ffi_type_uint64 },
  { "bool", &ffi_type_schar }
};

static const GumFFIABIMapping gum_ffi_abi_mappings[] =
{
  { "default", FFI_DEFAULT_ABI },
#if defined (X86_WIN64)
  { "win64", FFI_WIN64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 8
  { "unix64", FFI_UNIX64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 4
  { "sysv", FFI_SYSV },
  { "stdcall", FFI_STDCALL },
  { "thiscall", FFI_THISCALL },
  { "fastcall", FFI_FASTCALL },
# if defined (X86_WIN32)
  { "mscdecl", FFI_MS_CDECL },
# endif
#elif defined (ARM)
  { "sysv", FFI_SYSV },
# if GLIB_SIZEOF_VOID_P == 4
  { "vfp", FFI_VFP },
# endif
#endif
};

static gboolean
gumjs_ffi_type_try_get (JSContextRef ctx,
                        JSValueRef value,
                        ffi_type ** type,
                        GSList ** data,
                        JSValueRef * exception)
{
  gboolean success = FALSE;
  gchar * name = NULL;
  guint i;

  if (_gumjs_string_try_get (ctx, value, &name, NULL))
  {
    for (i = 0; i != G_N_ELEMENTS (gum_ffi_type_mappings); i++)
    {
      const GumFFITypeMapping * m = &gum_ffi_type_mappings[i];
      if (strcmp (name, m->name) == 0)
      {
        *type = m->type;
        success = TRUE;
        goto beach;
      }
    }
  }
  else if (JSValueIsArray (ctx, value))
  {
    JSObjectRef fields_value;
    guint length;
    ffi_type ** fields, * struct_type;

    fields_value = (JSObjectRef) value;

    if (!_gumjs_object_try_get_uint (ctx, fields_value, "length", &length,
        exception))
      return FALSE;

    fields = g_new (ffi_type *, length + 1);
    *data = g_slist_prepend (*data, fields);

    for (i = 0; i != length; i++)
    {
      JSValueRef field_value;

      field_value = JSObjectGetPropertyAtIndex (ctx, fields_value, i,
          exception);
      if (field_value == NULL)
        goto beach;

      if (!gumjs_ffi_type_try_get (ctx, field_value, &fields[i], data,
          exception))
        goto beach;
    }

    fields[length] = NULL;

    struct_type = g_new0 (ffi_type, 1);
    struct_type->type = FFI_TYPE_STRUCT;
    struct_type->elements = fields;
    *data = g_slist_prepend (*data, struct_type);

    *type = struct_type;
    success = TRUE;
    goto beach;
  }

beach:
  g_free (name);

  return success;
}

static gboolean
gumjs_ffi_abi_try_get (JSContextRef ctx,
                       const gchar * name,
                       ffi_abi * abi,
                       JSValueRef * exception)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_ffi_abi_mappings); i++)
  {
    const GumFFIABIMapping * m = &gum_ffi_abi_mappings[i];

    if (strcmp (name, m->name) == 0)
    {
      *abi = m->abi;
      return TRUE;
    }
  }

  _gumjs_throw (ctx, exception, "invalid abi specified");
  return FALSE;
}

static gboolean
gumjs_value_to_ffi_type (JSContextRef ctx,
                         JSValueRef svalue,
                         const ffi_type * type,
                         GumScriptCore * core,
                         GumFFIValue * value,
                         JSValueRef * exception)
{
  gint i;
  guint u;
  gdouble n;

  if (type == &ffi_type_void)
  {
    value->v_pointer = NULL;
  }
  else if (type == &ffi_type_pointer)
  {
    if (!_gumjs_native_pointer_try_get (ctx, svalue, core, &value->v_pointer,
        exception))
      return FALSE;
  }
  else if (type == &ffi_type_sint)
  {
    if (!_gumjs_int_try_get (ctx, svalue, &i, exception))
      return FALSE;
    value->v_sint = i;
  }
  else if (type == &ffi_type_uint)
  {
    if (!_gumjs_uint_try_get (ctx, svalue, &u, exception))
      return FALSE;
    value->v_uint = u;
  }
  else if (type == &ffi_type_slong)
  {
    if (!_gumjs_int_try_get (ctx, svalue, &i, exception))
      return FALSE;
    value->v_slong = i;
  }
  else if (type == &ffi_type_ulong)
  {
    if (!_gumjs_uint_try_get (ctx, svalue, &u, exception))
      return FALSE;
    value->v_ulong = u;
  }
  else if (type == &ffi_type_schar)
  {
    if (!_gumjs_int_try_get (ctx, svalue, &i, exception))
      return FALSE;
    value->v_schar = i;
  }
  else if (type == &ffi_type_uchar)
  {
    if (!_gumjs_uint_try_get (ctx, svalue, &u, exception))
      return FALSE;
    value->v_uchar = u;
  }
  else if (type == &ffi_type_float)
  {
    if (!_gumjs_number_try_get (ctx, svalue, &n, exception))
      return FALSE;
    value->v_float = n;
  }
  else if (type == &ffi_type_double)
  {
    if (!_gumjs_number_try_get (ctx, svalue, &n, exception))
      return FALSE;
    value->v_double = n;
  }
  else if (type == &ffi_type_sint8)
  {
    if (!_gumjs_int_try_get (ctx, svalue, &i, exception))
      return FALSE;
    value->v_sint8 = i;
  }
  else if (type == &ffi_type_uint8)
  {
    if (!_gumjs_uint_try_get (ctx, svalue, &u, exception))
      return FALSE;
    value->v_uint8 = u;
  }
  else if (type == &ffi_type_sint16)
  {
    if (!_gumjs_int_try_get (ctx, svalue, &i, exception))
      return FALSE;
    value->v_sint16 = i;
  }
  else if (type == &ffi_type_uint16)
  {
    if (!_gumjs_uint_try_get (ctx, svalue, &u, exception))
      return FALSE;
    value->v_uint16 = u;
  }
  else if (type == &ffi_type_sint32)
  {
    if (!_gumjs_int_try_get (ctx, svalue, &i, exception))
      return FALSE;
    value->v_sint32 = i;
  }
  else if (type == &ffi_type_uint32)
  {
    if (!_gumjs_uint_try_get (ctx, svalue, &u, exception))
      return FALSE;
    value->v_uint32 = u;
  }
  else if (type == &ffi_type_sint64)
  {
    if (!_gumjs_int_try_get (ctx, svalue, &i, exception))
      return FALSE;
    value->v_sint64 = i;
  }
  else if (type == &ffi_type_uint64)
  {
    if (!_gumjs_uint_try_get (ctx, svalue, &u, exception))
      return FALSE;
    value->v_uint64 = u;
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    JSObjectRef field_svalues;
    guint provided_length, length, i;
    guint8 * field_values;
    gsize offset;

    if (!JSValueIsArray (ctx, svalue))
    {
      _gumjs_throw (ctx, exception, "expected array with fields");
      return FALSE;
    }
    field_svalues = (JSObjectRef) svalue;

    if (!_gumjs_object_try_get_uint (ctx, field_svalues, "length",
        &provided_length, exception))
      return FALSE;
    length = 0;
    for (t = field_types; *t != NULL; t++)
      length++;
    if (provided_length != length)
    {
      _gumjs_throw (ctx, exception, "provided array length does not match "
          "number of fields");
      return FALSE;
    }

    field_values = (guint8 *) value;
    offset = 0;
    for (i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];
      GumFFIValue * field_value;
      JSValueRef field_svalue;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      field_value = (GumFFIValue *) (field_values + offset);
      field_svalue = JSObjectGetPropertyAtIndex (ctx, field_svalues, i,
          exception);
      if (field_svalue == NULL)
        return FALSE;

      if (!gumjs_value_to_ffi_type (ctx, field_svalue, field_type, core,
          field_value, exception))
      {
        return FALSE;
      }

      offset += field_type->size;
    }
  }
  else
  {
    goto unsupported_type;
  }

  return TRUE;

unsupported_type:
  {
    _gumjs_throw (ctx, exception, "unsupported type");
    return FALSE;
  }
}

static gboolean
gumjs_value_from_ffi_type (JSContextRef ctx,
                           const GumFFIValue * value,
                           const ffi_type * type,
                           GumScriptCore * core,
                           JSValueRef * svalue,
                           JSValueRef * exception)
{
  if (type == &ffi_type_void)
  {
    *svalue = JSValueMakeUndefined (ctx);
  }
  else if (type == &ffi_type_pointer)
  {
    *svalue = _gumjs_native_pointer_new (ctx, value->v_pointer, core);
  }
  else if (type == &ffi_type_sint)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_sint);
  }
  else if (type == &ffi_type_uint)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_uint);
  }
  else if (type == &ffi_type_slong)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_slong);
  }
  else if (type == &ffi_type_ulong)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_ulong);
  }
  else if (type == &ffi_type_schar)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_schar);
  }
  else if (type == &ffi_type_uchar)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_uchar);
  }
  else if (type == &ffi_type_float)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_float);
  }
  else if (type == &ffi_type_double)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_double);
  }
  else if (type == &ffi_type_sint8)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_sint8);
  }
  else if (type == &ffi_type_uint8)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_uint8);
  }
  else if (type == &ffi_type_sint16)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_sint16);
  }
  else if (type == &ffi_type_uint16)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_uint16);
  }
  else if (type == &ffi_type_sint32)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_sint32);
  }
  else if (type == &ffi_type_uint32)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_uint32);
  }
  else if (type == &ffi_type_sint64)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_sint64);
  }
  else if (type == &ffi_type_uint64)
  {
    *svalue = JSValueMakeNumber (ctx, value->v_uint64);
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    guint length, i;
    JSValueRef * field_svalues;
    const guint8 * field_values;
    gsize offset;

    length = 0;
    for (t = field_types; *t != NULL; t++)
      length++;

    field_svalues = g_alloca (length * sizeof (JSValueRef));
    field_values = (const guint8 *) value;
    offset = 0;
    for (i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];
      const GumFFIValue * field_value;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);
      field_value = (const GumFFIValue *) (field_values + offset);

      if (!gumjs_value_from_ffi_type (ctx, field_value, field_type, core,
          &field_svalues[i], exception))
        goto error;

      offset += field_type->size;
    }

    *svalue = JSObjectMakeArray (ctx, length, field_svalues, exception);
    if (*svalue == NULL)
      goto error;
  }
  else
  {
    goto unsupported_type;
  }

  return TRUE;

unsupported_type:
  {
    _gumjs_throw (ctx, exception, "unsupported type");
    goto error;
  }
error:
  {
    return FALSE;
  }
}
