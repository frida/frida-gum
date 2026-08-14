/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumpharo.h"
#include "testutil.h"

#include <gum/gum.h>
#include <gum/gummemory.h>

#define TESTCASE(NAME) \
    void test_gumpharo_ ## NAME (TestGumPharoFixture * fixture, \
        gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Bindings/Pharo", test_gumpharo, NAME, \
        TestGumPharoFixture)

#define GUM_PHARO_MAX_STACK_DEPTH 8

typedef struct _TestGumPharoFixture TestGumPharoFixture;
typedef sqInt (* TestGumPharoPrimitive) (void);

struct _TestGumPharoFixture
{
  sqInt result;
  gboolean returned_receiver;
  sqInt signalled_semaphore;
  sqInt failure;
};

typedef struct _TestGumPharoOop TestGumPharoOop;

struct _TestGumPharoOop
{
  gsize size;
  gchar bytes[];
};

extern void * GumPlugin_exports[][3];

static TestGumPharoFixture * current_fixture;
static sqInt current_stack[GUM_PHARO_MAX_STACK_DEPTH];
static sqInt current_stack_depth;

static void test_gumpharo_fixture_setup (TestGumPharoFixture * fixture,
    gconstpointer data);
static void test_gumpharo_fixture_teardown (TestGumPharoFixture * fixture,
    gconstpointer data);

static TestGumPharoPrimitive find_primitive (const gchar * name);
static sqInt string_oop (const gchar * text);
static sqInt byte_array_oop (gconstpointer data, gsize size);
static sqInt nil_oop (void);
static const gchar * payload_of (sqInt message);
static sqInt invoke_primitive (const gchar * name, guint n_arguments, ...);

static sqInt test_minor_version (void);
static sqInt test_major_version (void);
static sqInt test_ancient_major_version (void);
static sqInt test_stack_value (sqInt offset);
static sqInt test_boolean_value_of (sqInt object);
static sqInt test_positive_64bit_integer_for (usqLong value);
static usqLong test_positive_64bit_value_of (sqInt oop);
static sqInt test_method_return_bool (sqInt value);
static sqInt test_method_return_value (sqInt oop);
static sqInt test_method_return_receiver (void);
static sqInt test_is_bytes (sqInt oop);
static sqInt test_byte_size_of (sqInt oop);
static void * test_first_indexable_field (sqInt oop);
static sqInt test_instantiate_class_indexable_size (sqInt class_pointer,
    sqInt size);
static sqInt test_class_string (void);
static sqInt test_class_byte_array (void);
static sqInt test_nil_object (void);
static sqInt test_signal_semaphore_with_index (sqInt index);
static sqInt test_primitive_fail_for (sqInt reason);

static GPtrArray * test_oops;

static struct VirtualMachine test_interpreter;

static void
test_gumpharo_fixture_setup (TestGumPharoFixture * fixture,
                             gconstpointer data)
{
  test_interpreter.minorVersion = test_minor_version;
  test_interpreter.majorVersion = test_major_version;
  test_interpreter.stackValue = test_stack_value;
  test_interpreter.booleanValueOf = test_boolean_value_of;
  test_interpreter.positive64BitIntegerFor = test_positive_64bit_integer_for;
  test_interpreter.positive64BitValueOf = test_positive_64bit_value_of;
  test_interpreter.methodReturnBool = test_method_return_bool;
  test_interpreter.methodReturnValue = test_method_return_value;
  test_interpreter.methodReturnReceiver = test_method_return_receiver;

  test_interpreter.isBytes = test_is_bytes;
  test_interpreter.byteSizeOf = test_byte_size_of;
  test_interpreter.firstIndexableField = test_first_indexable_field;
  test_interpreter.instantiateClassindexableSize =
      test_instantiate_class_indexable_size;
  test_interpreter.classString = test_class_string;
  test_interpreter.classByteArray = test_class_byte_array;
  test_interpreter.nilObject = test_nil_object;
  test_interpreter.signalSemaphoreWithIndex = test_signal_semaphore_with_index;
  test_interpreter.primitiveFailFor = test_primitive_fail_for;

  gum_pharo_set_interpreter (&test_interpreter);

  current_fixture = fixture;
  current_stack_depth = 0;
  test_oops = g_ptr_array_new_with_free_func (g_free);
}

static void
test_gumpharo_fixture_teardown (TestGumPharoFixture * fixture,
                                gconstpointer data)
{
  g_ptr_array_unref (test_oops);
  test_oops = NULL;
  current_fixture = NULL;
}

static sqInt
string_oop (const gchar * text)
{
  return byte_array_oop (text, strlen (text));
}

static sqInt
byte_array_oop (gconstpointer data,
                gsize size)
{
  TestGumPharoOop * oop;

  oop = g_malloc0 (sizeof (TestGumPharoOop) + size + 1);
  oop->size = size;
  memcpy (oop->bytes, data, size);
  g_ptr_array_add (test_oops, oop);

  return (sqInt) oop;
}

static sqInt
nil_oop (void)
{
  return 0;
}

static const gchar *
payload_of (sqInt message)
{
  return ((TestGumPharoOop *) invoke_primitive ("primGumPharoMessagePayload",
      1, message))->bytes;
}

static sqInt
test_is_bytes (sqInt oop)
{
  guint i;

  for (i = 0; i != test_oops->len; i++)
  {
    if ((sqInt) g_ptr_array_index (test_oops, i) == oop)
      return 1;
  }

  return 0;
}

static sqInt
test_byte_size_of (sqInt oop)
{
  return ((TestGumPharoOop *) oop)->size;
}

static void *
test_first_indexable_field (sqInt oop)
{
  return ((TestGumPharoOop *) oop)->bytes;
}

static sqInt
test_instantiate_class_indexable_size (sqInt class_pointer,
                                       sqInt size)
{
  TestGumPharoOop * oop;

  oop = g_malloc0 (sizeof (TestGumPharoOop) + size + 1);
  oop->size = size;
  g_ptr_array_add (test_oops, oop);

  return (sqInt) oop;
}

static sqInt
test_class_string (void)
{
  return 1;
}

static sqInt
test_class_byte_array (void)
{
  return 2;
}

static sqInt
test_nil_object (void)
{
  return 0;
}

static sqInt
test_signal_semaphore_with_index (sqInt index)
{
  current_fixture->signalled_semaphore = index;

  return 1;
}

static sqInt
test_primitive_fail_for (sqInt reason)
{
  current_fixture->failure = reason;

  return 0;
}

static TestGumPharoPrimitive
find_primitive (const gchar * name)
{
  guint i;

  for (i = 0; GumPlugin_exports[i][0] != NULL; i++)
  {
    if (strcmp (GumPlugin_exports[i][1], name) == 0)
      return GumPlugin_exports[i][2];
  }

  return NULL;
}

static sqInt
invoke_primitive (const gchar * name,
                  guint n_arguments,
                  ...)
{
  TestGumPharoPrimitive primitive;
  va_list args;
  guint i;

  primitive = find_primitive (name);
  g_assert_nonnull (primitive);

  current_stack_depth = n_arguments;
  current_fixture->returned_receiver = FALSE;

  va_start (args, n_arguments);
  for (i = 0; i != n_arguments; i++)
    current_stack[n_arguments - 1 - i] = va_arg (args, sqInt);
  va_end (args);

  primitive ();

  return current_fixture->result;
}

static sqInt
test_minor_version (void)
{
  return VM_PROXY_MINOR;
}

static sqInt
test_major_version (void)
{
  return VM_PROXY_MAJOR;
}

static sqInt
test_ancient_major_version (void)
{
  return VM_PROXY_MAJOR - 1;
}

static sqInt
test_stack_value (sqInt offset)
{
  g_assert_cmpint (offset, <, current_stack_depth);

  return current_stack[offset];
}

static sqInt
test_boolean_value_of (sqInt object)
{
  return object;
}

static sqInt
test_positive_64bit_integer_for (usqLong value)
{
  return (sqInt) value;
}

static usqLong
test_positive_64bit_value_of (sqInt oop)
{
  return (usqLong) oop;
}

static sqInt
test_method_return_bool (sqInt value)
{
  current_fixture->result = value;

  return 0;
}

static sqInt
test_method_return_value (sqInt oop)
{
  current_fixture->result = oop;

  return 0;
}

static sqInt
test_method_return_receiver (void)
{
  current_fixture->returned_receiver = TRUE;

  return 0;
}
