#include "gumpharo.h"

#include <pharovm/staticPlugins.h>
#include <string.h>

STATIC_PLUGIN (GumPlugin)

static sqInt gum_pharo_new_string (const gchar * value, gsize size);

static struct VirtualMachine * gum_pharo_interpreter;

sqInt
gum_pharo_set_interpreter (struct VirtualMachine * interpreter)
{
  gum_pharo_interpreter = interpreter;

  return interpreter->majorVersion () == VM_PROXY_MAJOR &&
      interpreter->minorVersion () >= VM_PROXY_MINOR;
}

gpointer
gum_pharo_pointer_at (sqInt index)
{
  return GSIZE_TO_POINTER (gum_pharo_integer_at (index));
}

guint64
gum_pharo_integer_at (sqInt index)
{
  return gum_pharo_interpreter->positive64BitValueOf (
      gum_pharo_interpreter->stackValue (index));
}

gboolean
gum_pharo_boolean_at (sqInt index)
{
  return gum_pharo_interpreter->booleanValueOf (
      gum_pharo_interpreter->stackValue (index));
}

gconstpointer
gum_pharo_bytes_at (sqInt index,
                    gsize * size)
{
  sqInt oop;

  oop = gum_pharo_interpreter->stackValue (index);
  if (!gum_pharo_interpreter->isBytes (oop))
  {
    *size = 0;
    return NULL;
  }

  *size = gum_pharo_interpreter->byteSizeOf (oop);

  return gum_pharo_interpreter->firstIndexableField (oop);
}

gchar *
gum_pharo_string_at (sqInt index)
{
  gconstpointer bytes;
  gsize size;

  bytes = gum_pharo_bytes_at (index, &size);
  if (bytes == NULL)
    return NULL;

  return g_strndup (bytes, size);
}

void
gum_pharo_signal_semaphore (sqInt index)
{
  gum_pharo_interpreter->signalSemaphoreWithIndex (index);
}

sqInt
gum_pharo_return_pointer (gpointer value)
{
  return gum_pharo_return_integer (GPOINTER_TO_SIZE (value));
}

sqInt
gum_pharo_return_integer (guint64 value)
{
  return gum_pharo_interpreter->methodReturnValue (
      gum_pharo_interpreter->positive64BitIntegerFor (value));
}

sqInt
gum_pharo_return_boolean (gboolean value)
{
  return gum_pharo_interpreter->methodReturnBool (value);
}

static sqInt
gum_pharo_new_string (const gchar * value,
                      gsize size)
{
  sqInt oop;

  oop = gum_pharo_interpreter->instantiateClassindexableSize (
      gum_pharo_interpreter->classString (), size);
  memcpy (gum_pharo_interpreter->firstIndexableField (oop), value, size);

  return oop;
}

sqInt
gum_pharo_return_string (const gchar * value,
                         gsize size)
{
  return gum_pharo_interpreter->methodReturnValue (
      gum_pharo_new_string (value, size));
}

void
gum_pharo_array_new (gsize size)
{
  gum_pharo_interpreter->pushRemappableOop (
      gum_pharo_interpreter->instantiateClassindexableSize (
          gum_pharo_interpreter->classArray (), size));
}

void
gum_pharo_array_put_string (gsize index,
                            const gchar * value)
{
  sqInt string, array;

  string = gum_pharo_new_string (value, strlen (value));
  array = gum_pharo_interpreter->popRemappableOop ();
  gum_pharo_interpreter->storePointerofObjectwithValue (index, array, string);
  gum_pharo_interpreter->pushRemappableOop (array);
}

void
gum_pharo_array_put_utf8 (gsize index,
                          const gchar * value)
{
  sqInt oop, array;

  oop = (value != NULL)
      ? gum_pharo_new_string (value, strlen (value))
      : gum_pharo_interpreter->nilObject ();
  array = gum_pharo_interpreter->popRemappableOop ();
  gum_pharo_interpreter->storePointerofObjectwithValue (index, array, oop);
  gum_pharo_interpreter->pushRemappableOop (array);
}

void
gum_pharo_array_put_integer (gsize index,
                             guint64 value)
{
  sqInt number, array;

  number = gum_pharo_interpreter->positive64BitIntegerFor (value);
  array = gum_pharo_interpreter->popRemappableOop ();
  gum_pharo_interpreter->storePointerofObjectwithValue (index, array, number);
  gum_pharo_interpreter->pushRemappableOop (array);
}

void
gum_pharo_array_put_signed (gsize index,
                            gint64 value)
{
  sqInt number, array;

  number = gum_pharo_interpreter->signed64BitIntegerFor (value);
  array = gum_pharo_interpreter->popRemappableOop ();
  gum_pharo_interpreter->storePointerofObjectwithValue (index, array, number);
  gum_pharo_interpreter->pushRemappableOop (array);
}

sqInt
gum_pharo_array_return (void)
{
  return gum_pharo_interpreter->methodReturnValue (
      gum_pharo_interpreter->popRemappableOop ());
}


sqInt
gum_pharo_return_byte_array (gconstpointer value,
                             gsize size)
{
  sqInt oop;

  oop = gum_pharo_interpreter->instantiateClassindexableSize (
      gum_pharo_interpreter->classByteArray (), size);
  memcpy (gum_pharo_interpreter->firstIndexableField (oop), value, size);

  return gum_pharo_interpreter->methodReturnValue (oop);
}

sqInt
gum_pharo_return_utf8 (const gchar * value)
{
  if (value == NULL)
    return gum_pharo_return_nil ();

  return gum_pharo_return_string (value, strlen (value));
}

sqInt
gum_pharo_return_nil (void)
{
  return gum_pharo_interpreter->methodReturnValue (
      gum_pharo_interpreter->nilObject ());
}

sqInt
gum_pharo_fail_bad_argument (void)
{
  return gum_pharo_interpreter->primitiveFailFor (PrimErrBadArgument);
}

sqInt
gum_pharo_return_self (void)
{
  return gum_pharo_interpreter->methodReturnReceiver ();
}
