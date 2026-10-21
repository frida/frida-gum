/*
 * Copyright (C) 2026 Thanos Petsas <thanpetsas@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <glib.h>

#define GUM_TEST_THROW_DEPTH 16

extern "C"
{
  gboolean gum_test_unwind_broker_throw_and_catch (gint value);
}

class GumTestUnwindCleanup
{
public:
  ~GumTestUnwindCleanup ()
  {
    g_atomic_int_inc (&count);
  }

  static gint count;
};

gint GumTestUnwindCleanup::count = 0;

static gint gum_test_unwind_broker_throw (guint depth, gint value)
    __attribute__ ((noinline));

extern "C"
{
  gboolean
  gum_test_unwind_broker_throw_and_catch (gint value)
  {
    try
    {
      gum_test_unwind_broker_throw (GUM_TEST_THROW_DEPTH, value);
    }
    catch (gint caught)
    {
      return caught == value;
    }

    return FALSE;
  }
}

static gint
gum_test_unwind_broker_throw (guint depth,
                              gint value)
{
  GumTestUnwindCleanup cleanup;

  if (depth == 0)
    throw value;

  return gum_test_unwind_broker_throw (depth - 1, value) + 1;
}
