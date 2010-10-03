#include "gumdefs.h"

#include <glib.h>

gpointer GUM_NOINLINE
gum_test_target_function (GString * str)
{
  if (str != NULL)
    g_string_append_c (str, '|');
  else
    g_usleep (G_USEC_PER_SEC / 100);

  return NULL;
}

static guint counter = 0;

gpointer GUM_NOINLINE
gum_test_target_nop_function_a (gpointer data)
{
  (void) data;

  counter++;

  return GSIZE_TO_POINTER (0x1337);
}

gpointer GUM_NOINLINE
gum_test_target_nop_function_b (gpointer data)
{
  (void) data;

  counter += 2;

  return GSIZE_TO_POINTER (2);
}

gpointer GUM_NOINLINE
gum_test_target_nop_function_c (gpointer data)
{
  counter += 3;

  gum_test_target_nop_function_a (data);

  return GSIZE_TO_POINTER (3);
}
