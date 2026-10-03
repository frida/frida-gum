/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumpp.hpp"

#include "testutil.h"

G_BEGIN_DECLS

#define TESTCASE(NAME) \
    void test_gumpp_interceptor_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Gum++/Interceptor", test_gumpp_interceptor, NAME)

TESTLIST_BEGIN (gumpp_interceptor)
  TESTENTRY (probe_listener_is_hit_until_detached)
TESTLIST_END ()

static gpointer gumpp_test_probe_target (GString * str);

class ProbeTestListener : public Gum::ProbeListener
{
public:
  virtual void on_hit (Gum::InvocationContext * context)
  {
    g_string_append_c (static_cast<GString *> (
        context->get_listener_function_data_ptr ()), '>');
  }
};

TESTCASE (probe_listener_is_hit_until_detached)
{
  Gum::RefPtr<Gum::Interceptor> interceptor (Gum::Interceptor_obtain ());

  ProbeTestListener listener;

  GString * output = g_string_new ("");
  interceptor->attach (reinterpret_cast<void *> (gumpp_test_probe_target),
      &listener, output);

  gumpp_test_probe_target (output);
  g_assert_cmpstr (output->str, ==, ">|");

  interceptor->detach (&listener);

  gumpp_test_probe_target (output);
  g_assert_cmpstr (output->str, ==, ">||");

  g_string_free (output, TRUE);
}

GUM_HOOK_TARGET static gpointer
gumpp_test_probe_target (GString * str)
{
  g_string_append_c (str, '|');

  return NULL;
}

G_END_DECLS
