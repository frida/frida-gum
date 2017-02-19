/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "testutil.h"

#include <dlfcn.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>

#define INTERCEPTOR_TESTCASE(NAME) \
    void test_interceptor_ ## NAME ( \
        TestInterceptorFixture * fixture, gconstpointer data)
#define INTERCEPTOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Interceptor/Android", \
        test_interceptor, NAME, TestInterceptorFixture)

typedef struct _TestInterceptorFixture     TestInterceptorFixture;
typedef struct _AndroidListenerContext      AndroidListenerContext;
typedef struct _AndroidListenerContextClass AndroidListenerContextClass;

struct _AndroidListenerContext
{
  GObject parent;

  TestInterceptorFixture * harness;
  gchar enter_char;
  gchar leave_char;
  GumThreadId last_thread_id;
  gsize last_seen_argument;
  gpointer last_return_value;
  GumCpuContext last_on_enter_cpu_context;
};

struct _AndroidListenerContextClass
{
  GObjectClass parent_class;
};

struct _TestInterceptorFixture
{
  GumInterceptor * interceptor;
  GString * result;
  AndroidListenerContext * listener_context[2];
};

static void android_listener_context_iface_init (gpointer g_iface,
    gpointer iface_data);

static void init_java_vm (JavaVM ** vm, JNIEnv ** env);
static guint get_system_api_level (void);

G_DEFINE_TYPE_EXTENDED (AndroidListenerContext,
                        android_listener_context,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            android_listener_context_iface_init));

static JavaVM * java_vm = NULL;
static JNIEnv * java_env = NULL;

static void
test_interceptor_fixture_setup (TestInterceptorFixture * fixture,
                                gconstpointer data)
{
  (void) data;

  fixture->interceptor = gum_interceptor_obtain ();
  fixture->result = g_string_sized_new (4096);
  memset (&fixture->listener_context, 0, sizeof (fixture->listener_context));

  if (java_vm == NULL)
  {
    init_java_vm (&java_vm, &java_env);
  }
}

static void
test_interceptor_fixture_teardown (TestInterceptorFixture * fixture,
                                   gconstpointer data)
{
  guint i;

  (void) data;

  for (i = 0; i < G_N_ELEMENTS (fixture->listener_context); i++)
  {
    AndroidListenerContext * ctx = fixture->listener_context[i];

    if (ctx != NULL)
    {
      gum_interceptor_detach_listener (fixture->interceptor,
          GUM_INVOCATION_LISTENER (ctx));
      g_object_unref (ctx);
    }
  }

  g_string_free (fixture->result, TRUE);
  g_object_unref (fixture->interceptor);
}

static GumAttachReturn
interceptor_fixture_try_attaching_listener (TestInterceptorFixture * h,
                                            guint listener_index,
                                            gpointer test_func,
                                            gchar enter_char,
                                            gchar leave_char)
{
  GumAttachReturn result;
  AndroidListenerContext * ctx;

  if (h->listener_context[listener_index] != NULL)
  {
    g_object_unref (h->listener_context[listener_index]);
    h->listener_context[listener_index] = NULL;
  }

  ctx = (AndroidListenerContext *) g_object_new (
      android_listener_context_get_type (), NULL);
  ctx->harness = h;
  ctx->enter_char = enter_char;
  ctx->leave_char = leave_char;

  result = gum_interceptor_attach_listener (h->interceptor, test_func,
      GUM_INVOCATION_LISTENER (ctx), NULL);
  if (result == GUM_ATTACH_OK)
  {
    h->listener_context[listener_index] = ctx;
  }
  else
  {
    g_object_unref (ctx);
  }

  return result;
}

static void
interceptor_fixture_attach_listener (TestInterceptorFixture * h,
                                     guint listener_index,
                                     gpointer test_func,
                                     gchar enter_char,
                                     gchar leave_char)
{
  g_assert_cmpint (interceptor_fixture_try_attaching_listener (h,
      listener_index, test_func, enter_char, leave_char), ==,
      GUM_ATTACH_OK);
}

static void
interceptor_fixture_detach_listener (TestInterceptorFixture * h,
                                     guint listener_index)
{
  gum_interceptor_detach_listener (h->interceptor,
    GUM_INVOCATION_LISTENER (h->listener_context[listener_index]));
}

static void
android_listener_context_on_enter (GumInvocationListener * listener,
                                   GumInvocationContext * context)
{
  AndroidListenerContext * self = (AndroidListenerContext *) listener;

  g_assert_cmpuint (gum_invocation_context_get_point_cut (context), ==,
      GUM_POINT_ENTER);

  g_string_append_c (self->harness->result, self->enter_char);

  self->last_seen_argument = (gsize)
      gum_invocation_context_get_nth_argument (context, 0);
  self->last_on_enter_cpu_context = *context->cpu_context;

  self->last_thread_id = gum_invocation_context_get_thread_id (context);
}

static void
android_listener_context_on_leave (GumInvocationListener * listener,
                                   GumInvocationContext * context)
{
  AndroidListenerContext * self = (AndroidListenerContext *) listener;

  g_assert_cmpuint (gum_invocation_context_get_point_cut (context), ==,
      GUM_POINT_LEAVE);

  g_string_append_c (self->harness->result, self->leave_char);

  self->last_return_value = gum_invocation_context_get_return_value (context);
}

static void
android_listener_context_class_init (AndroidListenerContextClass * klass)
{
  (void) klass;
}

static void
android_listener_context_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = android_listener_context_on_enter;
  iface->on_leave = android_listener_context_on_leave;
}

static void
android_listener_context_init (AndroidListenerContext * self)
{
  (void) self;
}

static void
init_java_vm (JavaVM ** vm,
              JNIEnv ** env)
{
  void * vm_module, * runtime_module;
  jint (* create_java_vm) (JavaVM ** vm, JNIEnv ** env, void * vm_args);
  JavaVMOption options[4];
  JavaVMInitArgs args;
  jint (* register_natives) (JNIEnv * env);
  jint (* register_natives_legacy) (JNIEnv * env, jclass clazz);
  jint result;

  vm_module = dlopen ((get_system_api_level () >= 21)
      ? "libart.so"
      : "libdvm.so",
      RTLD_LAZY | RTLD_GLOBAL);
  g_assert (vm_module != NULL);

  runtime_module = dlopen ("libandroid_runtime.so", RTLD_LAZY | RTLD_GLOBAL);
  g_assert (runtime_module != NULL);

  create_java_vm = dlsym (vm_module, "JNI_CreateJavaVM");
  g_assert (create_java_vm != NULL);

  options[0].optionString = "-verbose:jni";
  options[1].optionString = "-verbose:gc";
  options[2].optionString = "-Xcheck:jni";
  options[3].optionString = "-Xdebug";

  args.version = JNI_VERSION_1_6;
  args.nOptions = G_N_ELEMENTS (options);
  args.options = options;
  args.ignoreUnrecognized = JNI_TRUE;

  result = create_java_vm (vm, env, &args);
  g_assert_cmpint (result, ==, JNI_OK);

  register_natives = dlsym (runtime_module, "registerFrameworkNatives");
  if (register_natives != NULL)
  {
    result = register_natives (*env);
    g_assert_cmpint (result, ==, JNI_OK);
  }
  else
  {
    register_natives_legacy = dlsym (runtime_module,
        "Java_com_android_internal_util_WithFramework_registerNatives");
    g_assert (register_natives_legacy != NULL);

    result = register_natives_legacy (*env, NULL);
    g_assert_cmpint (result, ==, JNI_OK);
  }
}

static guint
get_system_api_level (void)
{
  gchar sdk_version[PROP_VALUE_MAX];

  sdk_version[0] = '\0';
  __system_property_get ("ro.build.version.sdk", sdk_version);

  return atoi (sdk_version);
}
