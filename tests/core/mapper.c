#ifdef HAVE_DARWIN

#include "backend-darwin/gumdarwinmapper.h"

#include <mach/mach.h>

typedef struct _DarwinInjectorState DarwinInjectorState;

struct _DarwinInjectorState
{
  GumMemoryRange * mapped_range;
};

typedef void (* AgentEntrypoint) (const gchar * data_string,
    gint * unload_policy, gpointer injector_state);

gint
main (gint argc,
      gchar * argv[])
{
  gint result = 1;
  const gchar * dylib_path;
  mach_port_t task;
  GumCpuType cpu_type;
  GError * error = NULL;
  GumDarwinModuleResolver * resolver = NULL;
  GumDarwinMapper * mapper = NULL;
  mach_vm_address_t base_address = 0;
  gsize mapped_size;
  kern_return_t kr;
  GumDarwinModule * module = NULL;
  GumDarwinMapperConstructor constructor;
  GumDarwinMapperDestructor destructor;
  AgentEntrypoint entrypoint;
  gint unload_policy = 0;
  DarwinInjectorState injector_state;
  GumMemoryRange mapped_range;

  gum_init ();

  if (argc != 2)
  {
    g_printerr ("usage: %s <dylib_path>\n", argv[0]);
    goto beach;
  }

  dylib_path = argv[1];
  task = mach_task_self ();
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  cpu_type = GUM_CPU_IA32;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  cpu_type = GUM_CPU_AMD64;
#elif defined (HAVE_ARM)
  cpu_type = GUM_CPU_ARM;
#elif defined (HAVE_ARM64)
  cpu_type = GUM_CPU_ARM64;
#else
# error Unsupported CPU type
#endif

  resolver = gum_darwin_module_resolver_new (task, &error);
  if (error != NULL)
    goto failure;
  mapper = gum_darwin_mapper_new_from_file (dylib_path, resolver, &error);
  if (error != NULL)
    goto failure;

  mapped_size = gum_darwin_mapper_size (mapper);

  kr = mach_vm_allocate (task, &base_address, mapped_size, VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  gum_darwin_mapper_map (mapper, base_address, &error);
  if (error != NULL)
    goto failure;

  g_object_get (mapper, "module", &module, NULL);
  g_print ("Base address: 0x%llx\n", module->base_address);

  constructor =
      GSIZE_TO_POINTER (gum_darwin_mapper_constructor (mapper));
  destructor =
      GSIZE_TO_POINTER (gum_darwin_mapper_destructor (mapper));
  entrypoint =
      GSIZE_TO_POINTER (gum_darwin_mapper_resolve (mapper, "frida_agent_main"));

  g_print ("Mapped! constructor=%p destructor=%p entrypoint=%p\n",
      constructor, destructor, entrypoint);

  constructor ();

  injector_state.mapped_range = &mapped_range;
  mapped_range.base_address = base_address;
  mapped_range.size = mapped_size;

  entrypoint ("", &unload_policy, &injector_state);

  destructor ();

  result = 0;
  goto beach;

failure:
  {
    g_printerr ("%s\n", error->message);
    g_error_free (error);

    goto beach;
  }
beach:
  {
    if (base_address != 0)
    {
      kr = mach_vm_deallocate (task, base_address, mapped_size);
      g_assert_cmpint (kr, ==, KERN_SUCCESS);
    }

    g_clear_object (&module);
    g_clear_object (&mapper);
    g_clear_object (&resolver);

    return result;
  }
}

#else

int
main (int argc, char * argv[])
{
  return 0;
}

#endif
