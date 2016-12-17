#ifdef HAVE_DARWIN

#include "backend-darwin/gumdarwinmapper.h"

#include <mach/mach.h>

typedef void (* UnixAttackerEntrypoint) (const gchar * data_string);

gint
main (gint argc,
      gchar * argv[])
{
  const gchar * dylib_path;
  mach_port_t task;
  GumCpuType cpu_type;
  GumDarwinModuleResolver * resolver;
  GumDarwinMapper * mapper;
  mach_vm_address_t base_address = 0;
  kern_return_t kr;
  GumDarwinMapperConstructor constructor;
  GumDarwinMapperDestructor destructor;
  UnixAttackerEntrypoint entrypoint;

  glib_init ();

  if (argc != 2)
  {
    g_printerr ("usage: %s <dylib_path>\n", argv[0]);
    return 1;
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

  resolver = gum_darwin_module_resolver_new (task);
  mapper = gum_darwin_mapper_new_from_file (dylib_path, resolver);

  kr = mach_vm_allocate (task, &base_address, gum_darwin_mapper_size (mapper),
      VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  gum_darwin_mapper_map (mapper, base_address);

  constructor = (GumDarwinMapperConstructor) gum_darwin_mapper_constructor (
      mapper);
  destructor = (GumDarwinMapperDestructor) gum_darwin_mapper_destructor (
      mapper);
  entrypoint = (UnixAttackerEntrypoint) gum_darwin_mapper_resolve (mapper,
      "frida_agent_main");

  constructor ();
  entrypoint ("");
  destructor ();

  kr = mach_vm_deallocate (task, base_address, gum_darwin_mapper_size (mapper));
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  g_object_unref (mapper);
  g_object_unref (resolver);

  return 0;
}

#else

int
main (int argc, char * argv[])
{
  return 0;
}

#endif
