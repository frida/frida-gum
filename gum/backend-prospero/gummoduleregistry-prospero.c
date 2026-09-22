/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-elf.h"

#include "gummodule-elf.h"

#include <dlfcn.h>
#include <ps5/kernel.h>
#include <unistd.h>

#define GUM_MAX_MODULES 256
#define GUM_MAX_MODULE_PATH 1024
#define GUM_MAX_REDIRECT_SIZE 16
#define GUM_MAX_MODULE_SEGMENTS 4

typedef struct _GumSceKernelModuleSegmentInfo GumSceKernelModuleSegmentInfo;
typedef struct _GumSceKernelModuleInfo GumSceKernelModuleInfo;

struct _GumSceKernelModuleSegmentInfo
{
  gpointer base_address;
  guint32 size;
  gint32 prot;
};

struct _GumSceKernelModuleInfo
{
  gsize size;
  gchar name[256];
  GumSceKernelModuleSegmentInfo segments[GUM_MAX_MODULE_SEGMENTS];
  guint32 num_segments;
  guint8 fingerprint[20];
};

extern int sceKernelGetModuleInfo (int handle, GumSceKernelModuleInfo * info);
extern int kernel_dynlib_path (pid_t pid, uint32_t handle, char * buffer,
    size_t size);
extern int sceKernelLoadStartModule (const char * path, gsize argc,
    const void * argv, guint32 flags, const void * options, int * result);
extern int sceKernelStopUnloadModule (int handle, gsize argc,
    const void * argv, guint32 flags, const void * options, int * result);

static const gchar * gum_query_module_path (int handle,
    const GumSceKernelModuleInfo * info, gchar * buffer);
static gpointer gum_create_module_handle (GumNativeModule * module,
    gpointer user_data);

static void gum_compute_module_range (const GumSceKernelModuleInfo * info,
    GumMemoryRange * range);

void
_gum_module_registry_enumerate_loaded_modules (GumFoundModuleFunc func,
                                               gpointer user_data)
{
  int handle;

  for (handle = 0; handle != GUM_MAX_MODULES; handle++)
  {
    GumSceKernelModuleInfo info;
    gchar path[GUM_MAX_MODULE_PATH];
    GumMemoryRange range;
    GumNativeModule * module;
    gboolean carry_on;

    info.size = sizeof (info);
    if (sceKernelGetModuleInfo (handle, &info) != 0)
      continue;

    gum_compute_module_range (&info, &range);

    module = _gum_native_module_make (
        gum_query_module_path (handle, &info, path), &range,
        gum_create_module_handle, NULL, NULL, (GDestroyNotify) dlclose);

    carry_on = func (GUM_MODULE (module), user_data);

    g_object_unref (module);

    if (!carry_on)
      return;
  }
}

static const gchar *
gum_query_module_path (int handle,
                       const GumSceKernelModuleInfo * info,
                       gchar * buffer)
{
  if (kernel_dynlib_path (getpid (), handle, buffer, GUM_MAX_MODULE_PATH) != 0)
    return info->name;

  return buffer;
}

static gpointer
gum_create_module_handle (GumNativeModule * module,
                          gpointer user_data)
{
  return dlopen (module->path, RTLD_LAZY);
}

void
_gum_module_registry_enumerate_rtld_notifiers (GumFoundRtldNotifierFunc func,
                                               gpointer user_data)
{
  GumRtldNotifierDetails notifier;

  notifier.point_cut = GUM_POINT_LEAVE;

  notifier.location = GUM_FUNCPTR_TO_POINTER (sceKernelLoadStartModule);
  gum_ensure_code_readable (notifier.location, GUM_MAX_REDIRECT_SIZE);
  func (&notifier, user_data);

  notifier.location = GUM_FUNCPTR_TO_POINTER (sceKernelStopUnloadModule);
  gum_ensure_code_readable (notifier.location, GUM_MAX_REDIRECT_SIZE);
  func (&notifier, user_data);
}

void
_gum_module_registry_handle_rtld_notification (GumSynchronizeModulesFunc sync,
                                               GumInvocationContext * ic)
{
  sync ();
}

static void
gum_compute_module_range (const GumSceKernelModuleInfo * info,
                          GumMemoryRange * range)
{
  GumAddress lowest, highest;
  guint32 i;

  lowest = G_MAXUINT64;
  highest = 0;

  for (i = 0; i != info->num_segments; i++)
  {
    const GumSceKernelModuleSegmentInfo * segment = &info->segments[i];
    GumAddress start = GUM_ADDRESS (segment->base_address);

    lowest = MIN (lowest, start);
    highest = MAX (highest, start + segment->size);
  }

  range->base_address = lowest;
  range->size = highest - lowest;
}
