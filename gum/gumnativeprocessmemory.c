/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumnativeprocessmemory.h"

#include "gumcodesegment.h"
#include "gummemory-priv.h"
#if defined (HAVE_WINDOWS)
# include "gum/gumwindows.h"
#elif defined (HAVE_DARWIN)
# include "gum/gumdarwin.h"
#endif

#include <string.h>

struct _GumNativeProcessMemory
{
  GObject parent;

  gboolean is_local;
  GumProcessId pid;
  gpointer handle;
};

static void gum_native_process_memory_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumProcessId gum_native_process_memory_get_pid (
    GumProcessMemory * memory);
static GumAddress gum_native_process_memory_alloc (GumProcessMemory * memory,
    gsize size, gsize alignment);
static GumAddress gum_native_process_memory_alloc_anywhere (
    GumNativeProcessMemory * self, gsize size);
static GumAddress gum_native_process_memory_alloc_near (
    GumProcessMemory * memory, GumAddress near_address, gsize max_distance,
    gsize size, gsize alignment);
static gboolean gum_native_process_memory_try_alloc_at (
    GumNativeProcessMemory * self, GumAddress address, gsize size);
static void gum_native_process_memory_free (GumProcessMemory * memory,
    GumAddress address, gsize size);
static gboolean gum_native_process_memory_read (GumProcessMemory * memory,
    GumAddress address, gpointer buffer, gsize size);
static gboolean gum_native_process_memory_write (GumProcessMemory * memory,
    GumAddress address, gconstpointer data, gsize size);
#ifdef HAVE_DARWIN
static gboolean gum_native_process_memory_map (GumProcessMemory * memory,
    GumAddress address, gsize size, gconstpointer data, gsize data_size,
    GumPageProtection prot);
#endif
static gboolean gum_native_process_memory_protect (GumProcessMemory * memory,
    GumAddress address, gsize size, GumPageProtection prot);
static gboolean gum_native_process_memory_mark_code (GumProcessMemory * memory,
    GumAddress address, gsize size);

#ifdef HAVE_DARWIN
static gboolean gum_remap_as_code (mach_port_t task, GumAddress address,
    gsize size);
#endif

G_DEFINE_TYPE_WITH_CODE (GumNativeProcessMemory,
                         gum_native_process_memory,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_PROCESS_MEMORY,
                             gum_native_process_memory_iface_init))

static void
gum_native_process_memory_class_init (GumNativeProcessMemoryClass * klass)
{
}

static void
gum_native_process_memory_iface_init (gpointer g_iface,
                                      gpointer iface_data)
{
  GumProcessMemoryInterface * iface = g_iface;

  iface->get_pid = gum_native_process_memory_get_pid;
  iface->alloc = gum_native_process_memory_alloc;
  iface->alloc_near = gum_native_process_memory_alloc_near;
  iface->free = gum_native_process_memory_free;
  iface->read = gum_native_process_memory_read;
  iface->write = gum_native_process_memory_write;
#ifdef HAVE_DARWIN
  iface->map = gum_native_process_memory_map;
#endif
  iface->protect = gum_native_process_memory_protect;
  iface->mark_code = gum_native_process_memory_mark_code;
}

static void
gum_native_process_memory_init (GumNativeProcessMemory * self)
{
}

GumNativeProcessMemory *
gum_native_process_memory_new_local (void)
{
  GumNativeProcessMemory * self =
      g_object_new (GUM_TYPE_NATIVE_PROCESS_MEMORY, NULL);

  self->is_local = TRUE;
  self->pid = gum_process_get_id ();
  self->handle = NULL;

  return self;
}

GumNativeProcessMemory *
gum_native_process_memory_new_remote (GumProcessId pid,
                                      gpointer handle)
{
  GumNativeProcessMemory * self =
      g_object_new (GUM_TYPE_NATIVE_PROCESS_MEMORY, NULL);

  self->is_local = FALSE;
  self->pid = pid;
  self->handle = handle;

  return self;
}

gpointer
gum_native_process_memory_get_handle (GumNativeProcessMemory * self)
{
  return self->handle;
}

static GumProcessId
gum_native_process_memory_get_pid (GumProcessMemory * memory)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);

  return self->pid;
}

static GumAddress
gum_native_process_memory_alloc (GumProcessMemory * memory,
                                 gsize size,
                                 gsize alignment)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);
  GumAddress base;
  gint retries = 3;

  if (self->is_local)
  {
    return GUM_ADDRESS (gum_memory_allocate (NULL, size, alignment,
        GUM_PAGE_RW));
  }

  base = gum_native_process_memory_alloc_anywhere (self, size);
  if (base == 0 || (base & (alignment - 1)) == 0)
    return base;
  gum_native_process_memory_free (memory, base, size);

  while (retries-- != 0)
  {
    GumAddress aligned_base;

    base = gum_native_process_memory_alloc_anywhere (self, size + alignment);
    if (base == 0)
      return 0;
    gum_native_process_memory_free (memory, base, size + alignment);

    aligned_base = (base + alignment - 1) & ~((GumAddress) alignment - 1);
    if (gum_native_process_memory_try_alloc_at (self, aligned_base, size))
      return aligned_base;
  }

  return 0;
}

static GumAddress
gum_native_process_memory_alloc_anywhere (GumNativeProcessMemory * self,
                                          gsize size)
{
#if defined (HAVE_WINDOWS)
  return GUM_ADDRESS (VirtualAllocEx (self->handle, NULL, size,
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
#elif defined (HAVE_DARWIN)
  {
    mach_vm_address_t result = 0;
    mach_port_t task = (mach_port_t) GPOINTER_TO_SIZE (self->handle);

    if (mach_vm_allocate (task, &result, size, VM_FLAGS_ANYWHERE) !=
        KERN_SUCCESS)
    {
      return 0;
    }

    return result;
  }
#else
  return 0;
#endif
}

static GumAddress
gum_native_process_memory_alloc_near (GumProcessMemory * memory,
                                      GumAddress near_address,
                                      gsize max_distance,
                                      gsize size,
                                      gsize alignment)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);
  GumAddress step, candidate;

  if (self->is_local)
  {
    GumAddressSpec spec;

    spec.near_address = GSIZE_TO_POINTER (near_address);
    spec.max_distance = max_distance;

    return GUM_ADDRESS (gum_memory_allocate_near (&spec, size, alignment,
        GUM_PAGE_RW));
  }

  step = MAX (0x10000, alignment);

  for (candidate = (near_address & ~(step - 1)) - step;
      candidate >= step && near_address - candidate <= max_distance;
      candidate -= step)
  {
    if (gum_native_process_memory_try_alloc_at (self, candidate, size))
      return candidate;
  }

  return 0;
}

static gboolean
gum_native_process_memory_try_alloc_at (GumNativeProcessMemory * self,
                                        GumAddress address,
                                        gsize size)
{
#if defined (HAVE_WINDOWS)
  return VirtualAllocEx (self->handle, GSIZE_TO_POINTER (address), size,
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != NULL;
#elif defined (HAVE_DARWIN)
  mach_port_t task = (mach_port_t) GPOINTER_TO_SIZE (self->handle);
  mach_vm_address_t result = address;

  return mach_vm_allocate (task, &result, size, VM_FLAGS_FIXED) ==
      KERN_SUCCESS;
#else
  return FALSE;
#endif
}

static void
gum_native_process_memory_free (GumProcessMemory * memory,
                                GumAddress address,
                                gsize size)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);

  if (address == 0)
    return;

  if (self->is_local)
  {
    gum_memory_free (GSIZE_TO_POINTER (address), size);
    return;
  }

#if defined (HAVE_WINDOWS)
  VirtualFreeEx (self->handle, GSIZE_TO_POINTER (address), 0, MEM_RELEASE);
#elif defined (HAVE_DARWIN)
  {
    mach_port_t task = (mach_port_t) GPOINTER_TO_SIZE (self->handle);

    mach_vm_deallocate (task, address, size);
  }
#endif
}

static gboolean
gum_native_process_memory_read (GumProcessMemory * memory,
                                GumAddress address,
                                gpointer buffer,
                                gsize size)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);

  if (self->is_local)
  {
    memcpy (buffer, GSIZE_TO_POINTER (address), size);
    return TRUE;
  }

#if defined (HAVE_WINDOWS)
  {
    SIZE_T n = 0;

    return ReadProcessMemory (self->handle, GSIZE_TO_POINTER (address), buffer,
        size, &n) && n == size;
  }
#elif defined (HAVE_DARWIN)
  {
    mach_port_t task = (mach_port_t) GPOINTER_TO_SIZE (self->handle);
    gsize n = 0;
    guint8 * bytes;

    bytes = gum_darwin_read (task, address, size, &n);
    if (bytes == NULL)
      return FALSE;
    memcpy (buffer, bytes, n);
    g_free (bytes);

    return n == size;
  }
#elif defined (HAVE_LINUX)
  return _gum_try_read_process_memory (self->pid, address, buffer, size);
#else
  return FALSE;
#endif
}

static gboolean
gum_native_process_memory_write (GumProcessMemory * memory,
                                 GumAddress address,
                                 gconstpointer data,
                                 gsize size)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);

  if (self->is_local)
  {
    memcpy (GSIZE_TO_POINTER (address), data, size);
    return TRUE;
  }

#if defined (HAVE_WINDOWS)
  {
    SIZE_T written = 0;

    return WriteProcessMemory (self->handle, GSIZE_TO_POINTER (address), data,
        size, &written) && written == size;
  }
#elif defined (HAVE_DARWIN)
  {
    mach_port_t task = (mach_port_t) GPOINTER_TO_SIZE (self->handle);

    return gum_darwin_write (task, address, data, size);
  }
#elif defined (HAVE_LINUX)
  return _gum_try_write_process_memory (self->pid, address, data, size);
#else
  return FALSE;
#endif
}

#ifdef HAVE_DARWIN

static gboolean
gum_native_process_memory_map (GumProcessMemory * memory,
                               GumAddress address,
                               gsize size,
                               gconstpointer data,
                               gsize data_size,
                               GumPageProtection prot)
{
  static gboolean remapping_supported = TRUE;
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);
  mach_port_t task = self->is_local
      ? mach_task_self ()
      : (mach_port_t) GPOINTER_TO_SIZE (self->handle);
  vm_prot_t mach_prot = gum_page_protection_to_mach (prot);
  mach_vm_address_t mapped_address = address;
  vm_prot_t cur_protection, max_protection;
  kern_return_t kr;

  if (remapping_supported)
  {
    kr = mach_vm_remap (task, &mapped_address, data_size, 0,
        VM_FLAGS_OVERWRITE, mach_task_self (), GPOINTER_TO_SIZE (data), TRUE,
        &cur_protection, &max_protection, VM_INHERIT_COPY);
    if (kr != KERN_SUCCESS)
      return FALSE;

    kr = mach_vm_protect (task, address, size, FALSE, mach_prot);
    if (kr != KERN_PROTECTION_FAILURE)
      return kr == KERN_SUCCESS;

    remapping_supported = FALSE;

    kr = mach_vm_allocate (task, &mapped_address, size,
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    if (kr != KERN_SUCCESS)
      return FALSE;
  }

  return gum_darwin_write (task, address, data, data_size) &&
      mach_vm_protect (task, address, size, FALSE, mach_prot) == KERN_SUCCESS;
}

#endif

static gboolean
gum_native_process_memory_protect (GumProcessMemory * memory,
                                   GumAddress address,
                                   gsize size,
                                   GumPageProtection prot)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);

  if (self->is_local)
    return gum_try_mprotect (GSIZE_TO_POINTER (address), size, prot);

#if defined (HAVE_WINDOWS)
  {
    DWORD old_protect;

    return VirtualProtectEx (self->handle, GSIZE_TO_POINTER (address), size,
        gum_page_protection_to_windows (prot), &old_protect);
  }
#elif defined (HAVE_DARWIN)
  {
    mach_port_t task = (mach_port_t) GPOINTER_TO_SIZE (self->handle);

    return mach_vm_protect (task, address, size, FALSE,
        gum_page_protection_to_mach (prot)) == KERN_SUCCESS;
  }
#else
  return FALSE;
#endif
}

static gboolean
gum_native_process_memory_mark_code (GumProcessMemory * memory,
                                     GumAddress address,
                                     gsize size)
{
  GumNativeProcessMemory * self = GUM_NATIVE_PROCESS_MEMORY (memory);

  if (self->is_local)
    return gum_memory_mark_code (GSIZE_TO_POINTER (address), size);

#if defined (HAVE_WINDOWS)
  {
    gboolean protected;
    DWORD old_protect;

    protected = VirtualProtectEx (self->handle, GSIZE_TO_POINTER (address),
        size, PAGE_EXECUTE_READ, &old_protect);
    FlushInstructionCache (self->handle, GSIZE_TO_POINTER (address), size);

    return protected;
  }
#elif defined (HAVE_DARWIN)
  {
    mach_port_t task = (mach_port_t) GPOINTER_TO_SIZE (self->handle);

    if (gum_query_is_rwx_supported () || !gum_code_segment_is_supported ())
    {
      return mach_vm_protect (task, address, size, FALSE,
          VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS;
    }

    return gum_remap_as_code (task, address, size);
  }
#else
  return FALSE;
#endif
}

#ifdef HAVE_DARWIN

static gboolean
gum_remap_as_code (mach_port_t task,
                   GumAddress address,
                   gsize size)
{
  gboolean success;
  guint8 * code;
  gsize n;
  GumCodeSegment * segment;
  guint8 * scratch_page;
  mach_vm_address_t mapped_address;
  vm_prot_t cur_protection, max_protection;

  code = gum_darwin_read (task, address, size, &n);
  if (code == NULL)
    return FALSE;

  segment = gum_code_segment_new (size, NULL);

  scratch_page = gum_code_segment_get_address (segment);
  memcpy (scratch_page, code, n);

  gum_code_segment_realize (segment);
  gum_code_segment_map (segment, 0, size, scratch_page);

  mapped_address = address;
  success = mach_vm_remap (task, &mapped_address, size, 0, VM_FLAGS_OVERWRITE,
      mach_task_self (), (mach_vm_address_t) scratch_page, FALSE,
      &cur_protection, &max_protection, VM_INHERIT_COPY) == KERN_SUCCESS;

  gum_code_segment_free (segment);
  g_free (code);

  return success;
}

#endif
