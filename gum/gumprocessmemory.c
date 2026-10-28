/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocessmemory.h"

G_DEFINE_INTERFACE (GumProcessMemory, gum_process_memory, G_TYPE_OBJECT)

static void
gum_process_memory_default_init (GumProcessMemoryInterface * iface)
{
}

GumProcessId
gum_process_memory_get_pid (GumProcessMemory * self)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->get_pid (self);
}

GumAddress
gum_process_memory_alloc (GumProcessMemory * self,
                          gsize size,
                          gsize alignment)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->alloc (self, size, alignment);
}

GumAddress
gum_process_memory_alloc_near (GumProcessMemory * self,
                               GumAddress near_address,
                               gsize max_distance,
                               gsize size,
                               gsize alignment)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->alloc_near (self, near_address,
      max_distance, size, alignment);
}

void
gum_process_memory_free (GumProcessMemory * self,
                         GumAddress address,
                         gsize size)
{
  GUM_PROCESS_MEMORY_GET_IFACE (self)->free (self, address, size);
}

gboolean
gum_process_memory_read (GumProcessMemory * self,
                         GumAddress address,
                         gpointer buffer,
                         gsize size)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->read (self, address, buffer,
      size);
}

gboolean
gum_process_memory_write (GumProcessMemory * self,
                          GumAddress address,
                          gconstpointer data,
                          gsize size)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->write (self, address, data,
      size);
}

gboolean
gum_process_memory_map (GumProcessMemory * self,
                        GumAddress address,
                        gsize size,
                        gconstpointer data,
                        gsize data_size,
                        GumPageProtection prot)
{
  GumProcessMemoryInterface * iface = GUM_PROCESS_MEMORY_GET_IFACE (self);

  if (iface->map != NULL)
    return iface->map (self, address, size, data, data_size, prot);

  return gum_process_memory_write (self, address, data, data_size) &&
      gum_process_memory_protect (self, address, size, prot);
}

gboolean
gum_process_memory_protect (GumProcessMemory * self,
                            GumAddress address,
                            gsize size,
                            GumPageProtection prot)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->protect (self, address, size,
      prot);
}

gboolean
gum_process_memory_mark_code (GumProcessMemory * self,
                              GumAddress address,
                              gsize size)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->mark_code (self, address, size);
}
