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

GumAddress
gum_process_memory_alloc (GumProcessMemory * self,
                          gsize size)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->alloc (self, size);
}

GumAddress
gum_process_memory_alloc_near (GumProcessMemory * self,
                               GumAddress near_address,
                               gsize max_distance,
                               gsize size)
{
  return GUM_PROCESS_MEMORY_GET_IFACE (self)->alloc_near (self, near_address,
      max_distance, size);
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
