/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_MEMORY_H__
#define __GUM_PROCESS_MEMORY_H__

#include <gum/gummemory.h>

G_BEGIN_DECLS

#define GUM_TYPE_PROCESS_MEMORY (gum_process_memory_get_type ())
G_DECLARE_INTERFACE (GumProcessMemory, gum_process_memory, GUM, PROCESS_MEMORY,
                     GObject)

struct _GumProcessMemoryInterface
{
  GTypeInterface parent;

  GumAddress (* alloc) (GumProcessMemory * self, gsize size);
  GumAddress (* alloc_near) (GumProcessMemory * self, GumAddress near_address,
      gsize max_distance, gsize size);
  void (* free) (GumProcessMemory * self, GumAddress address, gsize size);
  gboolean (* read) (GumProcessMemory * self, GumAddress address,
      gpointer buffer, gsize size);
  gboolean (* write) (GumProcessMemory * self, GumAddress address,
      gconstpointer data, gsize size);
  gboolean (* protect) (GumProcessMemory * self, GumAddress address,
      gsize size, GumPageProtection prot);
  gboolean (* mark_code) (GumProcessMemory * self, GumAddress address,
      gsize size);
};

GUM_API GumAddress gum_process_memory_alloc (GumProcessMemory * self,
    gsize size);
GUM_API GumAddress gum_process_memory_alloc_near (GumProcessMemory * self,
    GumAddress near_address, gsize max_distance, gsize size);
GUM_API void gum_process_memory_free (GumProcessMemory * self,
    GumAddress address, gsize size);
GUM_API gboolean gum_process_memory_read (GumProcessMemory * self,
    GumAddress address, gpointer buffer, gsize size);
GUM_API gboolean gum_process_memory_write (GumProcessMemory * self,
    GumAddress address, gconstpointer data, gsize size);
GUM_API gboolean gum_process_memory_protect (GumProcessMemory * self,
    GumAddress address, gsize size, GumPageProtection prot);
GUM_API gboolean gum_process_memory_mark_code (GumProcessMemory * self,
    GumAddress address, gsize size);

G_END_DECLS

#endif
