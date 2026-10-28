/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_NATIVE_PROCESS_MEMORY_H__
#define __GUM_NATIVE_PROCESS_MEMORY_H__

#include <gum/gumprocess.h>
#include <gum/gumprocessmemory.h>

G_BEGIN_DECLS

#define GUM_TYPE_NATIVE_PROCESS_MEMORY (gum_native_process_memory_get_type ())
G_DECLARE_FINAL_TYPE (GumNativeProcessMemory, gum_native_process_memory, GUM,
                      NATIVE_PROCESS_MEMORY, GObject)

GUM_API GumNativeProcessMemory * gum_native_process_memory_new_local (void);
GUM_API GumNativeProcessMemory * gum_native_process_memory_new_remote (
    GumProcessId pid, gpointer handle);

GUM_API gpointer gum_native_process_memory_get_handle (
    GumNativeProcessMemory * self);

G_END_DECLS

#endif
