/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_H__
#define __GUM_DARWIN_H__

#include "gummemory.h"
#include "gumprocess.h"

#ifdef HAVE_IOS
  /*
   * HACK: the iOS 5.0 SDK provides a placeholder header containing nothing
   *       but an #error stating that this API is not available. So we work
   *       around it by taking a copy of the Mac SDK's header and putting it
   *       in our SDK's include directory. ICK!
   */
# include "frida_mach_vm.h"
#else
# include <mach/mach_vm.h>
#endif

G_BEGIN_DECLS

GUM_API guint8 * gum_darwin_read (mach_port_t task, GumAddress address,
    gsize len, gsize * n_bytes_read);
GUM_API gboolean gum_darwin_write (mach_port_t task, GumAddress address,
    guint8 * bytes, gsize len);
GUM_API gboolean gum_darwin_cpu_type_from_pid (pid_t pid,
    GumCpuType * cpu_type);
GUM_API gboolean gum_darwin_query_page_size (mach_port_t task,
    guint * page_size);
GUM_API GumAddress gum_darwin_find_entrypoint (mach_port_t task);
GUM_API void gum_darwin_enumerate_threads (mach_port_t task,
    GumFoundThreadFunc func, gpointer user_data);
GUM_API void gum_darwin_enumerate_modules (mach_port_t task,
    GumFoundModuleFunc func, gpointer user_data);
GUM_API void gum_darwin_enumerate_ranges (mach_port_t task,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_darwin_enumerate_exports (mach_port_t task,
    const gchar * module_name, GumFoundExportFunc func, gpointer user_data);

GUM_API gboolean gum_darwin_find_slide (GumAddress module_address,
    const guint8 * module, gsize module_size, gint64 * slide);
GUM_API gboolean gum_darwin_find_linkedit (const guint8 * module,
    gsize module_size, GumAddress * linkedit);
GUM_API gboolean gum_darwin_find_command (guint id, const guint8 * module,
    gsize module_size, gpointer * command);

GumPageProtection gum_page_protection_from_mach (vm_prot_t native_prot);
vm_prot_t gum_page_protection_to_mach (GumPageProtection page_prot);

G_END_DECLS

#endif
