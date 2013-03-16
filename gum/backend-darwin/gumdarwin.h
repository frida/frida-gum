/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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
GUM_API GumAddress gum_darwin_find_entrypoint (mach_port_t task);
GUM_API void gum_darwin_enumerate_modules (mach_port_t task,
    GumFoundModuleFunc func, gpointer user_data);
GUM_API void gum_darwin_enumerate_ranges (mach_port_t task,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_darwin_enumerate_exports (mach_port_t task,
    const gchar * module_name, GumFoundExportFunc func, gpointer user_data);

GumPageProtection gum_page_protection_from_mach (vm_prot_t native_prot);
vm_prot_t gum_page_protection_to_mach (GumPageProtection page_prot);

G_END_DECLS

#endif
