/*
 * Copyright (C) 2008-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_PROCESS_H__
#define __GUM_PROCESS_H__

#include <gum/gummemory.h>

typedef gsize GumThreadId;
typedef guint GumThreadState;
typedef struct _GumThreadDetails GumThreadDetails;

enum _GumThreadState
{
  GUM_THREAD_RUNNING = 1,
  GUM_THREAD_STOPPED,
  GUM_THREAD_WAITING,
  GUM_THREAD_UNINTERRUPTIBLE,
  GUM_THREAD_HALTED
};

struct _GumThreadDetails
{
  GumThreadId id;
  GumThreadState state;
  GumCpuContext cpu_context;
};

G_BEGIN_DECLS

typedef void (* GumModifyThreadFunc) (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
typedef gboolean (* GumFoundThreadFunc) (GumThreadDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundModuleFunc) (const gchar * name,
    const GumMemoryRange * range, const gchar * path, gpointer user_data);
typedef gboolean (* GumFoundExportFunc) (const gchar * name, GumAddress address,
    gpointer user_data);
typedef gboolean (* GumFoundRangeFunc) (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);

GUM_API GumThreadId gum_process_get_current_thread_id (void);
GUM_API gboolean gum_process_modify_thread (GumThreadId thread_id,
    GumModifyThreadFunc func, gpointer user_data);
GUM_API void gum_process_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data);
GUM_API void gum_process_enumerate_modules (GumFoundModuleFunc func,
    gpointer user_data);
GUM_API void gum_process_enumerate_ranges (GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_exports (const gchar * module_name,
    GumFoundExportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_ranges (const gchar * module_name,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
GUM_API GumAddress gum_module_find_base_address (const gchar * module_name);
GUM_API GumAddress gum_module_find_export_by_name (const gchar * module_name,
    const gchar * symbol_name);

G_END_DECLS

#endif
