/*
 * Copyright (C) 2012-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_LINUX_H__
#define __GUM_LINUX_H__

#include "gumprocess.h"

#include <ucontext.h>

G_BEGIN_DECLS

typedef struct _GumLinuxNamedRange GumLinuxNamedRange;

struct _GumLinuxNamedRange
{
  const gchar * name;
  gpointer base;
  gsize size;
};

GUM_API GumCpuType gum_linux_cpu_type_from_file (const gchar * path,
    GError ** error);
GUM_API GumCpuType gum_linux_cpu_type_from_pid (pid_t pid, GError ** error);
GUM_API void gum_linux_enumerate_modules_using_proc_maps (
    GumFoundModuleFunc func, gpointer user_data);
GUM_API void gum_linux_enumerate_ranges (pid_t pid, GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);
GUM_API GHashTable * gum_linux_collect_named_ranges (void);

GUM_API gboolean gum_linux_module_path_matches (const gchar * path,
    const gchar * name_or_path);

GUM_API void gum_linux_parse_ucontext (const ucontext_t * uc,
    GumCpuContext * ctx);
GUM_API void gum_linux_unparse_ucontext (const GumCpuContext * ctx,
    ucontext_t * uc);

G_END_DECLS

#endif
