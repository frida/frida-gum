/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_H__
#define __GUM_DARWIN_H__

#include "gumdarwinmapper.h"
#include "gumdarwinmodule.h"
#include "gumdarwinmoduleresolver.h"
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

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_LC_SEGMENT LC_SEGMENT
typedef struct mach_header gum_mach_header_t;
typedef struct segment_command gum_segment_command_t;
typedef struct section gum_section_t;
typedef struct nlist gum_nlist_t;
#else
# define GUM_LC_SEGMENT LC_SEGMENT_64
typedef struct mach_header_64 gum_mach_header_t;
typedef struct segment_command_64 gum_segment_command_t;
typedef struct section_64 gum_section_t;
typedef struct nlist_64 gum_nlist_t;
#endif

#if !defined (__arm__) && !defined (__aarch64__)
typedef x86_thread_state_t GumDarwinUnifiedThreadState;
# if GLIB_SIZEOF_VOID_P == 4
typedef x86_thread_state32_t GumDarwinNativeThreadState;
# else
typedef x86_thread_state64_t GumDarwinNativeThreadState;
# endif
# define GUM_DARWIN_THREAD_STATE_COUNT x86_THREAD_STATE_COUNT
# define GUM_DARWIN_THREAD_STATE_FLAVOR x86_THREAD_STATE
#else
typedef arm_unified_thread_state_t GumDarwinUnifiedThreadState;
# if GLIB_SIZEOF_VOID_P == 4
typedef arm_thread_state32_t GumDarwinNativeThreadState;
# else
typedef arm_thread_state64_t GumDarwinNativeThreadState;
# endif
# define GUM_DARWIN_THREAD_STATE_COUNT ARM_UNIFIED_THREAD_STATE_COUNT
# define GUM_DARWIN_THREAD_STATE_FLAVOR ARM_UNIFIED_THREAD_STATE
#endif

G_BEGIN_DECLS

GUM_API gboolean gum_darwin_is_ios9_or_newer (void);

GUM_API guint8 * gum_darwin_read (mach_port_t task, GumAddress address,
    gsize len, gsize * n_bytes_read);
GUM_API gboolean gum_darwin_write (mach_port_t task, GumAddress address,
    const guint8 * bytes, gsize len);
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
GUM_API void gum_darwin_enumerate_imports (mach_port_t task,
    const gchar * module_name, GumFoundImportFunc func, gpointer user_data);
GUM_API void gum_darwin_enumerate_exports (mach_port_t task,
    const gchar * module_name, GumFoundExportFunc func, gpointer user_data);

GUM_API gboolean gum_darwin_find_slide (GumAddress module_address,
    const guint8 * module, gsize module_size, gint64 * slide);
GUM_API gboolean gum_darwin_find_linkedit (const guint8 * module,
    gsize module_size, GumAddress * linkedit);
GUM_API gboolean gum_darwin_find_command (guint id, const guint8 * module,
    gsize module_size, gpointer * command);

GUM_API void gum_darwin_parse_unified_thread_state (
    const GumDarwinUnifiedThreadState * ts, GumCpuContext * ctx);
GUM_API void gum_darwin_parse_native_thread_state (
    const GumDarwinNativeThreadState * ts, GumCpuContext * ctx);
GUM_API void gum_darwin_unparse_unified_thread_state (
    const GumCpuContext * ctx, GumDarwinUnifiedThreadState * ts);
GUM_API void gum_darwin_unparse_native_thread_state (
    const GumCpuContext * ctx, GumDarwinNativeThreadState * ts);

GUM_API GumPageProtection gum_page_protection_from_mach (vm_prot_t native_prot);
GUM_API vm_prot_t gum_page_protection_to_mach (GumPageProtection page_prot);

GUM_API const char * gum_symbol_name_from_darwin (const char * s);

G_END_DECLS

#endif
