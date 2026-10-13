/*
 * Copyright (C) 2015-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2019 Jon Wilson <jonwilson@zepler.net>
 * Copyright (C) 2020 Marcus Mengs <mame8282@googlemail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_FFI_H__
#define __GUM_FFI_H__

#include "gumdefs.h"

#include <ffi.h>
#include <glib-object.h>

#if defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 8 && !defined (X86_WIN64) && \
    GUM_TARGET_ABI_IS_WINDOWS
# define GUM_DEFAULT_FFI_ABI FFI_EFI64
#else
# define GUM_DEFAULT_FFI_ABI FFI_DEFAULT_ABI
#endif

G_BEGIN_DECLS

typedef union _GumFFIArg GumFFIArg;

union _GumFFIArg
{
  gpointer v_pointer;
  gint v_sint;
  guint v_uint;
  glong v_slong;
  gulong v_ulong;
  gchar v_schar;
  guchar v_uchar;
  gfloat v_float;
  gdouble v_double;
  gint8 v_sint8;
  guint8 v_uint8;
  gint16 v_sint16;
  guint16 v_uint16;
  gint32 v_sint32;
  guint32 v_uint32;
  gint64 v_sint64;
  guint64 v_uint64;
};

extern ffi_type gum_ffi_type_size_t;
extern ffi_type gum_ffi_type_ssize_t;

G_GNUC_INTERNAL GumFFIArg * gum_ffi_ret_value (const ffi_type * type,
    gpointer ret);
G_GNUC_INTERNAL gboolean gum_ffi_try_get_type_by_name (const gchar * name,
    ffi_type ** type);
G_GNUC_INTERNAL gboolean gum_ffi_try_get_abi_by_name (const gchar * name,
    ffi_abi * abi);
G_GNUC_INTERNAL ffi_type * gum_ffi_maybe_promote_variadic (ffi_type * type);

G_END_DECLS

#endif
