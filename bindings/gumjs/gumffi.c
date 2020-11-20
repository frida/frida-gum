/*
 * Copyright (C) 2015-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumffi.h"
#include <ffi.h>

typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;

// from: https://github.com/libffi/libffi/blob/65da63abc843fe448aaa86015d094cf016f325ba/include/ffi_common.h
typedef unsigned int UINT16 __attribute__((__mode__(__HI__)));
typedef signed int   SINT16 __attribute__((__mode__(__HI__)));
typedef unsigned int UINT32 __attribute__((__mode__(__SI__)));
typedef signed int   SINT32 __attribute__((__mode__(__SI__)));
typedef unsigned int UINT64 __attribute__((__mode__(__DI__)));
typedef signed int   SINT64 __attribute__((__mode__(__DI__)));

// modified from: https://github.com/libffi/libffi/blob/master/src/types.c
#define FFI_TYPEDEF(name, type, id)\
struct struct_align_##name {			\
  char c;					\
  type x;					\
};                \
ffi_type ffi_type_##name = {	\
  sizeof(type),					\
  offsetof(struct struct_align_##name, x),	\
  id, NULL					\
}

// create strong type definition for 'ffi_type_size_t' and 'ffi_type_ssize_t'
// based on the respective properties of ffi_type_uint64, ffi_type_uint32 or ffi_type_uint16
//
// Strong typedef, instead of alias allows distinguishing 'size_t' from uint64/32/16
// in functions like:
// - gum_quick_value_to_ffi
// - gum_quick_value_from_ffi
// - gum_v8_value_to_ffi_type
// - gum_v8_value_from_ffi_type
#if SIZE_WIDTH == 64
FFI_TYPEDEF(size_t, UINT64, FFI_TYPE_UINT64);
FFI_TYPEDEF(ssize_t, SINT64, FFI_TYPE_SINT64);
#elif SIZE_WIDTH == 32
FFI_TYPEDEF(size_t, UINT32, FFI_TYPE_UINT32);
FFI_TYPEDEF(ssize_t, SINT32, FFI_TYPE_SINT32);
#elif SIZE_WIDTH == 16
FFI_TYPEDEF(size_t, UINT16, FFI_TYPE_UINT16);
FFI_TYPEDEF(ssize_t, SINT16, FFI_TYPE_SINT16);
#else
# error "size_t size not supported"
#endif



struct _GumFFITypeMapping
{
  const gchar * name;
  ffi_type * type;
};

struct _GumFFIABIMapping
{
  const gchar * name;
  ffi_abi abi;
};

static const GumFFITypeMapping gum_ffi_type_mappings[] =
{
  { "void", &ffi_type_void },
  { "pointer", &ffi_type_pointer },
  { "int", &ffi_type_sint },
  { "uint", &ffi_type_uint },
  { "long", &ffi_type_slong },
  { "ulong", &ffi_type_ulong },
  { "char", &ffi_type_schar },
  { "uchar", &ffi_type_uchar },
  { "float", &ffi_type_float },
  { "double", &ffi_type_double },
  { "int8", &ffi_type_sint8 },
  { "uint8", &ffi_type_uint8 },
  { "int16", &ffi_type_sint16 },
  { "uint16", &ffi_type_uint16 },
  { "int32", &ffi_type_sint32 },
  { "uint32", &ffi_type_uint32 },
  { "int64", &ffi_type_sint64 },
  { "uint64", &ffi_type_uint64 },
  { "bool", &ffi_type_schar },
  { "size_t", &ffi_type_size_t },
  { "ssize_t", &ffi_type_ssize_t }
};

static const GumFFIABIMapping gum_ffi_abi_mappings[] =
{
  { "default", FFI_DEFAULT_ABI },
#if defined (X86_WIN64)
  { "win64", FFI_WIN64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 8
  { "unix64", FFI_UNIX64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 4
  { "sysv", FFI_SYSV },
  { "stdcall", FFI_STDCALL },
  { "thiscall", FFI_THISCALL },
  { "fastcall", FFI_FASTCALL },
# if defined (X86_WIN32)
  { "mscdecl", FFI_MS_CDECL },
# endif
#elif defined (ARM)
  { "sysv", FFI_SYSV },
# if GLIB_SIZEOF_VOID_P == 4
  { "vfp", FFI_VFP },
# endif
#endif
};

gboolean
gum_ffi_try_get_type_by_name (const gchar * name,
                              ffi_type ** type)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_ffi_type_mappings); i++)
  {
    const GumFFITypeMapping * m = &gum_ffi_type_mappings[i];

    if (strcmp (m->name, name) == 0)
    {
      *type = m->type;
      return TRUE;
    }
  }

  return FALSE;
}

gboolean
gum_ffi_try_get_abi_by_name (const gchar * name,
                             ffi_abi * abi)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_ffi_abi_mappings); i++)
  {
    const GumFFIABIMapping * m = &gum_ffi_abi_mappings[i];

    if (strcmp (m->name, name) == 0)
    {
      *abi = m->abi;
      return TRUE;
    }
  }

  return FALSE;
}

ffi_type *
gum_ffi_maybe_promote_variadic (ffi_type * type)
{
  if (type->size < sizeof (int))
  {
    if (type == &ffi_type_sint8 || type == &ffi_type_sint16)
      return &ffi_type_sint32;

    if (type == &ffi_type_uint8 || type == &ffi_type_uint16)
      return &ffi_type_uint32;
  }

  if (type == &ffi_type_float)
    return &ffi_type_double;

  return type;
}
