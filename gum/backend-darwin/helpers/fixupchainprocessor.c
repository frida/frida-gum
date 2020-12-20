/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "fixupchainprocessor.h"

#include <ptrauth.h>
#include <stdint.h>

typedef struct _GumChainedStartsInImage GumChainedStartsInImage;
typedef struct _GumChainedStartsInSegment GumChainedStartsInSegment;

typedef struct _GumChainedPtrArm64eRebase GumChainedPtrArm64eRebase;
typedef struct _GumChainedPtrArm64eBind GumChainedPtrArm64eBind;
typedef struct _GumChainedPtrArm64eAuthRebase GumChainedPtrArm64eAuthRebase;
typedef struct _GumChainedPtrArm64eAuthBind GumChainedPtrArm64eAuthBind;

typedef uint32_t GumChainedImportFormat;
typedef uint32_t GumChainedSymbolFormat;

typedef struct _GumChainedImport GumChainedImport;
typedef struct _GumChainedImportAddend GumChainedImportAddend;
typedef struct _GumChainedImportAddend64 GumChainedImportAddend64;

struct _GumChainedFixupsHeader
{
  uint32_t fixups_version;
  uint32_t starts_offset;
  uint32_t imports_offset;
  uint32_t symbols_offset;
  uint32_t imports_count;
  GumChainedImportFormat imports_format;
  GumChainedSymbolFormat symbols_format;
};

struct _GumChainedStartsInImage
{
  uint32_t seg_count;
  uint32_t seg_info_offset[1];
};

struct _GumChainedStartsInSegment
{
  uint32_t size;
  uint16_t page_size;
  uint16_t pointer_format;
  uint64_t segment_offset;
  uint32_t max_valid_pointer;
  uint16_t page_count;
  uint16_t page_start[1];
};

enum _GumChainedPtrStart
{
  GUM_CHAINED_PTR_START_NONE  = 0xffff,
  GUM_CHAINED_PTR_START_MULTI = 0x8000,
  GUM_CHAINED_PTR_START_LAST  = 0x8000,
};

struct _GumChainedPtrArm64eRebase
{
  uint64_t target : 43,
           high8  :  8,
           next   : 11,
           bind   :  1,
           auth   :  1;
};

struct _GumChainedPtrArm64eBind
{
  uint64_t ordinal : 16,
           zero    : 16,
           addend  : 19,
           next    : 11,
           bind    :  1,
           auth    :  1;
};

struct _GumChainedPtrArm64eAuthRebase
{
  uint64_t target    : 32,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

struct _GumChainedPtrArm64eAuthBind
{
  uint64_t ordinal   : 16,
           zero      : 16,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

enum _GumChainedImportFormat
{
  GUM_CHAINED_IMPORT          = 1,
  GUM_CHAINED_IMPORT_ADDEND   = 2,
  GUM_CHAINED_IMPORT_ADDEND64 = 3,
};

enum _GumChainedSymbolFormat
{
  GUM_CHAINED_SYMBOL_UNCOMPRESSED,
  GUM_CHAINED_SYMBOL_ZLIB_COMPRESSED,
};

struct _GumChainedImport
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
};

struct _GumChainedImportAddend
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
  int32_t  addend;
};

struct _GumChainedImportAddend64
{
  uint64_t lib_ordinal : 16,
           weak_import :  1,
           reserved    : 15,
           name_offset : 32;
  uint64_t addend;
};

static void * gum_resolve_import (void ** dylib_handles, int dylib_ordinal,
    const char * symbol_strings, uint32_t symbol_offset,
    const GumFixupChainProcessorApi * api);
static void * gum_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity,
    bool use_address_diversity, void * address_of_ptr);
static const char * gum_symbol_name_from_darwin (const char * name);

void
gum_process_chained_fixups (const GumChainedFixupsHeader * fixups_header,
                            struct mach_header_64 * mach_header,
                            size_t preferred_base_address,
                            const GumFixupChainProcessorApi * api)
{
  mach_port_t task;
  mach_vm_address_t slab_start;
  size_t slab_size;
  void * slab_cursor;
  void ** dylib_handles;
  size_t dylib_count;
  const void * command;
  uint32_t command_index;
  void ** bound_pointers;
  size_t bound_count, i;
  const char * symbols;
  const GumChainedStartsInImage * image_starts;
  ssize_t slide;
  uint32_t seg_index;

  task = api->_mach_task_self ();

  slab_start = 0;
  slab_size = 64 * 1024;
  api->mach_vm_allocate (task, &slab_start, slab_size, VM_FLAGS_ANYWHERE);
  slab_cursor = (void *) slab_start;

  dylib_handles = slab_cursor;
  dylib_count = 0;

  command = mach_header + 1;
  for (command_index = 0; command_index != mach_header->ncmds; command_index++)
  {
    const struct load_command * lc = command;

    switch (lc->cmd)
    {
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      {
        const struct dylib_command * dc = command;
        const char * name = command + dc->dylib.name.offset;

        dylib_handles[dylib_count++] =
            api->dlopen (name, RTLD_LAZY | RTLD_GLOBAL);

        break;
      }
      default:
        break;
    }

    command += lc->cmdsize;
  }

  slab_cursor += dylib_count * sizeof (void *);

  bound_pointers = slab_cursor;
  bound_count = fixups_header->imports_count;
  slab_cursor += bound_count * sizeof (void *);

  symbols = (const char *) fixups_header + fixups_header->symbols_offset;

  switch (fixups_header->imports_format)
  {
    case GUM_CHAINED_IMPORT:
    {
      const GumChainedImport * imports =
          ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const GumChainedImport * import = &imports[i];

        bound_pointers[i] = gum_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
      }

      break;
    }
    case GUM_CHAINED_IMPORT_ADDEND:
    {
      const GumChainedImportAddend * imports =
          ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const GumChainedImportAddend * import = &imports[i];

        bound_pointers[i] = gum_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
    case GUM_CHAINED_IMPORT_ADDEND64:
    {
      const GumChainedImportAddend64 * imports =
          ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const GumChainedImportAddend64 * import = &imports[i];

        bound_pointers[i] = gum_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
  }

  image_starts = (const GumChainedStartsInImage *)
      ((const void *) fixups_header + fixups_header->starts_offset);
  slide = (void *) mach_header - (void *) preferred_base_address;

  for (seg_index = 0; seg_index != image_starts->seg_count; seg_index++)
  {
    const uint32_t seg_offset = image_starts->seg_info_offset[seg_index];
    const GumChainedStartsInSegment * seg_starts;
    uint16_t page_index;

    if (seg_offset == 0)
      continue;

    seg_starts = (const GumChainedStartsInSegment *)
        ((const void *) image_starts + seg_offset);

    for (page_index = 0; page_index != seg_starts->page_count; page_index++)
    {
      uint16_t start;
      void * cursor;

      start = seg_starts->page_start[page_index];
      if (start == GUM_CHAINED_PTR_START_NONE)
        continue;
      /* Ignoring MULTI for now as it only applies to 32-bit formats. */

      cursor = (void *) mach_header + seg_starts->segment_offset +
          (page_index * seg_starts->page_size) +
          start;

      while (TRUE)
      {
        uint64_t * slot = cursor;
        size_t delta;
        const size_t stride = sizeof (uint64_t);

        switch (*slot >> 62)
        {
          case 0b00:
          {
            GumChainedPtrArm64eRebase * item = cursor;
            uint64_t top_8_bits, bottom_43_bits, sign_bits;
            bool sign_bit_set;

            delta = item->next;

            top_8_bits = (uint64_t) item->high8 << (64 - 8);
            bottom_43_bits = item->target;

            sign_bit_set = (bottom_43_bits >> 42) & 1;
            if (sign_bit_set)
              sign_bits = 0x00fff80000000000UL;
            else
              sign_bits = 0;

            *slot = (top_8_bits | sign_bits | bottom_43_bits) + slide;

            break;
          }
          case 0b01:
          {
            GumChainedPtrArm64eBind * item = cursor;

            delta = item->next;

            *slot = (uint64_t) (bound_pointers[item->ordinal] + item->addend);

            break;
          }
          case 0b10:
          {
            GumChainedPtrArm64eAuthRebase * item = cursor;

            delta = item->next;

            *slot = (uint64_t) gum_sign_pointer (
                (void *) (preferred_base_address + item->target + slide),
                item->key, item->diversity, item->addr_div, slot);

            break;
          }
          case 0b11:
          {
            GumChainedPtrArm64eAuthBind * item = cursor;

            delta = item->next;

            *slot = (uint64_t) gum_sign_pointer (bound_pointers[item->ordinal],
                item->key, item->diversity, item->addr_div, slot);

            break;
          }
        }

        if (delta == 0)
          break;

        cursor += delta * stride;
      }
    }
  }

  api->mach_vm_deallocate (task, slab_start, slab_size);
}

static void *
gum_resolve_import (void ** dylib_handles,
                    int dylib_ordinal,
                    const char * symbol_strings,
                    uint32_t symbol_offset,
                    const GumFixupChainProcessorApi * api)
{
  void * result;
  const char * raw_name, * name;

  if (dylib_ordinal <= 0)
    return NULL; /* Placeholder if we ever need to support this. */

  raw_name = symbol_strings + symbol_offset;
  name = gum_symbol_name_from_darwin (raw_name);

  result = api->dlsym (dylib_handles[dylib_ordinal - 1], name);

  result = ptrauth_strip (result, ptrauth_key_asia);

  return result;
}

static void *
gum_sign_pointer (void * ptr,
                  uint8_t key,
                  uintptr_t diversity,
                  bool use_address_diversity,
                  void * address_of_ptr)
{
  void * p = ptr;
  uintptr_t d = diversity;

  if (use_address_diversity)
    d = ptrauth_blend_discriminator (address_of_ptr, d);

  switch (key)
  {
    case ptrauth_key_asia:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asia, d);
      break;
    case ptrauth_key_asib:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asib, d);
      break;
    case ptrauth_key_asda:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asda, d);
      break;
    case ptrauth_key_asdb:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asdb, d);
      break;
  }

  return p;
}

static const char *
gum_symbol_name_from_darwin (const char * name)
{
  return (name[0] == '_') ? name + 1 : name;
}
