/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_FIXUP_CHAIN_PROCESSOR_H__
#define __GUM_FIXUP_CHAIN_PROCESSOR_H__

#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach/mach.h>

typedef struct _GumChainedFixupsHeader GumChainedFixupsHeader;
typedef struct _GumFixupChainProcessorApi GumFixupChainProcessorApi;

struct _GumFixupChainProcessorApi
{
  mach_port_t (* _mach_task_self) (void);
  kern_return_t (* mach_vm_allocate) (vm_map_t target,
      mach_vm_address_t * address, mach_vm_size_t size, int flags);
  kern_return_t (* mach_vm_deallocate) (vm_map_t target,
      mach_vm_address_t address, mach_vm_size_t size);
  void * (* dlopen) (const char * path, int mode);
  void * (* dlsym) (void * handle, const char * symbol);
  int (* strcmp) (const char * s1, const char * s2);
};

void gum_process_chained_fixups (const GumChainedFixupsHeader * fixups_header,
    struct mach_header_64 * mach_header, size_t preferred_base_address,
    const GumFixupChainProcessorApi * api);

#endif
