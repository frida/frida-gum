/* Optional process-local ABI, shared with Dopamine's memory_hooks.h. */

#ifndef __GUM_MEMORY_JAILBREAK_H__
#define __GUM_MEMORY_JAILBREAK_H__

#include "gummemory.h"

#include <mach/mach.h>

typedef struct _GumJailbreakMemoryHooks GumJailbreakMemoryHooks;

struct _GumJailbreakMemoryHooks
{
  guint32 version;
  guint32 size;
  kern_return_t (* patch_code) (void * address, const void * data, size_t size);
  kern_return_t (* protect) (mach_port_t task, mach_vm_address_t address,
      mach_vm_size_t size, boolean_t set_maximum, vm_prot_t protection);
};

G_GNUC_INTERNAL extern const GumJailbreakMemoryHooks * gum_jailbreak_memory_hooks;

#endif
