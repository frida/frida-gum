/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-priv.h"

#include "gum/gumbarebone.h"

void
_gum_module_registry_activate (GumModuleRegistry * self)
{
  gum_barebone_on_registry_activating (self);
}

void
_gum_module_registry_deactivate (GumModuleRegistry * self)
{
}

G_GNUC_WEAK void
gum_barebone_on_registry_activating (GumModuleRegistry * registry)
{
}

void
gum_barebone_register_module (GumModuleRegistry * registry,
                              GumModule * module)
{
  _gum_module_registry_register (registry, module);
}
