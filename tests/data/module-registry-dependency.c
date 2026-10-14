/*
 * Copyright (C) 2026 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifdef _WIN32
__declspec (dllexport)
#endif
int
gum_module_registry_dependency_function (void)
{
  return 1337;
}
