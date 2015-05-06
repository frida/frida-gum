/*
 * Copyright (C) 2010-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SCOPE_H__
#define __GUM_SCRIPT_SCOPE_H__

#include "gumscript.h"

#include <v8.h>

class ScriptScopeImpl;

class ScriptScope
{
public:
  ScriptScope (GumScript * parent);
  ~ScriptScope ();

  bool HasPendingException () const;

private:
  GumScript * parent;
  ScriptScopeImpl * impl;
};

#endif
