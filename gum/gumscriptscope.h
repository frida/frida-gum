/*
 * Copyright (C) 2010-2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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

private:
  GumScript * parent;
  ScriptScopeImpl * impl;
};

#endif
