/*
 * Copyright (C) 2021 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_DARWIN_PRIV_H__
#define __GUM_PROCESS_DARWIN_PRIV_H__

#include <glib.h>

#define DYLD_INFO_COUNT 5
#define DYLD_INFO_LEGACY_COUNT 1
#define DYLD_INFO_32_COUNT 3
#define DYLD_INFO_64_COUNT 5

typedef union _DyldInfo DyldInfo;
typedef struct _DyldInfoLegacy DyldInfoLegacy;
typedef struct _DyldInfo32 DyldInfo32;
typedef struct _DyldInfo64 DyldInfo64;

struct _DyldInfoLegacy
{
  guint32 all_image_info_addr;
};

struct _DyldInfo32
{
  guint32 all_image_info_addr;
  guint32 all_image_info_size;
  gint32 all_image_info_format;
};

struct _DyldInfo64
{
  guint64 all_image_info_addr;
  guint64 all_image_info_size;
  gint32 all_image_info_format;
};

union _DyldInfo
{
  DyldInfoLegacy info_legacy;
  DyldInfo32 info_32;
  DyldInfo64 info_64;
};

#endif
