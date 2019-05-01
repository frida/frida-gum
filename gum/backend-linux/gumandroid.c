/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumandroid.h"

#include "arch-x86/gumx86writer.h"
#include "gum-init.h"
#include "gumlinux.h"

#include <dlfcn.h>
#include <sys/system_properties.h>

typedef struct _GumCopyLinkerModuleContext GumCopyLinkerModuleContext;

struct _GumCopyLinkerModuleContext
{
  GumAddress address_in_linker;
  GumModuleDetails * linker_module;
};

static gboolean gum_copy_linker_module (const GumModuleDetails * details,
    gpointer user_data);

static GumAndroidDlopenImpl gum_init_inner_dlopen (void);
static void * gum_call_inner_dlopen (const char * path, int mode);
static GumAndroidDlopenImpl gum_resolve_inner_dlopen (void);
# if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
static GumAndroidDlopenImpl gum_make_inner_dlopen_pic_thunk (
    GumAndroidDlopenImpl impl, gsize pic_value);
#endif

static guint gum_android_get_api_level (void);

static GumAndroidDlopenImpl gum_inner_dlopen = NULL;
static gpointer gum_inner_trusted_caller = NULL;

gboolean
gum_android_is_linker_module_name (const gchar * name)
{
  const gchar * linker_name = (sizeof (gpointer) == 4)
      ? "/system/bin/linker"
      : "/system/bin/linker64";
  return strcmp (name, linker_name) == 0;
}

GumModuleDetails *
gum_android_get_linker_module (void)
{
  GumCopyLinkerModuleContext ctx;

  ctx.address_in_linker = GUM_ADDRESS (dlsym (RTLD_DEFAULT, "dlopen"));
  ctx.linker_module = NULL;

  gum_linux_enumerate_modules_using_proc_maps (gum_copy_linker_module, &ctx);

  return ctx.linker_module;
}

static gboolean
gum_copy_linker_module (const GumModuleDetails * details,
                        gpointer user_data)
{
  GumCopyLinkerModuleContext * ctx = user_data;

  if (!GUM_MEMORY_RANGE_INCLUDES (details->range, ctx->address_in_linker))
    return TRUE;

  ctx->linker_module = gum_module_details_copy (details);

  return FALSE;
}

gboolean
gum_android_find_unrestricted_dlopen (GumGenericDlopenImpl * generic_dlopen,
                                      GumAndroidDlopenImpl * android_dlopen)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_init_inner_dlopen, NULL);

  if (once.retval == NULL)
    return FALSE;

  if (generic_dlopen != NULL)
    *generic_dlopen = gum_call_inner_dlopen;

  if (android_dlopen != NULL)
    *android_dlopen = once.retval;

  return TRUE;
}

static GumAndroidDlopenImpl
gum_init_inner_dlopen (void)
{
  void * libc;

  gum_inner_dlopen = gum_resolve_inner_dlopen ();
  if (gum_inner_dlopen == NULL)
    return NULL;

  libc = dlopen ("libc.so", RTLD_LAZY);
  gum_inner_trusted_caller = dlsym (libc, "open");
  dlclose (libc);

  return gum_inner_dlopen;
}

static void *
gum_call_inner_dlopen (const char * path,
                       int mode)
{
  return gum_inner_dlopen (path, mode, gum_inner_trusted_caller);
}

static GumAndroidDlopenImpl
gum_resolve_inner_dlopen (void)
{
  GumAndroidDlopenImpl impl;
  csh capstone;
  cs_insn * insn;
  size_t count;

  if (gum_android_get_api_level () < 26)
    return NULL;

  impl = NULL;
  insn = NULL;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  cs_open (CS_ARCH_X86, CS_MODE_32, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  count = cs_disasm (capstone, (const uint8_t *) dlopen, 48,
      GPOINTER_TO_SIZE (dlopen), 18, &insn);

  {
    gsize pic_value = 0;
    size_t i;

    for (i = 0; i != count; i++)
    {
      const cs_insn * cur = &insn[i];
      const cs_x86_op * op1 = &cur->detail->x86.operands[0];
      const cs_x86_op * op2 = &cur->detail->x86.operands[1];

      switch (cur->id)
      {
        case X86_INS_CALL:
          if (op1->type == X86_OP_IMM)
            impl = GSIZE_TO_POINTER (op1->imm);
          break;
        case X86_INS_POP:
          if (op1->reg == X86_REG_EBX && pic_value == 0)
            pic_value = cur->address;
          break;
        case X86_INS_ADD:
          if (op1->reg == X86_REG_EBX)
            pic_value += op2->imm;
          break;
      }
    }

    if (pic_value != 0)
      impl = gum_make_inner_dlopen_pic_thunk (impl, pic_value);
  }
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  cs_open (CS_ARCH_X86, CS_MODE_64, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  count = cs_disasm (capstone, (const uint8_t *) dlopen, 16,
      GPOINTER_TO_SIZE (dlopen), 4, &insn);

  {
    size_t i;

    for (i = 0; i != count; i++)
    {
      const cs_insn * cur = &insn[i];
      const cs_x86_op * op = &cur->detail->x86.operands[0];

      if (cur->id == X86_INS_JMP)
      {
        if (op->type == X86_OP_IMM)
          impl = GSIZE_TO_POINTER (op->imm);
        break;
      }
    }
  }
#elif defined (HAVE_ARM)
  cs_open (CS_ARCH_ARM, CS_MODE_THUMB, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  {
    gsize dlopen_address = GPOINTER_TO_SIZE (dlopen) & (gsize) ~1;

    count = cs_disasm (capstone, GSIZE_TO_POINTER (dlopen_address), 10,
        dlopen_address, 4, &insn);
  }

  if (count == 4 &&
      insn[0].id == ARM_INS_PUSH &&
      (insn[1].id == ARM_INS_MOV &&
          insn[1].detail->arm.operands[0].reg == ARM_REG_R2 &&
          insn[1].detail->arm.operands[1].reg == ARM_REG_LR) &&
      (insn[2].id == ARM_INS_BL || insn[2].id == ARM_INS_BLX) &&
      insn[3].id == ARM_INS_POP)
  {
    gsize thumb_bit = (insn[2].id == ARM_INS_BL) ? 1 : 0;
    impl = GSIZE_TO_POINTER (insn[2].detail->arm.operands[0].imm | thumb_bit);
  }
#elif defined (HAVE_ARM64)
  cs_open (CS_ARCH_ARM64, CS_MODE_ARM, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  count = cs_disasm (capstone, (const uint8_t *) dlopen, 6 * sizeof (guint32),
      GPOINTER_TO_SIZE (dlopen), 6, &insn);

  if (count == 6 &&
      insn[0].id == ARM64_INS_STP &&
      insn[1].id == ARM64_INS_MOV &&
      (insn[2].id == ARM64_INS_MOV &&
          insn[2].detail->arm64.operands[0].reg == ARM64_REG_X2 &&
          insn[2].detail->arm64.operands[1].reg == ARM64_REG_LR) &&
      insn[3].id == ARM64_INS_BL &&
      insn[4].id == ARM64_INS_LDP &&
      insn[5].id == ARM64_INS_RET)
  {
    impl = GSIZE_TO_POINTER (insn[3].detail->arm64.operands[0].imm);
  }
#else
# error Unsupported architecture
#endif

  cs_free (insn, count);

  cs_close (&capstone);

  return impl;
}

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4

static void gum_free_inner_dlopen_pic_thunk (void);

static gpointer gum_inner_dlopen_pic_thunk = NULL;

static GumAndroidDlopenImpl
gum_make_inner_dlopen_pic_thunk (GumAndroidDlopenImpl impl,
                                 gsize pic_value)
{
  gpointer thunk;
  gsize page_size;
  GumX86Writer cw;

  g_assert (gum_inner_dlopen_pic_thunk == NULL);

  page_size = gum_query_page_size ();
  thunk = gum_memory_allocate (NULL, page_size, page_size, GUM_PAGE_RW);

  gum_x86_writer_init (&cw, thunk);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EBX, pic_value);
  gum_x86_writer_put_jmp_address (&cw, GUM_ADDRESS (impl));
  gum_x86_writer_clear (&cw);

  gum_memory_mark_code (thunk, page_size);

  gum_inner_dlopen_pic_thunk = thunk;
  _gum_register_destructor (gum_free_inner_dlopen_pic_thunk);

  return thunk;
}

static void
gum_free_inner_dlopen_pic_thunk (void)
{
  gum_memory_free (gum_inner_dlopen_pic_thunk, gum_query_page_size ());
}

#endif

static guint
gum_android_get_api_level (void)
{
  gchar sdk_version[PROP_VALUE_MAX];

  sdk_version[0] = '\0';
  __system_property_get ("ro.build.version.sdk", sdk_version);

  return atoi (sdk_version);
}
