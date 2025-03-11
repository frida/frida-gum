/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsystemtap.h"

#include "gummodule-elf.h"

#include <string.h>

typedef struct _GumEmitProbesContext GumEmitProbesContext;
typedef struct _GumSdt GumSdt;

struct _GumEmitProbesContext
{
  GumFoundSystemTapProbeFunc func;
  gpointer user_data;

  GumElfModule * elf;
  GumAddress sdt_base;
};

struct _GumSdt
{
  gsize pc;
  gsize base;
  gsize semaphore;
};

static gboolean gum_find_sdt_base (const GumElfSectionDetails * section,
    gpointer user_data);
static gboolean gum_emit_probes_in_section (
    const GumElfSectionDetails * section, gpointer user_data);

void
gum_system_tap_enumerate_probes (GumModule * module,
                                 GumFoundSystemTapProbeFunc func,
                                 gpointer user_data)
{
  GumEmitProbesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.elf = _gum_native_module_get_elf_module (GUM_NATIVE_MODULE (module));
  ctx.sdt_base = 0;
  gum_elf_module_enumerate_sections (ctx.elf, gum_find_sdt_base, &ctx.sdt_base);

  gum_elf_module_enumerate_sections (ctx.elf, gum_emit_probes_in_section, &ctx);
}

static gboolean
gum_find_sdt_base (const GumElfSectionDetails * section,
                   gpointer user_data)
{
  GumAddress * base = user_data;

  if (section->type != GUM_ELF_SECTION_PROGBITS)
    return TRUE;

  if (strcmp (section->name, ".stapsdt.base") != 0)
    return TRUE;

  *base = section->address;

  return FALSE;
}

static gboolean
gum_emit_probes_in_section (const GumElfSectionDetails * section,
                            gpointer user_data)
{
  GumEmitProbesContext * ctx = user_data;
  gconstpointer elf_data;
  gsize elf_size;
  const GumElfNoteHeader * header, * end;

  if (section->type != GUM_ELF_SECTION_NOTE)
    return TRUE;

  elf_data = gum_elf_module_get_file_data (ctx->elf, &elf_size);

  header = (const GumElfNoteHeader *)
      ((const guint8 *) elf_data + section->offset);
  end = (const GumElfNoteHeader *)
      ((const guint8 *) header + section->size);

  while (header < end)
  {
    gchar * name;
    gboolean is_sdt;
    const GumSdt * sdt;
    gssize slide;
    GumSystemTapProbeDetails probe;

    name = g_strndup ((const gchar *) (header + 1), header->name_size);
    is_sdt = strcmp (name, "stapsdt") == 0 && header->type == 3;
    g_free (name);

    if (!is_sdt)
      break;

    sdt = (const GumSdt *)
        (((const guint8 *) (header + 1)) + header->name_size);

    slide = ctx->sdt_base - sdt->base;

    probe.provider = (const gchar *) (sdt + 1);
    probe.name = probe.provider + strlen (probe.provider) + 1;
    probe.args = probe.name + strlen (probe.name) + 1;
    probe.address = sdt->pc + slide;
    probe.semaphore = (sdt->semaphore != 0)
        ? sdt->semaphore + slide
        : 0;

    if (!ctx->func (&probe, ctx->user_data))
      return FALSE;

    header = GUM_ALIGN_POINTER (const GumElfNoteHeader *, (const guint8 *)
        (header + 1) + header->name_size + header->desc_size,
        4);
  }

  return TRUE;
}
