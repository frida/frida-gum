/*
 * Copyright (C) 2009-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gumwindows.h"

#include <intrin.h>
#include <psapi.h>
#include <tlhelp32.h>

typedef struct _GumFindExportContext GumFindExportContext;

struct _GumFindExportContext
{
  const gchar * symbol_name;
  GumAddress result;
};

static gboolean gum_windows_get_thread_details (DWORD thread_id,
    GumThreadDetails * details);
static gboolean gum_process_enumerate_heap_ranges (HANDLE heap,
    GumFoundMallocRangeFunc func, gpointer user_data);
static gboolean gum_store_address_if_module_has_export (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_store_address_if_export_name_matches (
    const GumExportDetails * details, gpointer user_data);
static HMODULE get_module_handle_utf8 (const gchar * module_name);

gboolean
gum_process_is_debugger_attached (void)
{
  return IsDebuggerPresent ();
}

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4

GumThreadId
gum_process_get_current_thread_id (void)
{
  return __readfsdword (0x24);
}

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8

GumThreadId
gum_process_get_current_thread_id (void)
{
  return __readgsdword (0x48);
}

#else

GumThreadId
gum_process_get_current_thread_id (void)
{
  return GetCurrentThreadId ();
}

#endif

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  gboolean success = FALSE;
  HANDLE thread;
  __declspec (align (64)) CONTEXT context = { 0, };
  GumCpuContext cpu_context;

  thread = OpenThread (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
      THREAD_SUSPEND_RESUME, FALSE, thread_id);
  if (thread == NULL)
    goto beach;

  if (SuspendThread (thread) == (DWORD) -1)
    goto beach;

  context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  if (!GetThreadContext (thread, &context))
    goto beach;

  gum_windows_parse_context (&context, &cpu_context);
  func (thread_id, &cpu_context, user_data);
  gum_windows_unparse_context (&cpu_context, &context);

  if (!SetThreadContext (thread, &context))
  {
    ResumeThread (thread);
    goto beach;
  }

  success = ResumeThread (thread) != (DWORD) -1;

beach:
  if (thread != NULL)
    CloseHandle (thread);

  return success;
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  DWORD this_process_id;
  HANDLE snapshot;
  THREADENTRY32 entry;

  this_process_id = GetCurrentProcessId ();

  snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    goto beach;

  entry.dwSize = sizeof (entry);
  if (!Thread32First (snapshot, &entry))
    goto beach;

  do
  {
    if (RTL_CONTAINS_FIELD (&entry, entry.dwSize, th32OwnerProcessID) &&
        entry.th32OwnerProcessID == this_process_id)
    {
      GumThreadDetails details;

      if (gum_windows_get_thread_details (entry.th32ThreadID, &details))
      {
        if (!func (&details, user_data))
          break;
      }
    }

    entry.dwSize = sizeof (entry);
  }
  while (Thread32Next (snapshot, &entry));

beach:
  if (snapshot != INVALID_HANDLE_VALUE)
    CloseHandle (snapshot);
}

static gboolean
gum_windows_get_thread_details (DWORD thread_id,
                                GumThreadDetails * details)
{
  gboolean success = FALSE;
  __declspec (align (64)) CONTEXT context = { 0, };

  details->id = thread_id;

  if (thread_id == GetCurrentThreadId ())
  {
    details->state = GUM_THREAD_RUNNING;

    RtlCaptureContext (&context);
    gum_windows_parse_context (&context, &details->cpu_context);

    success = TRUE;
  }
  else
  {
    HANDLE thread;

    thread = OpenThread (THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE,
        thread_id);
    if (thread != NULL)
    {
      DWORD previous_suspend_count;

      previous_suspend_count = SuspendThread (thread);
      if (previous_suspend_count != (DWORD) -1)
      {
        if (previous_suspend_count == 0)
          details->state = GUM_THREAD_RUNNING;
        else
          details->state = GUM_THREAD_STOPPED;

        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext (thread, &context))
        {
          gum_windows_parse_context (&context, &details->cpu_context);
          success = TRUE;
        }

        ResumeThread (thread);
      }

      CloseHandle (thread);
    }
  }

  return success;
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  HANDLE this_process;
  HMODULE first_module;
  DWORD modules_size = 0;
  HMODULE * modules = NULL;
  guint mod_idx;

  this_process = GetCurrentProcess ();

  if (!EnumProcessModules (this_process, &first_module, sizeof (first_module),
      &modules_size))
  {
    goto beach;
  }

  modules = (HMODULE *) g_malloc (modules_size);

  if (!EnumProcessModules (this_process, modules, modules_size, &modules_size))
  {
    goto beach;
  }

  for (mod_idx = 0; mod_idx != modules_size / sizeof (HMODULE); mod_idx++)
  {
    MODULEINFO mi;
    WCHAR module_path_utf16[MAX_PATH];
    gchar * module_path, * module_name;
    GumMemoryRange range;
    GumModuleDetails details;
    gboolean carry_on;

    if (!GetModuleInformation (this_process, modules[mod_idx], &mi,
        sizeof (mi)))
    {
      continue;
    }

    GetModuleFileNameW (modules[mod_idx], module_path_utf16, MAX_PATH);
    module_path_utf16[MAX_PATH - 1] = '\0';
    module_path = g_utf16_to_utf8 ((const gunichar2 *) module_path_utf16, -1,
        NULL, NULL, NULL);
    module_name = strrchr (module_path, '\\') + 1;

    range.base_address = GUM_ADDRESS (mi.lpBaseOfDll);
    range.size = mi.SizeOfImage;

    details.name = module_name;
    details.range = &range;
    details.path = module_path;

    carry_on = func (&details, user_data);

    g_free (module_path);

    if (!carry_on)
      break;
  }

beach:
  g_free (modules);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  guint8 * cur_base_address;

  cur_base_address = NULL;

  while (TRUE)
  {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret;

    ret = VirtualQuery (cur_base_address, &mbi, sizeof (mbi));
    if (ret == 0)
      break;

    if (mbi.Protect != 0 && (mbi.Protect & PAGE_GUARD) == 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_windows (mbi.Protect);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;

        range.base_address = GUM_ADDRESS (cur_base_address);
        range.size = mbi.RegionSize;

        details.range = &range;
        details.prot = cur_prot;
        details.file = NULL; /* TODO */

        if (!func (&details, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  HANDLE process_heap;
  DWORD num_heaps;
  HANDLE * heaps;
  DWORD num_heaps_after;
  DWORD i;

  process_heap = GetProcessHeap ();
  if (!gum_process_enumerate_heap_ranges (process_heap, func, user_data))
    return;

  num_heaps = GetProcessHeaps (0, NULL);
  if (num_heaps == 0)
    return;
  heaps = HeapAlloc (process_heap, 0, num_heaps * sizeof (HANDLE));
  if (heaps == NULL)
    return;
  num_heaps_after = GetProcessHeaps (num_heaps, heaps);

  num_heaps = MIN (num_heaps_after, num_heaps);
  for (i = 0; i != num_heaps; i++)
  {
    if (heaps[i] != process_heap)
    {
      if (!gum_process_enumerate_heap_ranges (process_heap, func, user_data))
        break;
    }
  }

  HeapFree (process_heap, 0, heaps);
}

static gboolean
gum_process_enumerate_heap_ranges (HANDLE heap,
                                   GumFoundMallocRangeFunc func,
                                   gpointer user_data)
{
  gboolean carry_on;
  gboolean locked_heap;
  GumMemoryRange range;
  GumMallocRangeDetails details;
  PROCESS_HEAP_ENTRY entry;

  /* HeapLock may fail but it doesn't seem to have any real consequences... */
  locked_heap = HeapLock (heap);

  details.range = &range;
  carry_on = TRUE;
  entry.lpData = NULL;
  while (carry_on && HeapWalk (heap, &entry))
  {
    if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0)
    {
      range.base_address = GUM_ADDRESS (entry.lpData);
      range.size = entry.cbData;
      carry_on = func (&details, user_data);
    }
  }

  if (locked_heap)
    HeapUnlock (heap);

  return carry_on;
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  /* Not implemented */
  return 0;
}

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4

gint
gum_thread_get_system_error (void)
{
  gint32 * teb = (gint32 *) __readfsdword (0x18);
  return teb[13];
}

void
gum_thread_set_system_error (gint value)
{
  gint32 * teb = (gint32 *) __readfsdword (0x18);
  if (teb[13] != value)
    teb[13] = value;
}

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8

gint
gum_thread_get_system_error (void)
{
  gint32 * teb = (gint32 *) __readgsqword (0x30);
  return teb[26];
}

void
gum_thread_set_system_error (gint value)
{
  gint32 * teb = (gint32 *) __readgsqword (0x30);
  if (teb[26] != value)
    teb[26] = value;
}

#else

gint
gum_thread_get_system_error (void)
{
  return (gint) GetLastError ();
}

void
gum_thread_set_system_error (gint value)
{
  SetLastError ((DWORD) value);
}

#endif

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  HMODULE module;

  module = get_module_handle_utf8 (module_name);

  return module != NULL;
}

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  gpointer module;
  const guint8 * mod_base;
  const IMAGE_DOS_HEADER * dos_hdr;
  const IMAGE_NT_HEADERS * nt_hdrs;
  const IMAGE_DATA_DIRECTORY * entry;
  const IMAGE_IMPORT_DESCRIPTOR * desc;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  mod_base = (const guint8 *) module;
  dos_hdr = (const IMAGE_DOS_HEADER *) module;
  nt_hdrs = (const IMAGE_NT_HEADERS *) &mod_base[dos_hdr->e_lfanew];
  entry = &nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  desc = (const IMAGE_IMPORT_DESCRIPTOR *) (mod_base + entry->VirtualAddress);

  for (; desc->Characteristics != 0; desc++)
  {
    GumImportDetails details;
    const IMAGE_THUNK_DATA * thunk_data;

    if (desc->OriginalFirstThunk == 0)
      continue;

    details.type = GUM_IMPORT_FUNCTION; /* FIXME: how can we tell? */
    details.name = NULL;
    details.module = (const gchar *) (mod_base + desc->Name);
    details.address = 0;
    details.slot = 0; /* TODO */

    thunk_data = (const IMAGE_THUNK_DATA *)
        (mod_base + desc->OriginalFirstThunk);
    for (; thunk_data->u1.AddressOfData != 0; thunk_data++)
    {
      if ((thunk_data->u1.AddressOfData & IMAGE_ORDINAL_FLAG) != 0)
        continue; /* FIXME: we ignore imports by ordinal */

      details.name = (const gchar *)
          (mod_base + thunk_data->u1.AddressOfData + 2);
      details.address =
          gum_module_find_export_by_name (details.module, details.name);

      if (!func (&details, user_data))
        return;
    }
  }
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  gpointer module;
  const guint8 * mod_base;
  const IMAGE_DOS_HEADER * dos_hdr;
  const IMAGE_NT_HEADERS * nt_hdrs;
  const IMAGE_DATA_DIRECTORY * entry;
  const IMAGE_EXPORT_DIRECTORY * exp;
  const guint8 * exp_begin, * exp_end;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  mod_base = (const guint8 *) module;
  dos_hdr = (const IMAGE_DOS_HEADER *) module;
  nt_hdrs = (const IMAGE_NT_HEADERS *) &mod_base[dos_hdr->e_lfanew];
  entry = &nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  exp = (const IMAGE_EXPORT_DIRECTORY *)(mod_base + entry->VirtualAddress);
  exp_begin = mod_base + entry->VirtualAddress;
  exp_end = exp_begin + entry->Size - 1;

  if (exp->AddressOfNames != 0)
  {
    const DWORD * name_rvas, * func_rvas;
    const WORD * ord_rvas;
    DWORD index;

    name_rvas = (const DWORD *) &mod_base[exp->AddressOfNames];
    ord_rvas = (const WORD *) &mod_base[exp->AddressOfNameOrdinals];
    func_rvas = (const DWORD *) &mod_base[exp->AddressOfFunctions];

    for (index = 0; index < exp->NumberOfNames; index++)
    {
      DWORD func_rva;
      const guint8 * func_address;

      func_rva = func_rvas[ord_rvas[index]];
      func_address = &mod_base[func_rva];
      if (func_address < exp_begin || func_address > exp_end)
      {
        GumExportDetails details;

        details.type = GUM_EXPORT_FUNCTION; /* TODO: data exports */
        details.name = (const gchar *) &mod_base[name_rvas[index]];
        details.address = GUM_ADDRESS (func_address);

        if (!func (&details, user_data))
          return;
      }
    }
  }
}

void
gum_module_enumerate_symbols (const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  /* TODO: implement */
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  HANDLE this_process = GetCurrentProcess ();
  HMODULE module;
  MODULEINFO mi;
  guint8 * cur_base_address, * end_address;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  if (!GetModuleInformation (this_process, module, &mi, sizeof (mi)))
    return;

  cur_base_address = (guint8 *) mi.lpBaseOfDll;
  end_address = (guint8 *) mi.lpBaseOfDll + mi.SizeOfImage;

  do
  {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret;

    ret = VirtualQuery (cur_base_address, &mbi, sizeof (mbi));
    g_assert (ret != 0);

    if (mbi.Protect != 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_windows (mbi.Protect);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;

        range.base_address = GUM_ADDRESS (cur_base_address);
        range.size = mbi.RegionSize;

        details.range = &range;
        details.prot = cur_prot;
        details.file = NULL; /* TODO */

        if (!func (&details, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
  while (cur_base_address < end_address);
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  return GUM_ADDRESS (get_module_handle_utf8 (module_name));
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  if (module_name == NULL)
  {
    GumFindExportContext ctx;

    ctx.symbol_name = symbol_name;
    ctx.result = 0;

    gum_process_enumerate_modules (gum_store_address_if_module_has_export,
        &ctx);

    return ctx.result;
  }
  else
  {
    HMODULE module;

    module = get_module_handle_utf8 (module_name);
    if (module == NULL)
      return 0;

    return GUM_ADDRESS (GetProcAddress (module, symbol_name));
  }
}

static gboolean
gum_store_address_if_module_has_export (const GumModuleDetails * details,
                                        gpointer user_data)
{
  GumFindExportContext * ctx = user_data;

  gum_module_enumerate_exports (details->path,
      gum_store_address_if_export_name_matches, ctx);

  return ctx->result == 0;
}

static gboolean
gum_store_address_if_export_name_matches (const GumExportDetails * details,
                                          gpointer user_data)
{
  GumFindExportContext * ctx = user_data;

  if (strcmp (details->name, ctx->symbol_name) == 0)
  {
    ctx->result = details->address;
    return FALSE;
  }

  return TRUE;
}

static HMODULE
get_module_handle_utf8 (const gchar * module_name)
{
  HMODULE module;
  gunichar2 * wide_name;

  wide_name = g_utf8_to_utf16 (module_name, -1, NULL, NULL, NULL);
  module = GetModuleHandleW ((LPCWSTR) wide_name);
  g_free (wide_name);

  return module;
}

void
gum_windows_parse_context (const CONTEXT * context,
                           GumCpuContext * cpu_context)
{
#if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = context->Eip;

  cpu_context->edi = context->Edi;
  cpu_context->esi = context->Esi;
  cpu_context->ebp = context->Ebp;
  cpu_context->esp = context->Esp;
  cpu_context->ebx = context->Ebx;
  cpu_context->edx = context->Edx;
  cpu_context->ecx = context->Ecx;
  cpu_context->eax = context->Eax;
#else
  cpu_context->rip = context->Rip;

  cpu_context->r15 = context->R15;
  cpu_context->r14 = context->R14;
  cpu_context->r13 = context->R13;
  cpu_context->r12 = context->R12;
  cpu_context->r11 = context->R11;
  cpu_context->r10 = context->R10;
  cpu_context->r9 = context->R9;
  cpu_context->r8 = context->R8;

  cpu_context->rdi = context->Rdi;
  cpu_context->rsi = context->Rsi;
  cpu_context->rbp = context->Rbp;
  cpu_context->rsp = context->Rsp;
  cpu_context->rbx = context->Rbx;
  cpu_context->rdx = context->Rdx;
  cpu_context->rcx = context->Rcx;
  cpu_context->rax = context->Rax;
#endif
}

void
gum_windows_unparse_context (const GumCpuContext * cpu_context,
                             CONTEXT * context)
{
#if GLIB_SIZEOF_VOID_P == 4
  context->Eip = cpu_context->eip;

  context->Edi = cpu_context->edi;
  context->Esi = cpu_context->esi;
  context->Ebp = cpu_context->ebp;
  context->Esp = cpu_context->esp;
  context->Ebx = cpu_context->ebx;
  context->Edx = cpu_context->edx;
  context->Ecx = cpu_context->ecx;
  context->Eax = cpu_context->eax;
#else
  context->Rip = cpu_context->rip;

  context->R15 = cpu_context->r15;
  context->R14 = cpu_context->r14;
  context->R13 = cpu_context->r13;
  context->R12 = cpu_context->r12;
  context->R11 = cpu_context->r11;
  context->R10 = cpu_context->r10;
  context->R9 = cpu_context->r9;
  context->R8 = cpu_context->r8;

  context->Rdi = cpu_context->rdi;
  context->Rsi = cpu_context->rsi;
  context->Rbp = cpu_context->rbp;
  context->Rsp = cpu_context->rsp;
  context->Rbx = cpu_context->rbx;
  context->Rdx = cpu_context->rdx;
  context->Rcx = cpu_context->rcx;
  context->Rax = cpu_context->rax;
#endif
}
