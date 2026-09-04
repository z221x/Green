/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * green_hook memory backend — gum's Linux backend replaced by the green
 * shadow pager at the source level.
 *
 * The functions below carry the exact gum names and prototypes used by the
 * vendored frida-gum sources (gummemory.h / gummemory-priv.h); they are the
 * porting seam gum itself provides (gummemory-linux.c plays the same role
 * upstream).  Hook-time semantics:
 *
 *   gum_memory_patch_code()      snapshot original page → apply() writes the
 *                                redirect (emitted by the real
 *                                GumArm64Writer) → commit via an authenticated
 *                                direct KPM shadow prctl.  Execution
 *                                observes the patch, reads observe the
 *                                original page.
 *   gum_memory_read()            process_vm_readv; the shadow GUP hook
 *                                already answers shadowed pages with the
 *                                original PFN.
 *   gum_memory_write()           shadow patch (never mprotect+memcpy on RX).
 *   gum_try_mprotect()/gum_mprotect()  native mprotect — only reached for
 *                                gum's own allocations (code allocator), not
 *                                for hooked targets.
 *   gum_clear_cache()            no-op; the kernel performs icache/TLB
 *                                maintenance when installing the shadow page.
 *   green_gum_release_page()     gum's deactivate_trampoline equivalent:
 *                                restores the original PTE.
 *
 * The patch_code page-lump logic is adapted from gummemory.c's
 * gum_memory_patch_code_pages_via_remap() with the remap pair
 * (try_remap_writable_pages/dispose_writable_pages) implemented as
 * snapshot/commit against the shadow ABI.
 */

#include "gummemory.h"
#include "gummemory-priv.h"
#include "gumprocess.h"

#include "green_agent.h"
#include <green/abi.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <unistd.h>

#define GREEN_GUM_MAX_SNAPSHOT_PAGES 64

typedef struct _GreenGumRemap GreenGumRemap;

struct _GreenGumRemap
{
  gpointer writable;
  gpointer target_page;
  guint n_pages;
};

static GreenGumRemap green_gum_remaps[GREEN_GUM_MAX_SNAPSHOT_PAGES];

/* ------------------------------------------------------------------ */
/* gum backend bootstrap                                              */
/* ------------------------------------------------------------------ */

void
_gum_memory_backend_init (void)
{
}

void
_gum_memory_backend_deinit (void)
{
}

guint
_gum_memory_backend_query_page_size (void)
{
  return 4096;
}

gint
_gum_page_protection_to_posix (GumPageProtection prot)
{
  gint posix_prot = PROT_NONE;

  if ((prot & GUM_PAGE_READ) != 0)
    posix_prot |= PROT_READ;
  if ((prot & GUM_PAGE_WRITE) != 0)
    posix_prot |= PROT_WRITE;
  if ((prot & GUM_PAGE_EXECUTE) != 0)
    posix_prot |= PROT_EXEC;

  return posix_prot;
}

guint
gum_query_page_size (void)
{
  return _gum_memory_backend_query_page_size ();
}

GumPtrauthSupport
gum_query_ptrauth_support (void)
{
  return GUM_PTRAUTH_UNSUPPORTED;
}

gboolean
gum_query_is_rwx_supported (void)
{
  return FALSE;
}

GumRwxSupport
gum_query_rwx_support (void)
{
  return GUM_RWX_NONE;
}

gpointer
gum_sign_code_pointer (gpointer value)
{
  return value;
}

gpointer
gum_strip_code_pointer (gpointer value)
{
  return value;
}

GumAddress
gum_sign_code_address (GumAddress value)
{
  return value;
}

GumAddress
gum_strip_code_address (GumAddress value)
{
  return value;
}

GumOS
gum_process_get_native_os (void)
{
  return GUM_OS_ANDROID;
}

/* gum internal heap (gummetalhash) */
gpointer
gum_internal_malloc (size_t size)
{
  return malloc (size);
}

gpointer
gum_internal_calloc (size_t count, size_t size)
{
  return calloc (count, size);
}

gpointer
gum_internal_realloc (gpointer mem, size_t size)
{
  return realloc (mem, size);
}

void
gum_internal_free (gpointer mem)
{
  free (mem);
}

/* ------------------------------------------------------------------ */
/* reads                                                               */
/* ------------------------------------------------------------------ */

static gssize
green_gum_process_vm_read (gpointer local, gsize len, gconstpointer remote)
{
  struct iovec local_iov = { .iov_base = local, .iov_len = len };
  struct iovec remote_iov = { .iov_base = (void *) remote, .iov_len = len };
  gssize n;

  do
  {
    n = process_vm_readv (getpid (), &local_iov, 1, &remote_iov, 1, 0);
  }
  while (n < 0 && errno == EINTR);

  return n;
}

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  return green_gum_process_vm_read ((gpointer) &len, 1, address) == 1;
}

guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint8 * buffer;
  gssize n;

  if (address == NULL || len == 0)
    return NULL;

  buffer = g_malloc (len);
  n = green_gum_process_vm_read (buffer, len, address);
  if (n <= 0)
  {
    g_free (buffer);
    return NULL;
  }

  if (n != (gssize) len)
  {
    guint8 * shrunk = g_realloc (buffer, (gsize) n);
    buffer = shrunk;
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = (gsize) n;

  return buffer;
}

/* ------------------------------------------------------------------ */
/* hook-time writes — the shadow path                                  */
/* ------------------------------------------------------------------ */

static gboolean
green_gum_shadow_patch (gconstpointer address,
                        gconstpointer bytes,
                        gsize len)
{
  /* The injected process calls KPM directly.  The token is carried in every
   * prctl by green_agent_shadow_request(); there is no privileged broker
   * connection in the memory path. */
  guint8 * page_addr = (guint8 *) (((guintptr) address) & ~4095ULL);
  gsize page_off = (gsize) ((guintptr) address & 4095ULL);
  if (len == 0 || page_off + len > 4096)
    return FALSE;
  /* KPM overlays the supplied range onto the existing shadow copy. Do not
   * send a process_vm_readv snapshot here: for execute-only pages that read
   * intentionally returns the original PFN, and would erase earlier writes
   * to the agent's own generated code page. */
  return green_agent_shadow_request (GREEN_SHADOW_OP_PATCH,
                                     GPOINTER_TO_SIZE (page_addr) + page_off,
                                     bytes, len, NULL) == 0;
}

gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  guint8 * cursor = address;
  const guint8 * source = bytes;
  gsize remaining = len;

  if (address == NULL || bytes == NULL)
    return FALSE;

  /* KPM limits one authenticated request to one page, so split writes at
   * page boundaries and route every chunk through shadow. */
  while (remaining != 0)
  {
    gsize chunk = 4096 - (GPOINTER_TO_SIZE (cursor) & 4095);
    if (chunk > remaining)
      chunk = remaining;
    if (!green_gum_shadow_patch (cursor, source, chunk))
      return FALSE;
    cursor += chunk;
    source += chunk;
    remaining -= chunk;
  }
  return TRUE;
}

/* ------------------------------------------------------------------ */
/* remap pair: snapshot + shadow commit (gum via_remap seam)            */
/* ------------------------------------------------------------------ */

gboolean
gum_memory_can_remap_writable (void)
{
  /* Routes gum's patch_code_pages into via_remap(), whose writable-alias
   * pair is implemented below as snapshot/commit. */
  return TRUE;
}

static GreenGumRemap *
green_gum_remap_find (gpointer writable)
{
  guint i;

  for (i = 0; i != GREEN_GUM_MAX_SNAPSHOT_PAGES; i++)
  {
    if (green_gum_remaps[i].writable == writable)
      return &green_gum_remaps[i];
  }

  return NULL;
}

gpointer
gum_memory_try_remap_writable_pages (gpointer first_page,
                                     guint n_pages)
{
  GreenGumRemap * slot = NULL;
  gpointer snapshot;
  gsize size;
  guint i;

  if (first_page == NULL || n_pages == 0 ||
      n_pages > GREEN_GUM_MAX_SNAPSHOT_PAGES)
    return NULL;

  for (i = 0; i != GREEN_GUM_MAX_SNAPSHOT_PAGES; i++)
  {
    if (green_gum_remaps[i].writable == NULL)
    {
      slot = &green_gum_remaps[i];
      break;
    }
  }
  if (slot == NULL)
    return NULL;

  size = (gsize) n_pages * 4096;
  snapshot = g_malloc (size);

  /* The "writable alias" is a snapshot of the ORIGINAL pages, taken through
   * the GUP path so an already-shadowed target snapshots its original
   * bytes, not the patched ones. */
  if (green_gum_process_vm_read (snapshot, size, first_page) !=
      (gssize) size)
  {
    g_free (snapshot);
    return NULL;
  }

  slot->writable = snapshot;
  slot->target_page = first_page;
  slot->n_pages = n_pages;

  return snapshot;
}

void
gum_memory_dispose_writable_pages (gpointer first_page,
                                   guint n_pages)
{
  GreenGumRemap * remap = green_gum_remap_find (first_page);
  guint i;

  if (remap == NULL)
  {
    g_free (first_page);
    return;
  }

  /* Commit only bytes changed by the patch callback. A full snapshot read from
   * an execute-only page is the original PFN; sending it back wholesale would
   * clobber an earlier hook on the same page. */
  for (i = 0; i != remap->n_pages && i != n_pages; i++)
  {
    guint8 * target = (guint8 *) remap->target_page + i * 4096;
    const guint8 * source = (const guint8 *) remap->writable + i * 4096;
    guint8 original[4096];
    guint j;

    if (green_gum_process_vm_read (original, 4096, target) != 4096)
      continue;
    j = 0;
    while (j < 4096)
    {
      guint start;
      while (j < 4096 && source[j] == original[j])
        j++;
      start = j;
      while (j < 4096 && source[j] != original[j])
        j++;
      if (j > start)
        (void) green_gum_shadow_patch (target + start, source + start,
                                        j - start);
    }
  }

  g_free (remap->writable);
  remap->writable = NULL;
  remap->target_page = NULL;
  remap->n_pages = 0;
}

/* ------------------------------------------------------------------ */
/* patch_code — adapted from gummemory.c patch_code_pages_via_remap()  */
/* ------------------------------------------------------------------ */

typedef struct _GumPatchCodeContext GumPatchCodeContext;

struct _GumPatchCodeContext
{
  gsize page_offset;
  GumMemoryPatchApplyFunc func;
  gpointer user_data;
};

static void
gum_apply_patch_code (gpointer mem,
                      gpointer target_page,
                      guint n_pages,
                      gpointer user_data)
{
  GumPatchCodeContext * context = user_data;

  (void) target_page;
  (void) n_pages;

  context->func ((guint8 *) mem + context->page_offset, context->user_data);
}

gboolean
gum_memory_patch_code (gpointer address,
                       gsize size,
                       GumMemoryPatchApplyFunc apply,
                       gpointer apply_data)
{
  gsize page_size;
  guint8 * start_page, * end_page;
  gsize page_offset;
  guint n_pages;
  GumPatchCodeContext context;
  gpointer writable;

  if (address == NULL || apply == NULL || size == 0)
    return FALSE;

  address = gum_strip_code_pointer (address);

  page_size = gum_query_page_size ();
  start_page = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  end_page = GSIZE_TO_POINTER (
      (GPOINTER_TO_SIZE (address) + size - 1) & ~(page_size - 1));
  page_offset = ((guint8 *) address) - start_page;
  n_pages = ((end_page - start_page) / page_size) + 1;

  if (n_pages > GREEN_GUM_MAX_SNAPSHOT_PAGES)
    return FALSE;

  /* gum via_remap, single-lump path: one contiguous snapshot covering all
   * touched pages, one apply at the patch offset, then commit per page. */
  writable = gum_memory_try_remap_writable_pages (start_page, n_pages);
  if (writable == NULL)
    return FALSE;

  context.page_offset = page_offset;
  context.func = apply;
  context.user_data = apply_data;

  gum_apply_patch_code (writable, start_page, n_pages, &context);

  gum_memory_dispose_writable_pages (writable, n_pages);
  gum_clear_cache (start_page, n_pages * page_size);

  return TRUE;
}

/* ------------------------------------------------------------------ */
/* protection / cache / allocation passthrough                         */
/* ------------------------------------------------------------------ */

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection prot)
{
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;

  if (size == 0)
    return FALSE;

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;

  return mprotect (aligned_address, aligned_size,
      _gum_page_protection_to_posix (prot)) == 0;
}

void
gum_mprotect (gpointer address,
              gsize size,
              GumPageProtection prot)
{
  if (!gum_try_mprotect (address, size, prot))
    g_assert_not_reached ();
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
  (void) address;
  (void) size;
  /* The kernel runs green_shadow_sync_code() (dc cvau + ic ialluis + TLB
   * flush) when committing a shadow page, so the patch is already coherent
   * with the icache by the time the prctl returns. */
}

gboolean
gum_memory_mark_code (gpointer address,
                      gsize size)
{
  (void) address;
  (void) size;
  return TRUE;
}

void
gum_ensure_code_readable (gconstpointer address,
                          gsize size)
{
  (void) address;
  (void) size;
}

gpointer
gum_memory_allocate (gpointer address,
                     gsize size,
                     gsize alignment,
                     GumPageProtection prot)
{
  gsize page_size = gum_query_page_size ();
  gsize allocation_size = (size + page_size - 1) & ~(page_size - 1);
  gpointer base;

  (void) alignment;

  base = mmap (address, allocation_size, _gum_page_protection_to_posix (prot),
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED)
    return NULL;

  return base;
}

gboolean
gum_memory_free (gpointer address,
                 gsize size)
{
  gsize page_size = gum_query_page_size ();
  gsize allocation_size = (size + page_size - 1) & ~(page_size - 1);

  return munmap (address, allocation_size) == 0;
}

gboolean
gum_memory_release (gpointer address,
                    gsize size)
{
  return gum_memory_free (address, size);
}

gboolean
gum_memory_recommit (gpointer address,
                     gsize size,
                     GumPageProtection prot)
{
  (void) address;
  (void) size;
  (void) prot;
  return TRUE;
}

gboolean
gum_memory_discard (gpointer address,
                    gsize size)
{
  (void) address;
  (void) size;
  return TRUE;
}

gboolean
gum_memory_decommit (gpointer address,
                     gsize size)
{
  (void) address;
  (void) size;
  return TRUE;
}

gboolean
gum_memory_query_protection (gconstpointer address,
                             GumPageProtection * prot)
{
  (void) address;
  if (prot != NULL)
    *prot = GUM_PAGE_RWX;
  return TRUE;
}

guint
gum_peek_private_memory_usage (void)
{
  return 0;
}

/* ------------------------------------------------------------------ */
/* green extension: hook 卸载（deactivate 等价）                        */
/* ------------------------------------------------------------------ */

gboolean
green_gum_release_page (gconstpointer address)
{
  unsigned long page;

  if (address == NULL)
    return FALSE;

  page = ((unsigned long) GPOINTER_TO_SIZE (address)) & ~4095UL;
  return green_agent_shadow_request (GREEN_SHADOW_OP_RELEASE, page, NULL, 0,
                                     NULL) == 0;
}
