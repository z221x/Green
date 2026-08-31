/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GREEN_GUM_GUMPROCESS_SHIM_H_
#define _GREEN_GUM_GUMPROCESS_SHIM_H_

#include <gum/gumdefs.h>

/* gumdefs.h already defines GumOS and the GUM_OS_* enum; this shim only
 * adds the small process surface the vendored writer needs. */

typedef guint64 GumThreadId;

GUM_API GumOS gum_process_get_native_os (void);

#endif
