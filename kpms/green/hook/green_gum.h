/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GREEN_GUM_H_
#define _GREEN_GUM_H_

#include <gum/gummemory.h>

/* green extension: gum deactivate_trampoline equivalent — restores the
 * original PTE of the page containing address (drops its shadow state). */
GUM_API gboolean green_gum_release_page (gconstpointer address);

#endif
