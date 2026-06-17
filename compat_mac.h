/* macOS build shim: this SDK does not declare reallocarray() even under
 * _DARWIN_C_SOURCE. Provide a portable static-inline fallback. */
#pragma once
#include <stdlib.h>
static inline void *reallocarray(void *ptr, size_t nmemb, size_t size) {
    return realloc(ptr, nmemb * size);
}
