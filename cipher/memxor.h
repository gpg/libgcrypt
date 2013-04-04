/* memxor.h
 *
 */

#ifndef MEMXOR_H_INCLUDED
#define MEMXOR_H_INCLUDED

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t *memxor(uint8_t *dst, const uint8_t *src, size_t n);
uint8_t *memxor3(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* MEMXOR_H_INCLUDED */
