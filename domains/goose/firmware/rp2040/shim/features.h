// Minimal <features.h> shim for bare-metal arm-none-eabi. PQClean common/compat.h includes
// <features.h> only to get __GNUC_PREREQ for an x86 AVX polyfill that is irrelevant on Cortex-M.
// Providing the macro lets modern GCC skip the polyfill without pulling in glibc's features.h.
#ifndef _FEATURES_H_SHIM
#define _FEATURES_H_SHIM
#ifndef __GNUC_PREREQ
#define __GNUC_PREREQ(maj, min) (((__GNUC__ << 16) + __GNUC_MINOR__) >= (((maj) << 16) + (min)))
#endif
#endif
