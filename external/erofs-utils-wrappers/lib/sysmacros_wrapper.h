#pragma once

#include "erofs/os.h"

#ifdef __cplusplus
extern "C" {
#endif

unsigned int linux_major(dev_t dev);

unsigned int linux_minor(dev_t dev);

#ifdef __cplusplus
}
#endif
