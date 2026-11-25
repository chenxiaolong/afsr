#include "sysmacros_wrapper.h"

unsigned int linux_major(dev_t dev)
{
    return erofs_os_major(dev);
}

unsigned int linux_minor(dev_t dev)
{
    return erofs_os_minor(dev);
}
