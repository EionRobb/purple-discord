
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include "win32/win32dep.h"
#endif

#define purple_proxy_info_get_proxy_type        purple_proxy_info_get_type
#define purple_connection_is_disconnecting(c)   FALSE

#ifndef N_
#	define N_(a) (a)
#endif

#ifndef _
#	define _(a) (a)
#endif
