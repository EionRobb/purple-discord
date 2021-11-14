
#if !GLIB_CHECK_VERSION(2, 68, 0)
#define g_memdup2(mem,size) g_memdup((mem),(size))
#endif