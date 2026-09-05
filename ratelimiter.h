#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H
#include <glib.h>
#ifdef __cplusplus
extern "C" {
#endif

void initialize_rate_limiter(guint interval);
void stop_rate_limiter();
guint rlimited_timeout_add(guint interval, GSourceFunc function, gpointer data);

#ifdef __cplusplus
}
#endif

#endif
