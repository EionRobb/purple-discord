#ifndef _DISCORD_LOTTIE_H_
#define _DISCORD_LOTTIE_H_

#include <glib.h>

G_BEGIN_DECLS

/**
 * Checks if rlottie is available (either statically linked or successfully dlopened).
 *
 * @return TRUE if rlottie is available, FALSE otherwise.
 */
gboolean discord_lottie_is_available(void);

/**
 * Renders a Lottie JSON string to an animated GIF buffer in memory.
 *
 * @param json_data  Null-terminated Lottie JSON string.
 * @param max_width  Maximum width (e.g. 160; 0 for default 160).
 * @param max_height Maximum height (e.g. 160; 0 for default 160).
 * @param max_fps    Maximum frame rate (e.g. 30; 0 for default 30).
 * @param out_len    Pointer to receive the length of the returned buffer in bytes.
 * @return Newly allocated GIF buffer (caller frees with g_free), or NULL on failure.
 */
gpointer discord_lottie_render_to_gif(const gchar *json_data, guint max_width, guint max_height, guint max_fps, gsize *out_len);

G_END_DECLS

#endif /* _DISCORD_LOTTIE_H_ */
