#include "discord_lottie.h"

#if !GLIB_CHECK_VERSION(2, 68, 0)
#   define g_memdup2(mem, size) g_memdup((mem), (size))
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#   include <windows.h>
#   define dlopen(filename, flag)  LoadLibraryA(filename)
#   define dlsym(handle, symbol)   (void *)GetProcAddress((HMODULE)(handle), (symbol))
#   define dlclose(handle)         FreeLibrary((HMODULE)(handle))
    static inline const char *dlerror(void) {
        static char err[256];
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, err, sizeof(err), NULL);
        return err;
    }
#else
#   include <dlfcn.h>
#endif

typedef struct Lottie_Animation_S Lottie_Animation;

#ifdef RLOTTIE_STATIC

Lottie_Animation *lottie_animation_from_data(const char *data, const char *key, const char *resourcePath);
void lottie_animation_destroy(Lottie_Animation *animation);
size_t lottie_animation_get_totalframe(const Lottie_Animation *animation);
double lottie_animation_get_framerate(const Lottie_Animation *animation);
void lottie_animation_get_size(const Lottie_Animation *animation, size_t *width, size_t *height);
void lottie_animation_render(Lottie_Animation *animation, size_t frame_num, uint32_t *buffer, size_t width, size_t height, size_t bytesPerLine);

#define lottie_from_data_ptr       lottie_animation_from_data
#define lottie_destroy_ptr         lottie_animation_destroy
#define lottie_get_totalframe_ptr  lottie_animation_get_totalframe
#define lottie_get_framerate_ptr   lottie_animation_get_framerate
#define lottie_get_size_ptr        lottie_animation_get_size
#define lottie_render_ptr          lottie_animation_render

gboolean
discord_lottie_is_available(void)
{
	return TRUE;
}

#else

typedef Lottie_Animation *(*lottie_from_data_fn)(const char *data, const char *key, const char *resourcePath);
typedef void (*lottie_destroy_fn)(Lottie_Animation *animation);
typedef size_t (*lottie_get_totalframe_fn)(const Lottie_Animation *animation);
typedef double (*lottie_get_framerate_fn)(const Lottie_Animation *animation);
typedef void (*lottie_get_size_fn)(const Lottie_Animation *animation, size_t *width, size_t *height);
typedef void (*lottie_render_fn)(Lottie_Animation *animation, size_t frame_num, uint32_t *buffer, size_t width, size_t height, size_t bytesPerLine);

static lottie_from_data_fn lottie_from_data_ptr = NULL;
static lottie_destroy_fn lottie_destroy_ptr = NULL;
static lottie_get_totalframe_fn lottie_get_totalframe_ptr = NULL;
static lottie_get_framerate_fn lottie_get_framerate_ptr = NULL;
static lottie_get_size_fn lottie_get_size_ptr = NULL;
static lottie_render_fn lottie_render_ptr = NULL;

static void *rlottie_handle = NULL;
static gboolean rlottie_checked = FALSE;

static const char *const rlottie_lib_names[] = {
#ifdef _WIN32
	"rlottie.dll",
	"librlottie.dll",
#elif defined(__APPLE__)
	"librlottie.0.dylib",
	"librlottie.dylib",
#else
	"librlottie.so.0",
	"librlottie.so",
#endif
	NULL
};

gboolean
discord_lottie_is_available(void)
{
	if (rlottie_checked) {
		return (rlottie_handle != NULL);
	}
	rlottie_checked = TRUE;

	for (int i = 0; rlottie_lib_names[i] != NULL; i++) {
		rlottie_handle = dlopen(rlottie_lib_names[i], RTLD_LAZY);
		if (rlottie_handle != NULL) {
			break;
		}
	}

	if (rlottie_handle == NULL) {
		return FALSE;
	}

	lottie_from_data_ptr = (lottie_from_data_fn)dlsym(rlottie_handle, "lottie_animation_from_data");
	lottie_destroy_ptr = (lottie_destroy_fn)dlsym(rlottie_handle, "lottie_animation_destroy");
	lottie_get_totalframe_ptr = (lottie_get_totalframe_fn)dlsym(rlottie_handle, "lottie_animation_get_totalframe");
	lottie_get_framerate_ptr = (lottie_get_framerate_fn)dlsym(rlottie_handle, "lottie_animation_get_framerate");
	lottie_get_size_ptr = (lottie_get_size_fn)dlsym(rlottie_handle, "lottie_animation_get_size");
	lottie_render_ptr = (lottie_render_fn)dlsym(rlottie_handle, "lottie_animation_render");

	if (!lottie_from_data_ptr || !lottie_destroy_ptr || !lottie_get_totalframe_ptr ||
	    !lottie_get_framerate_ptr || !lottie_get_size_ptr || !lottie_render_ptr) {
		dlclose(rlottie_handle);
		rlottie_handle = NULL;
		lottie_from_data_ptr = NULL;
		lottie_destroy_ptr = NULL;
		lottie_get_totalframe_ptr = NULL;
		lottie_get_framerate_ptr = NULL;
		lottie_get_size_ptr = NULL;
		lottie_render_ptr = NULL;
		return FALSE;
	}

	return TRUE;
}

#endif

#if defined(__GNUC__)
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wold-style-declaration"
#   pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#   pragma GCC diagnostic ignored "-Wunused-function"
#   pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

#define MSF_GIF_IMPL
#include "msf_gif.h"

#if defined(__GNUC__)
#   pragma GCC diagnostic pop
#endif

gpointer
discord_lottie_render_to_gif(const gchar *json_data, guint max_width, guint max_height, guint max_fps, gsize *out_len)
{
	if (!discord_lottie_is_available() || json_data == NULL || *json_data == '\0') {
		return NULL;
	}

	Lottie_Animation *anim = lottie_from_data_ptr(json_data, "", "");
	if (anim == NULL) {
		return NULL;
	}

	size_t total_frames = lottie_get_totalframe_ptr(anim);
	if (total_frames == 0) {
		lottie_destroy_ptr(anim);
		return NULL;
	}

	double fps = lottie_get_framerate_ptr(anim);
	if (fps <= 0.0) {
		fps = 60.0;
	}

	size_t orig_width = 0, orig_height = 0;
	lottie_get_size_ptr(anim, &orig_width, &orig_height);
	if (orig_width == 0 || orig_height == 0) {
		orig_width = 320;
		orig_height = 320;
	}

	if (max_width == 0) max_width = 160;
	if (max_height == 0) max_height = 160;
	if (max_fps == 0) max_fps = 30;

	double scale_x = (double)max_width / (double)orig_width;
	double scale_y = (double)max_height / (double)orig_height;
	double scale = (scale_x < scale_y) ? scale_x : scale_y;
	if (scale > 1.0) {
		scale = 1.0;
	}

	size_t render_width = (size_t)(orig_width * scale);
	size_t render_height = (size_t)(orig_height * scale);
	if (render_width < 16) render_width = 16;
	if (render_height < 16) render_height = 16;

	double target_fps = ((double)max_fps < fps) ? (double)max_fps : fps;
	double frame_step = fps / target_fps;
	int centiseconds = (int)(100.0 / target_fps + 0.5);
	if (centiseconds < 2) centiseconds = 2;

	MsfGifState gif_state;
	memset(&gif_state, 0, sizeof(gif_state));

	msf_gif_bgra_flag = 1;
	msf_gif_alpha_threshold = 128;

	if (!msf_gif_begin(&gif_state, render_width, render_height)) {
		lottie_destroy_ptr(anim);
		return NULL;
	}

	uint32_t *frame_buffer = g_new0(uint32_t, render_width * render_height);
	size_t bytes_per_line = render_width * sizeof(uint32_t);

	for (double f = 0.0; f < (double)total_frames; f += frame_step) {
		size_t frame_idx = (size_t)f;
		if (frame_idx >= total_frames) {
			frame_idx = total_frames - 1;
		}

		memset(frame_buffer, 0, bytes_per_line * render_height);
		lottie_render_ptr(anim, frame_idx, frame_buffer, render_width, render_height, bytes_per_line);
		msf_gif_frame(&gif_state, (uint8_t *)frame_buffer, centiseconds, 16, bytes_per_line);
	}

	g_free(frame_buffer);
	lottie_destroy_ptr(anim);

	MsfGifResult result = msf_gif_end(&gif_state);
	if (result.data == NULL || result.dataSize == 0) {
		msf_gif_free(result);
		return NULL;
	}

	gpointer gif_data = g_memdup2(result.data, result.dataSize);
	if (out_len != NULL) {
		*out_len = result.dataSize;
	}
	msf_gif_free(result);

	return gif_data;
}
