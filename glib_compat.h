/*
 *   Discord plugin for libpurple
 *   Copyright (C) 2016-2017  Eion Robb
 *   Copyright (C) 2017 Alyssa Rosenzweig
 *   Copyright 2019 Christian Hergert <chergert@redhat.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <glib.h>
#include <purple.h>

#if !GLIB_CHECK_VERSION(2, 56, 0)
// From https://gitlab.gnome.org/GNOME/sysprof/-/raw/master/src/libsysprof-ui/sysprof-details-page.c
// Modified to avoid use of g_autoptr, which only works on GCC/clang.
static GDateTime *
g_date_time_new_from_iso8601 (const gchar *str,
                              GTimeZone   *default_tz)
{
  GTimeVal tv;

  if (g_time_val_from_iso8601 (str, &tv))
    {
      GDateTime *dt = g_date_time_new_from_timeval_utc (&tv);

      if (default_tz) {
        GDateTime *dt_tz = g_date_time_to_timezone (dt, default_tz);
        g_date_time_unref(dt);
        return g_steal_pointer (&dt_tz);
      } else {
        return g_steal_pointer (&dt);
      }
    }

  return NULL;
}
#endif /* 2.56.0 */

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended(hash_table, key, NULL, NULL)
#endif /* 2.32.0 */

#if !GLIB_CHECK_VERSION(2, 68, 0) && !PURPLE_VERSION_CHECK(2, 14, 2)
#define g_memdup2(mem,size) g_memdup((mem),(size))
#endif

static gboolean
g_str_insensitive_equal(gconstpointer v1, gconstpointer v2)
{
	return (g_ascii_strcasecmp(v1, v2) == 0);
}
static guint
g_str_insensitive_hash(gconstpointer v)
{
	guint hash;
	gchar *lower_str = g_ascii_strdown(v, -1);

	hash = g_str_hash(lower_str);
	g_free(lower_str);

	return hash;
}
