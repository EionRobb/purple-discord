// From https://github.com/GNOME/glib/blob/2.56.4/glib/gdatetime.c

#include <glib.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/time.h>
#include <time.h>

#define GREGORIAN_LEAP(y)    ((((y) % 4) == 0) && (!((((y) % 100) == 0) && (((y) % 400) != 0))))

/* Parse integers in the form d (week days), dd (hours etc), ddd (ordinal days) or dddd (years) */
static gboolean
get_iso8601_int (const gchar *text, gsize length, gint *value)
{
  gsize i;
  gint v = 0;

  if (length < 1 || length > 4)
    return FALSE;

  for (i = 0; i < length; i++)
    {
      const gchar c = text[i];
      if (c < '0' || c > '9')
        return FALSE;
      v = v * 10 + (c - '0');
    }

  *value = v;
  return TRUE;
}

/* Parse seconds in the form ss or ss.sss (variable length decimal) */
static gboolean
get_iso8601_seconds (const gchar *text, gsize length, gdouble *value)
{
  gsize i;
  gdouble divisor = 1, v = 0;

  if (length < 2)
    return FALSE;

  for (i = 0; i < 2; i++)
    {
      const gchar c = text[i];
      if (c < '0' || c > '9')
        return FALSE;
      v = v * 10 + (c - '0');
    }

  if (length > 2 && !(text[i] == '.' || text[i] == ','))
    return FALSE;
  i++;
  if (i == length)
    return FALSE;

  for (; i < length; i++)
    {
      const gchar c = text[i];
      if (c < '0' || c > '9')
        return FALSE;
      v = v * 10 + (c - '0');
      divisor *= 10;
    }

  *value = v / divisor;
  return TRUE;
}

struct _GDateTime
{
  /* Microsecond timekeeping within Day */
  guint64 usec;

  /* TimeZone information */
  GTimeZone *tz;
  gint interval;

  /* 1 is 0001-01-01 in Proleptic Gregorian */
  gint32 days;

  volatile gint ref_count;
};

static GDateTime *
g_date_time_new_ordinal (GTimeZone *tz, gint year, gint ordinal_day, gint hour, gint minute, gdouble seconds)
{
  GDateTime *dt;

  if (ordinal_day < 1 || ordinal_day > (GREGORIAN_LEAP (year) ? 366 : 365))
    return NULL;

  dt = g_date_time_new (tz, year, 1, 1, hour, minute, seconds);
  dt->days += ordinal_day - 1;

  return dt;
}

static void
g_date_time_get_week_number (GDateTime *datetime,
                             gint      *week_number,
                             gint      *day_of_week,
                             gint      *day_of_year)
{
  gint a, b, c, d, e, f, g, n, s, month, day, year;

  g_date_time_get_ymd (datetime, &year, &month, &day);

  if (month <= 2)
    {
      a = g_date_time_get_year (datetime) - 1;
      b = (a / 4) - (a / 100) + (a / 400);
      c = ((a - 1) / 4) - ((a - 1) / 100) + ((a - 1) / 400);
      s = b - c;
      e = 0;
      f = day - 1 + (31 * (month - 1));
    }
  else
    {
      a = year;
      b = (a / 4) - (a / 100) + (a / 400);
      c = ((a - 1) / 4) - ((a - 1) / 100) + ((a - 1) / 400);
      s = b - c;
      e = s + 1;
      f = day + (((153 * (month - 3)) + 2) / 5) + 58 + s;
    }

  g = (a + b) % 7;
  d = (f + g - e) % 7;
  n = f + 3 - d;

  if (week_number)
    {
      if (n < 0)
        *week_number = 53 - ((g - s) / 5);
      else if (n > 364 + s)
        *week_number = 1;
      else
        *week_number = (n / 7) + 1;
    }

  if (day_of_week)
    *day_of_week = d + 1;

  if (day_of_year)
    *day_of_year = f + 1;
}

static GDateTime *
g_date_time_new_week (GTimeZone *tz, gint year, gint week, gint week_day, gint hour, gint minute, gdouble seconds)
{
  gint64 p;
  gint max_week, jan4_week_day, ordinal_day;
  GDateTime *dt;

  p = (year * 365 + (year / 4) - (year / 100) + (year / 400)) % 7;
  max_week = p == 4 ? 53 : 52;

  if (week < 1 || week > max_week || week_day < 1 || week_day > 7)
    return NULL;

  dt = g_date_time_new (tz, year, 1, 4, 0, 0, 0);
  g_date_time_get_week_number (dt, NULL, &jan4_week_day, NULL);
  ordinal_day = (week * 7) + week_day - (jan4_week_day + 3);
  if (ordinal_day < 0)
    {
      year--;
      ordinal_day += GREGORIAN_LEAP (year) ? 366 : 365;
    }
  else if (ordinal_day > (GREGORIAN_LEAP (year) ? 366 : 365))
    {
      ordinal_day -= (GREGORIAN_LEAP (year) ? 366 : 365);
      year++;
    }

  return g_date_time_new_ordinal (tz, year, ordinal_day, hour, minute, seconds);
}

static GDateTime *
parse_iso8601_date (const gchar *text, gsize length,
                    gint hour, gint minute, gdouble seconds, GTimeZone *tz)
{
  /* YYYY-MM-DD */
  if (length == 10 && text[4] == '-' && text[7] == '-')
    {
      int year, month, day;
      if (!get_iso8601_int (text, 4, &year) ||
          !get_iso8601_int (text + 5, 2, &month) ||
          !get_iso8601_int (text + 8, 2, &day))
        return NULL;
      return g_date_time_new (tz, year, month, day, hour, minute, seconds);
    }
  /* YYYY-DDD */
  else if (length == 8 && text[4] == '-')
    {
      gint year, ordinal_day;
      if (!get_iso8601_int (text, 4, &year) ||
          !get_iso8601_int (text + 5, 3, &ordinal_day))
        return NULL;
      return g_date_time_new_ordinal (tz, year, ordinal_day, hour, minute, seconds);
    }
  /* YYYY-Www-D */
  else if (length == 10 && text[4] == '-' && text[5] == 'W' && text[8] == '-')
    {
      gint year, week, week_day;
      if (!get_iso8601_int (text, 4, &year) ||
          !get_iso8601_int (text + 6, 2, &week) ||
          !get_iso8601_int (text + 9, 1, &week_day))
        return NULL;
      return g_date_time_new_week (tz, year, week, week_day, hour, minute, seconds);
    }
  /* YYYYWwwD */
  else if (length == 8 && text[4] == 'W')
    {
      gint year, week, week_day;
      if (!get_iso8601_int (text, 4, &year) ||
          !get_iso8601_int (text + 5, 2, &week) ||
          !get_iso8601_int (text + 7, 1, &week_day))
        return NULL;
      return g_date_time_new_week (tz, year, week, week_day, hour, minute, seconds);
    }
  /* YYYYMMDD */
  else if (length == 8)
    {
      int year, month, day;
      if (!get_iso8601_int (text, 4, &year) ||
          !get_iso8601_int (text + 4, 2, &month) ||
          !get_iso8601_int (text + 6, 2, &day))
        return NULL;
      return g_date_time_new (tz, year, month, day, hour, minute, seconds);
    }
  /* YYYYDDD */
  else if (length == 7)
    {
      gint year, ordinal_day;
      if (!get_iso8601_int (text, 4, &year) ||
          !get_iso8601_int (text + 4, 3, &ordinal_day))
        return NULL;
      return g_date_time_new_ordinal (tz, year, ordinal_day, hour, minute, seconds);
    }
  else
    return FALSE;
}

static GTimeZone *
parse_iso8601_timezone (const gchar *text, gsize length, gssize *tz_offset)
{
  gint i, tz_length, offset_sign = 1, offset_hours, offset_minutes;
  GTimeZone *tz;

  /* UTC uses Z suffix  */
  if (length > 0 && text[length - 1] == 'Z')
    {
      *tz_offset = length - 1;
      return g_time_zone_new_utc ();
    }

  /* Look for '+' or '-' of offset */
  for (i = length - 1; i >= 0; i--)
    if (text[i] == '+' || text[i] == '-')
      {
        offset_sign = text[i] == '-' ? -1 : 1;
        break;
      }
  if (i < 0)
    return NULL;
  tz_length = length - i;

  /* +hh:mm or -hh:mm */
  if (tz_length == 6 && text[i+3] == ':')
    {
      if (!get_iso8601_int (text + i + 1, 2, &offset_hours) ||
          !get_iso8601_int (text + i + 4, 2, &offset_minutes))
        return NULL;
    }
  /* +hhmm or -hhmm */
  else if (tz_length == 5)
    {
      if (!get_iso8601_int (text + i + 1, 2, &offset_hours) ||
          !get_iso8601_int (text + i + 3, 2, &offset_minutes))
        return NULL;
    }
  /* +hh or -hh */
  else if (tz_length == 3)
    {
      if (!get_iso8601_int (text + i + 1, 2, &offset_hours))
        return NULL;
      offset_minutes = 0;
    }
  else
    return NULL;

  *tz_offset = i;
  tz = g_time_zone_new (text + i);

  /* Double-check that the GTimeZone matches our interpretation of the timezone.
   * Failure would indicate a bug either here of in the GTimeZone code. */
  g_assert (g_time_zone_get_offset (tz, 0) == offset_sign * (offset_hours * 3600 + offset_minutes * 60));

  return tz;
}

static gboolean
parse_iso8601_time (const gchar *text, gsize length,
                    gint *hour, gint *minute, gdouble *seconds, GTimeZone **tz)
{
  gssize tz_offset = -1;

  /* Check for timezone suffix */
  *tz = parse_iso8601_timezone (text, length, &tz_offset);
  if (tz_offset >= 0)
    length = tz_offset;

  /* hh:mm:ss(.sss) */
  if (length >= 8 && text[2] == ':' && text[5] == ':')
    {
      return get_iso8601_int (text, 2, hour) &&
             get_iso8601_int (text + 3, 2, minute) &&
             get_iso8601_seconds (text + 6, length - 6, seconds);
    }
  /* hhmmss(.sss) */
  else if (length >= 6)
    {
      return get_iso8601_int (text, 2, hour) &&
             get_iso8601_int (text + 2, 2, minute) &&
             get_iso8601_seconds (text + 4, length - 4, seconds);
    }
  else
    return FALSE;
}

/**
 * g_date_time_new_from_iso8601:
 * @text: an ISO 8601 formatted time string.
 * @default_tz: (nullable): a #GTimeZone to use if the text doesn't contain a
 *                          timezone, or %NULL.
 *
 * Creates a #GDateTime corresponding to the given
 * [ISO 8601 formatted string](https://en.wikipedia.org/wiki/ISO_8601)
 * @text. ISO 8601 strings of the form <date><sep><time><tz> are supported.
 *
 * <sep> is the separator and can be either 'T', 't' or ' '.
 *
 * <date> is in the form:
 *
 * - `YYYY-MM-DD` - Year/month/day, e.g. 2016-08-24.
 * - `YYYYMMDD` - Same as above without dividers.
 * - `YYYY-DDD` - Ordinal day where DDD is from 001 to 366, e.g. 2016-237.
 * - `YYYYDDD` - Same as above without dividers.
 * - `YYYY-Www-D` - Week day where ww is from 01 to 52 and D from 1-7,
 *   e.g. 2016-W34-3.
 * - `YYYYWwwD` - Same as above without dividers.
 *
 * <time> is in the form:
 *
 * - `hh:mm:ss(.sss)` - Hours, minutes, seconds (subseconds), e.g. 22:10:42.123.
 * - `hhmmss(.sss)` - Same as above without dividers.
 *
 * <tz> is an optional timezone suffix of the form:
 *
 * - `Z` - UTC.
 * - `+hh:mm` or `-hh:mm` - Offset from UTC in hours and minutes, e.g. +12:00.
 * - `+hh` or `-hh` - Offset from UTC in hours, e.g. +12.
 *
 * If the timezone is not provided in @text it must be provided in @default_tz
 * (this field is otherwise ignored).
 *
 * This call can fail (returning %NULL) if @text is not a valid ISO 8601
 * formatted string.
 *
 * You should release the return value by calling g_date_time_unref()
 * when you are done with it.
 *
 * Returns: (transfer full) (nullable): a new #GDateTime, or %NULL
 *
 * Since: 2.56
 */
GDateTime *
g_date_time_new_from_iso8601 (const gchar *text, GTimeZone *default_tz)
{
  gint length, date_length = -1;
  gint hour = 0, minute = 0;
  gdouble seconds = 0.0;
  GTimeZone *tz = NULL;
  GDateTime *datetime = NULL;

  g_return_val_if_fail (text != NULL, NULL);

  /* Count length of string and find date / time separator ('T', 't', or ' ') */
  for (length = 0; text[length] != '\0'; length++)
    {
      if (date_length < 0 && (text[length] == 'T' || text[length] == 't' || text[length] == ' '))
        date_length = length;
    }

  if (date_length < 0)
    return NULL;

  if (!parse_iso8601_time (text + date_length + 1, length - (date_length + 1),
                           &hour, &minute, &seconds, &tz))
    goto out;
  if (tz == NULL && default_tz == NULL)
    return NULL;

  datetime = parse_iso8601_date (text, date_length, hour, minute, seconds, tz ? tz : default_tz);

out:
    if (tz != NULL)
      g_time_zone_unref (tz);
    return datetime;
}
