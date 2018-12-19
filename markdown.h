/*
 *   Markdown library for libpurple
 *   Copyright (C) 2018 Alyssa Rosenzweig
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


#ifndef __MARKDOWN_H
#define __MARKDOWN_H

#include <purple.h>
#include <glib.h>

gchar *markdown_convert_markdown(const gchar *html, gboolean escape_html, gboolean markdown_hacks);
gchar *markdown_escape_md(const gchar *markdown, gboolean markdown_hacks);
gchar *markdown_html_to_markdown(gchar *html);

#endif
