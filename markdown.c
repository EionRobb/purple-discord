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


#include "markdown.h"

/* Markdown test string:
 *
 * "<--- \o/ **¯\_(ツ)_/¯**  _italics_ __underline__ *correction right* *italics2* ~~strikethrough~~ ~notstriked~ ~me https://pidgin.im <style>body{background-color:red}</script> &lt;style&gt;body{background-color: red}&lt;/style&gt; <b>notbold</b> &lt;notatag&gt;"
 *
 * Checks for:
 * 	- Correct escaping of lt/gt signs
 * 	- Aesthetically correct (but non-comformant) handling of escape sequences as found in backslash-containing emoticons
 * 	- Exhaustive test of syntaxes for italics, underline, strikethrough
 * 	- Correct escaping for XSS rsisk
 *
 * Does not check for (open issues):
 * 	- Italicised shruggie
 *
 */

#define HTML_TOGGLE_OUT(f, a, b) \
	out = g_string_append(out, f ? b : a); \
	f = !f;

/* workaround errata in Discord's (users') markdown implementation */

static gboolean
markdown_underscore_match(const gchar *html, int i)
{
	while (html[i] != ' ' && html[i]) {
		if (html[i++] == '_') {
			return !html[i] || html[i] == ' ';
		}
	}

	return FALSE;
}

static gboolean
markdown_char_later_unspaced(const gchar *html, unsigned i, guint len, char c)
{
	for (i = i + 1; i < len; ++i)
		if (html[i] == c)
			if (html[i - 1] != ' ')
				return TRUE;
	
	return FALSE;
}

/* Is a character escapable, that is, does it have a special meaning in
 * Markdown? */

static gboolean
markdown_is_escapable(char c)
{
	switch (c) {
	case '\\':
	case '*':
	case '~':
	case '_':
	case '`':
		return TRUE;
	default:
		return FALSE;
	}
}

/* Should we interpret a _ as italics?  */

static gboolean
markdown_should_underscore_italics(const gchar *html, unsigned i, gboolean s_italics)
{
	return s_italics || markdown_underscore_match(html, i + 1);
}

/* Should we interpret _  as special at all? */

static gboolean
markdown_should_underscore(const gchar *html, unsigned i, gboolean s_italics)
{
	return html[i + 1] == '_' || markdown_should_underscore_italics(html, i, s_italics);
}

static gchar *
markdown_helper_replace(gchar *a, gchar *b, gchar *c)
{
	gchar *temp = purple_strreplace(a, b, c);
	g_free(a);
	return temp;
}

gchar *
markdown_convert_markdown(const gchar *html, gboolean escape_html, gboolean discord_hacks)
{
	g_return_val_if_fail(html != NULL, NULL);

	guint html_len = strlen(html);
	GString *out = g_string_sized_new(html_len * 2);

	gboolean s_bold = FALSE;
	gboolean s_italics = FALSE;
	gboolean s_underline = FALSE;
	gboolean s_strikethrough = FALSE;
	gboolean s_codeblock = FALSE;
	gboolean s_codebit = FALSE;

	for (guint i = 0; i < html_len; ++i) {
		char c = html[i];

		if ((s_codeblock || s_codebit) && c != '`') {
			out = g_string_append_c(out, html[i]);
			continue;
		}

		if (c == '\\') {
			char next_char = html[++i];

			/* If this is an escape-able character, don't print the
			 * backslash. Otherwise, do because the \ wasn't an
			 * escape anyway */

			gboolean escapable = markdown_is_escapable(next_char);

			/* Also, if this is an escapable character that would
			 * not actually -matter-, print it too. Fixes shruggie
			 * */

			if (next_char == '_' && !markdown_should_underscore(html, i + 1, s_italics) && (escape_html || discord_hacks))
				escapable = FALSE;

			if (!escapable) {
				out = g_string_append_c(out, '\\');
			}

			/* Append the next char regardless */
			out = g_string_append_c(out, next_char);
		} else if ((c == '<' || c == '>' || c == '&') && escape_html) {
			/* These characters lack any particular meaning in
			 * Markdown, but need to be escaped to prevent getting
			 * mixed up with HTML. Failing to do so may result in
			 * valid parts of the message being stripped by
			 * overzealous sanitizers */

			if (c == '<')
				out = g_string_append(out, "&lt;");
			else if (c == '>')
				out = g_string_append(out, "&gt;");
			else if (c == '&')
				out = g_string_append(out, "&amp;");
		} else if (c == '*') {
			if (html[i + 1] == '*') {
				HTML_TOGGLE_OUT(s_bold, "<b>", "</b>");
				i += 1;
			} else {
				/* Workaround some corner cases regarding italics placement. */

				/* Don't match a*b */
				gboolean unspaced_end = s_italics && html[i - 1] != ' ';

				/* Don't match a* b */
				gboolean unspaced_begin = !s_italics && html[i + 1] != ' ';

				/* Don't match "*correction" or even "*correction *" */
				gboolean balanced = s_italics || markdown_char_later_unspaced(html, i, html_len, '*');

				if ((unspaced_begin || unspaced_end) && balanced) {
					HTML_TOGGLE_OUT(s_italics, "<i>", "</i>");
				} else {
					out = g_string_append_c(out, html[i]);
				}
			}
		} else if (c == '~' && html[i + 1] == '~') {
			HTML_TOGGLE_OUT(s_strikethrough, "<s>", "</s>");
			++i;
		} else if (c == '_') {
			if (html[i + 1] == '_') {
				HTML_TOGGLE_OUT(s_underline, "<u>", "</u>");
				++i;
			} else {
				if (markdown_should_underscore_italics(html, i, s_italics)) {
					HTML_TOGGLE_OUT(s_italics, "<i>", "</i>");
				} else {
					out = g_string_append_c(out, html[i]);
				}
			}
		} else if (c == '`') {
			if (html[i + 1] == '`' && html[i + 2] == '`') {
				if (!s_codeblock) {
#ifdef MARKDOWN_PIDGIN
					out = g_string_append(out, "<br/><span style='font-family: monospace; white-space: pre'>");
#else
					out = g_string_append(out, "<br/><pre>");
#endif
				} else {
#ifdef MARKDOWN_PIDGIN
					out = g_string_append(out, "</span>");
#else
					out = g_string_append(out, "</pre>");
#endif
					i += 2;
				}

				s_codeblock = !s_codeblock;
			} else {
#ifdef MARKDOWN_PIDGIN
				HTML_TOGGLE_OUT(s_codebit, "<span style='font-family: monospace; white-space: pre'>", "</span>");
#else
				HTML_TOGGLE_OUT(s_codebit, "<code>", "</code>");
#endif
			}
		} else {
			out = g_string_append_c(out, c);
		}
	}

	gchar *new_out = g_string_free(out, FALSE);
	return markdown_helper_replace(new_out, "\n", "<br>");
}

#define REPLACE_TAG(name, repl) \
	html = markdown_helper_replace(html, "<" name ">", repl); \
	html = markdown_helper_replace(html, "</" name ">", repl);

gchar *
markdown_html_to_markdown(gchar *html)
{
	REPLACE_TAG("b", "**");
	REPLACE_TAG("strong", "**");
	REPLACE_TAG("i", "*");
	REPLACE_TAG("em", "*");
	REPLACE_TAG("u", "__");
	REPLACE_TAG("s", "~~");
	REPLACE_TAG("pre", "```");
	REPLACE_TAG("code", "`");

	/* Let newlines get passed through as HTML */

	/* Workaround XHTML-IM stuff. TODO: XXX */
	html = markdown_helper_replace(html, "<span style='font-weight: bold;'>", "**");
	html = markdown_helper_replace(html, "</span>", "**");

	return html;
}

gchar *
markdown_escape_md(const gchar *markdown, gboolean discord_hacks)
{
	size_t markdown_len = strlen(markdown);
	/* Worst case allocation */
	GString *s = g_string_sized_new(markdown_len * 2);

	gboolean verbatim = FALSE;
	gboolean code_block = FALSE;
	gboolean link = FALSE;

	for (guint i = 0; i < markdown_len; ++i) {
		char c = markdown[i];

		if (c == '`') {
			if (code_block) {
				code_block = verbatim = FALSE;
			} else if (!verbatim) {
				code_block = verbatim = TRUE;
			}

			g_string_append_c(s, markdown[i]);

			if (markdown[i + 1] == '`' && markdown[i + 2] == '`') {
				i += 2;
				g_string_append_c(s, markdown[i]);
				g_string_append_c(s, markdown[i]);
				continue;
			}
		}

		if (!verbatim) {
			if (strncmp(markdown + i, "http://", sizeof("http://") - 1) == 0 ||
				strncmp(markdown + i, "https://", sizeof("https://") - 1) == 0)

			{
				link = verbatim = TRUE;
			}
		}

		if (link && c == ' ') {
			link = verbatim = FALSE;
		}

		if (!verbatim) {
			if (
			  (c == '_' && (markdown[i + 1] == ' ' ||
							markdown[i + 1] == '\0' ||
							i == 0 ||
							markdown[i - 1] == ' ' ||
							markdown[i - 1] == '\0')) ||
			  (c == '*') ||
			  (c == '\\' && !(markdown[i + 1] == '_' && (i == 0 || markdown[i - 1] == ' ')) && !discord_hacks) ||
			  (c == '~' && (markdown[i + 1] == '~'))) {
				g_string_append_c(s, '\\');
			}
		}

		g_string_append_c(s, c);
	}

	return g_string_free(s, FALSE);
}
