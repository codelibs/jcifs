/*
 * © 2017 Matthias Bläsing <mblaesing@doppel-helix.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.codelibs.jcifs.smb.internal.util;

/**
 * Utility class providing string manipulation methods for the jCIFS library.
 * Contains helper methods for string operations, including backported JDK functionality
 * for compatibility with older Java versions.
 */
public final class StringUtil {

    /**
     *
     */
    private StringUtil() {
    }

    /**
     * Implementation of {@link java.lang.String#join} backported for JDK7.
     *
     * @param delimiter the separator to use between elements
     * @param elements the elements to join
     * @return elements separated by delimiter
     */
    public static String join(final CharSequence delimiter, final CharSequence... elements) {
        final StringBuilder sb = new StringBuilder();
        for (final CharSequence element : elements) {
            if (sb.length() > 0) {
                if (delimiter != null) {
                    sb.append(delimiter);
                } else {
                    sb.append("null");
                }
            }
            sb.append(element);
        }
        return sb.toString();
    }
}
