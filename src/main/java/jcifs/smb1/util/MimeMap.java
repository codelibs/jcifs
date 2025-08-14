/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb1.util;

import java.io.IOException;
import java.io.InputStream;

/**
 * MIME type mapping utility for file extensions.
 * Provides mappings between file extensions and their corresponding MIME types
 * by reading from a resource file containing extension-to-MIME-type mappings.
 */
public class MimeMap {

    private static final int IN_SIZE = 7000;

    private static final int ST_START = 1;
    private static final int ST_COMM = 2;
    private static final int ST_TYPE = 3;
    private static final int ST_GAP = 4;
    private static final int ST_EXT = 5;

    private final byte[] in;
    private int inLen;

    /**
     * Creates a new MimeMap instance by loading MIME type mappings from the resource file.
     *
     * @throws IOException if there is an error reading the mime.map resource file
     */
    public MimeMap() throws IOException {
        int n;

        in = new byte[IN_SIZE];
        final InputStream is = getClass().getClassLoader().getResourceAsStream("jcifs/smb1/util/mime.map");

        inLen = 0;
        while ((n = is.read(in, inLen, IN_SIZE - inLen)) != -1) {
            inLen += n;
        }
        if (inLen < 100 || inLen == IN_SIZE) {
            throw new IOException("Error reading jcifs/smb1/util/mime.map resource");
        }
        is.close();
    }

    /**
     * Returns the MIME type for the given file extension.
     * If no mapping is found, returns "application/octet-stream" as the default.
     *
     * @param extension the file extension to look up (without the dot)
     * @return the MIME type for the extension, or "application/octet-stream" if not found
     * @throws IOException if there is an error processing the MIME mappings
     */
    public String getMimeType(final String extension) throws IOException {
        return getMimeType(extension, "application/octet-stream");
    }

    /**
     * Returns the MIME type for the given file extension with a custom default.
     *
     * @param extension the file extension to look up (without the dot)
     * @param def the default MIME type to return if no mapping is found
     * @return the MIME type for the extension, or the specified default if not found
     * @throws IOException if there is an error processing the MIME mappings
     */
    public String getMimeType(final String extension, final String def) throws IOException {
        int state, t, x, i, off;
        byte ch;
        final byte[] type = new byte[128];
        final byte[] buf = new byte[16];
        final byte[] ext = extension.toLowerCase().getBytes("ASCII");

        state = ST_START;
        t = x = i = 0;
        for (off = 0; off < inLen; off++) {
            ch = in[off];
            switch (state) {
            case ST_START:
                if (ch == ' ' || ch == '\t') {
                    break;
                }
                if (ch == '#') {
                    state = ST_COMM;
                    break;
                }
                state = ST_TYPE;
            case ST_TYPE:
                if (ch == ' ' || ch == '\t') {
                    state = ST_GAP;
                } else {
                    type[t++] = ch;
                }
                break;
            case ST_COMM:
                if (ch == '\n') {
                    t = x = i = 0;
                    state = ST_START;
                }
                break;
            case ST_GAP:
                if (ch == ' ' || ch == '\t') {
                    break;
                }
                state = ST_EXT;
            case ST_EXT:
                switch (ch) {
                case ' ':
                case '\t':
                case '\n':
                case '#':
                    for (i = 0; i < x && x == ext.length && buf[i] == ext[i]; i++) {

                    }
                    if (i == ext.length) {
                        return new String(type, 0, t, "ASCII");
                    }
                    if (ch == '#') {
                        state = ST_COMM;
                    } else if (ch == '\n') {
                        t = x = i = 0;
                        state = ST_START;
                    }
                    x = 0;
                    break;
                default:
                    buf[x] = ch;
                    x++;
                }
                break;
            }
        }
        return def;
    }
}
