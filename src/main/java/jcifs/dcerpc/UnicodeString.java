/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc;

/**
 * Unicode string type wrapper
 *
 */
public class UnicodeString extends rpc.unicode_string {

    boolean zterm;

    /**
     *
     * @param zterm
     *            whether the string should be zero terminated
     */
    public UnicodeString(final boolean zterm) {
        this.zterm = zterm;
    }

    /**
     *
     * @param rus
     *            wrapped string
     * @param zterm
     *            whether the string should be zero terminated
     */
    public UnicodeString(final rpc.unicode_string rus, final boolean zterm) {
        this.length = rus.length;
        this.maximum_length = rus.maximum_length;
        this.buffer = rus.buffer;
        this.zterm = zterm;
    }

    /**
     *
     * @param str
     *            wrapped string
     * @param zterm
     *            whether the string should be zero terminated
     */
    public UnicodeString(final String str, final boolean zterm) {
        this.zterm = zterm;

        final int len = str.length();
        final int zt = zterm ? 1 : 0;

        this.length = this.maximum_length = (short) ((len + zt) * 2);
        this.buffer = new short[len + zt];

        int i;
        for (i = 0; i < len; i++) {
            this.buffer[i] = (short) str.charAt(i);
        }
        if (zterm) {
            this.buffer[i] = (short) 0;
        }
    }

    @Override
    public String toString() {
        final int len = this.length / 2 - (this.zterm ? 1 : 0);
        final char[] ca = new char[len];
        for (int i = 0; i < len; i++) {
            ca[i] = (char) this.buffer[i];
        }
        return new String(ca, 0, len);
    }
}
