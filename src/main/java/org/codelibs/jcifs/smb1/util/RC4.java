/* Copyright (C) 2009 "Michael B Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1.util;

/**
 * Implementation of the RC4 (ARCFOUR) stream cipher algorithm.
 * This class provides RC4 encryption/decryption functionality used in SMB1 protocol operations.
 */
public class RC4 {

    byte[] s;
    int i, j;

    /**
     * Default constructor for RC4 cipher.
     * Call init() to initialize with a key before use.
     */
    public RC4() {
    }

    /**
     * Constructs and initializes an RC4 cipher with the specified key.
     *
     * @param key the encryption key
     */
    public RC4(final byte[] key) {
        init(key, 0, key.length);
    }

    /**
     * Initializes the RC4 cipher with a key.
     * This method sets up the RC4 state array using the key scheduling algorithm.
     *
     * @param key the key array
     * @param ki the starting offset in the key array
     * @param klen the length of the key to use
     */
    public void init(final byte[] key, final int ki, final int klen) {
        s = new byte[256];

        for (i = 0; i < 256; i++) {
            s[i] = (byte) i;
        }

        for (i = j = 0; i < 256; i++) {
            j = j + key[ki + i % klen] + s[i] & 0xff;
            final byte t = s[i];
            s[i] = s[j];
            s[j] = t;
        }

        i = j = 0;
    }

    /**
     * Encrypts or decrypts data using the RC4 stream cipher.
     * Since RC4 is a stream cipher, the same operation is used for both encryption and decryption.
     *
     * @param src the source data array
     * @param soff the offset in the source array
     * @param slen the length of data to process
     * @param dst the destination array for the result
     * @param doff the offset in the destination array
     */
    public void update(final byte[] src, int soff, final int slen, final byte[] dst, int doff) {
        int slim = soff + slen;
        while (soff < slim) {
            i = i + 1 & 0xff;
            j = j + s[i] & 0xff;
            final byte t = s[i];
            s[i] = s[j];
            s[j] = t;
            dst[doff] = (byte) (src[soff++] ^ s[s[i] + s[j] & 0xff]);
            doff++;
        }
    }
}
