/* HMACT64 keyed hashing algorithm
 * Copyright (C) 2003 "Eric Glass" <jcifs at samba dot org>
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

import java.security.MessageDigest;

/**
 * This is an implementation of the HMACT64 keyed hashing algorithm.
 * HMACT64 is defined by Luke Leighton as a modified HMAC-MD5 (RFC 2104)
 * in which the key is truncated at 64 bytes (rather than being hashed
 * via MD5).
 */
public class HMACT64 extends MessageDigest implements Cloneable {

    private static final int BLOCK_LENGTH = 64;

    private static final byte IPAD = (byte) 0x36;

    private static final byte OPAD = (byte) 0x5c;

    private MessageDigest md5;

    private byte[] ipad = new byte[BLOCK_LENGTH];

    private byte[] opad = new byte[BLOCK_LENGTH];

    /**
     * Creates an HMACT64 instance which uses the given secret key material.
     *
     * @param key The key material to use in hashing.
     */
    public HMACT64(final byte[] key) {
        super("HMACT64");
        final int length = Math.min(key.length, BLOCK_LENGTH);
        for (int i = 0; i < length; i++) {
            ipad[i] = (byte) (key[i] ^ IPAD);
            opad[i] = (byte) (key[i] ^ OPAD);
        }
        for (int i = length; i < BLOCK_LENGTH; i++) {
            ipad[i] = IPAD;
            opad[i] = OPAD;
        }
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (final Exception ex) {
            throw new IllegalStateException(ex.getMessage());
        }
        engineReset();
    }

    private HMACT64(final HMACT64 hmac) throws CloneNotSupportedException {
        super("HMACT64");
        this.ipad = hmac.ipad;
        this.opad = hmac.opad;
        this.md5 = (MessageDigest) hmac.md5.clone();
    }

    @Override
    public Object clone() {
        try {
            return new HMACT64(this);
        } catch (final CloneNotSupportedException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    @Override
    protected byte[] engineDigest() {
        final byte[] digest = md5.digest();
        md5.update(opad);
        return md5.digest(digest);
    }

    @Override
    protected int engineDigest(final byte[] buf, final int offset, final int len) {
        final byte[] digest = md5.digest();
        md5.update(opad);
        md5.update(digest);
        try {
            return md5.digest(buf, offset, len);
        } catch (final Exception ex) {
            throw new IllegalStateException();
        }
    }

    @Override
    protected int engineGetDigestLength() {
        return md5.getDigestLength();
    }

    @Override
    protected void engineReset() {
        md5.reset();
        md5.update(ipad);
    }

    @Override
    protected void engineUpdate(final byte b) {
        md5.update(b);
    }

    @Override
    protected void engineUpdate(final byte[] input, final int offset, final int len) {
        md5.update(input, offset, len);
    }

}
