/*
 * © 2026 CodeLibs, Inc.
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
package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.smb2.nego.EncryptionNegotiateContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Interoperability tests for SMB3 transform (encryption) handling.
 *
 * <p>
 * The AES-128-GCM vector below is a real SMB2 TREE_CONNECT response captured from Samba 4.23.8 with
 * {@code smb encrypt = required}. Unlike a self round-trip, it fails if this implementation disagrees with a real
 * server about the transform header layout, the additional authenticated data or the nonce length. The keys are
 * throw-away material from a local test container.
 * </p>
 */
class Smb3EncryptionInteropTest {

    /** SMB2 TRANSFORM_HEADER + ciphertext, exactly as Samba 4.23.8 put it on the wire. */
    private static final String SAMBA_TRANSFORM_MESSAGE = "fd534d42166b7cb493b2c0e8e7b99057dbe62335"
            + "01000000000000001143ba84000000004900000000000100e5fbad4c00000000" + "0eba618e39cd4c9860faeb1abcaca826b3d14657"
            + "f32fe842c6a1b34922a4dc1f2ce828ed149863300b3c8c6b004f15f930f772cc" + "ae4a14778fae80aa393ae2af6e82be2835231aa539";

    /** Session-to-client cipher key derived for that session. */
    private static final String SAMBA_DECRYPTION_KEY = "53A4662E590F584E41FFD762E053925D";

    /** The same, for an AES-128-CCM session: Samba 4.23.8 negotiated down to SMB 3.0.2. */
    private static final String SAMBA_CCM_TRANSFORM_MESSAGE =
            "fd534d42e0cef907f6d23d0d9013598a442d6d44" + "0100000000000000f961e0000000000050000000000001009de9b57700000000"
                    + "36ad7e5afc598b2ae698e590bc277a9b48d63336" + "874c61a11bba9d78e90f47e5e93661bf4ebf6181ba987be3a47a0466158aabb3"
                    + "ed8c56a843f7480930a252e8ad6378bfee7d19c3a4386b04df7594c8";

    private static final String SAMBA_CCM_DECRYPTION_KEY = "666A4C38B330CF2467D12D1CFA8EF6C6";

    private static final String SAMBA_CCM_PLAINTEXT = "FE534D42400000000000000003000100" + "01000000000000000400000000000000"
            + "00000000B650A9279DE9B57700000000" + "00000000000000000000000000000000" + "100001000080000000000000FF011F00";

    /** The plaintext Samba encrypted: an SMB2 TREE_CONNECT response carrying STATUS_ACCESS_DENIED. */
    private static final String SAMBA_PLAINTEXT = "FE534D4240000000220000C003000100" + "09000000000000000400000000000000"
            + "0000000000000000E5FBAD4C00000000" + "106E3667B09BE2591D9079FFDCAE58AB" + "090000000000000000";

    private static byte[] hex(final String s) {
        final byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static byte[] sampleMessage(final int len) {
        final byte[] msg = new byte[len];
        for (int i = 0; i < len; i++) {
            msg[i] = (byte) (0x40 + i % 0x50);
        }
        return msg;
    }

    @Test
    @DisplayName("decrypts a transform message produced by a real SMB3 server")
    void decryptsRealServerTransformMessage() throws Exception {
        final byte[] key = hex(SAMBA_DECRYPTION_KEY);
        final Smb2EncryptionContext ctx =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, key, key);

        final byte[] plaintext = ctx.decryptMessage(hex(SAMBA_TRANSFORM_MESSAGE));

        assertArrayEquals(hex(SAMBA_PLAINTEXT), plaintext, "decrypted payload must match the SMB2 message Samba sent");
    }

    @Test
    @DisplayName("decrypts an AES-128-CCM transform message produced by a real SMB3 server")
    void decryptsRealServerCcmTransformMessage() throws Exception {
        final byte[] key = hex(SAMBA_CCM_DECRYPTION_KEY);
        final Smb2EncryptionContext ctx =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_CCM, DialectVersion.SMB302, key, key);

        final byte[] plaintext = ctx.decryptMessage(hex(SAMBA_CCM_TRANSFORM_MESSAGE));

        assertArrayEquals(hex(SAMBA_CCM_PLAINTEXT), plaintext, "decrypted payload must match the SMB2 message Samba sent");
    }

    @Test
    @DisplayName("writes the transform protocol id in network byte order")
    void writesProtocolIdInNetworkByteOrder() throws Exception {
        final byte[] key = new byte[16];
        final Smb2EncryptionContext ctx =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, key, key);

        final byte[] wire = ctx.encryptMessage(sampleMessage(73), 0x1122334455667788L);

        assertEquals((byte) 0xFD, wire[0], "byte 0 must be 0xFD");
        assertEquals((byte) 'S', wire[1], "byte 1 must be 'S'");
        assertEquals((byte) 'M', wire[2], "byte 2 must be 'M'");
        assertEquals((byte) 'B', wire[3], "byte 3 must be 'B'");
    }

    @Test
    @DisplayName("AES-128-CCM decrypts what it encrypted")
    void aesCcmRoundTrips() throws Exception {
        final byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        final Smb2EncryptionContext ctx =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_CCM, DialectVersion.SMB300, key, key);

        final byte[] message = sampleMessage(73);
        final byte[] wire = ctx.encryptMessage(message, 0x1122334455667788L);

        assertArrayEquals(message, ctx.decryptMessage(wire), "AES-128-CCM must round-trip");
    }

    @Test
    @DisplayName("AES-128-GCM decrypts what it encrypted")
    void aesGcmRoundTrips() throws Exception {
        final byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        final Smb2EncryptionContext ctx =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, key, key);

        final byte[] message = sampleMessage(512);
        final byte[] wire = ctx.encryptMessage(message, 0x1122334455667788L);

        assertArrayEquals(message, ctx.decryptMessage(wire), "AES-128-GCM must round-trip");
    }

    @Test
    @DisplayName("zero-pads the nonce field beyond the cipher nonce length")
    void zeroPadsNonceField() throws Exception {
        final byte[] key = new byte[16];

        final Smb2EncryptionContext gcm =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, key, key);
        final byte[] gcmWire = gcm.encryptMessage(sampleMessage(64), 1L);
        for (int i = 20 + 12; i < 20 + 16; i++) {
            assertEquals(0, gcmWire[i], "AES-128-GCM nonce byte " + (i - 20) + " must be zero");
        }

        final Smb2EncryptionContext ccm =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_CCM, DialectVersion.SMB300, key, key);
        final byte[] ccmWire = ccm.encryptMessage(sampleMessage(64), 1L);
        for (int i = 20 + 11; i < 20 + 16; i++) {
            assertEquals(0, ccmWire[i], "AES-128-CCM nonce byte " + (i - 20) + " must be zero");
        }
    }

    @Test
    @DisplayName("never repeats a nonce for the same key")
    void neverRepeatsNonce() throws Exception {
        final byte[] key = new byte[16];
        final Smb2EncryptionContext ctx =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, key, key);

        final java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < 2000; i++) {
            final byte[] wire = ctx.encryptMessage(sampleMessage(16), 1L);
            final StringBuilder sb = new StringBuilder();
            for (int j = 20; j < 36; j++) {
                sb.append(String.format("%02X", wire[j]));
            }
            assertEquals(true, seen.add(sb.toString()), "nonce repeated after " + i + " messages");
        }
    }
}
