/*
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
package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;
import jcifs.pac.PACDecodingException;

/**
 * Tests for the PacSignature class.
 */
class PacSignatureTest {

    /**
     * Test constructor with KERB_CHECKSUM_HMAC_MD5 type.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the PAC is malformed
     */
    @Test
    void testConstructorKerbChecksumHmacMd5() throws IOException, PACDecodingException {
        // Prepare data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(PacSignature.KERB_CHECKSUM_HMAC_MD5);
        byte[] checksum = new byte[16];
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        dos.write(checksum);
        byte[] data = baos.toByteArray();

        // Create PacSignature
        PacSignature pacSignature = new PacSignature(data);

        // Verify
        assertEquals(PacSignature.KERB_CHECKSUM_HMAC_MD5, pacSignature.getType());
        assertArrayEquals(checksum, pacSignature.getChecksum());
    }

    /**
     * Test constructor with HMAC_SHA1_96_AES128 type.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the PAC is malformed
     */
    @Test
    void testConstructorHmacSha1Aes128() throws IOException, PACDecodingException {
        // Prepare data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(PacSignature.HMAC_SHA1_96_AES128);
        byte[] checksum = new byte[12];
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        dos.write(checksum);
        byte[] data = baos.toByteArray();

        // Create PacSignature
        PacSignature pacSignature = new PacSignature(data);

        // Verify
        assertEquals(PacSignature.HMAC_SHA1_96_AES128, pacSignature.getType());
        assertArrayEquals(checksum, pacSignature.getChecksum());
    }

    /**
     * Test constructor with HMAC_SHA1_96_AES256 type.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the PAC is malformed
     */
    @Test
    void testConstructorHmacSha1Aes256() throws IOException, PACDecodingException {
        // Prepare data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(PacSignature.HMAC_SHA1_96_AES256);
        byte[] checksum = new byte[12];
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        dos.write(checksum);
        byte[] data = baos.toByteArray();

        // Create PacSignature
        PacSignature pacSignature = new PacSignature(data);

        // Verify
        assertEquals(PacSignature.HMAC_SHA1_96_AES256, pacSignature.getType());
        assertArrayEquals(checksum, pacSignature.getChecksum());
    }

    /**
     * Test constructor with a default type.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the PAC is malformed
     */
    @Test
    void testConstructorDefaultType() throws IOException, PACDecodingException {
        // Prepare data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        int defaultType = 99;
        dos.writeInt(defaultType);
        byte[] checksum = new byte[10]; // Arbitrary length
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        dos.write(checksum);
        byte[] data = baos.toByteArray();

        // Create PacSignature
        PacSignature pacSignature = new PacSignature(data);

        // Verify
        assertEquals(defaultType, pacSignature.getType());
        assertArrayEquals(checksum, pacSignature.getChecksum());
    }

    /**
     * Test constructor with malformed data (too short).
     */
    @Test
    void testConstructorMalformedData() {
        // Prepare data (only 2 bytes, less than an int)
        byte[] data = new byte[] { 0x01, 0x02 };

        // Verify that PACDecodingException is thrown
        assertThrows(PACDecodingException.class, () -> {
            new PacSignature(data);
        });
    }
    
    /**
     * Test constructor with malformed data (checksum too short).
     */
    @Test
    void testConstructorChecksumTooShort() throws IOException {
        // Prepare data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(PacSignature.KERB_CHECKSUM_HMAC_MD5);
        // Write only 10 bytes instead of 16
        dos.write(new byte[10]);
        byte[] data = baos.toByteArray();

        // Verify that PACDecodingException is thrown
        assertThrows(PACDecodingException.class, () -> {
            new PacSignature(data);
        });
    }
}
