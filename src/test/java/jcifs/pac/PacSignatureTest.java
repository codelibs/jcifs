package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.Test;

/**
 * Tests for the PacSignature class.
 */
class PacSignatureTest {

    /**
     * Helper method to write integer in little-endian format.
     */
    private void writeLittleEndianInt(ByteArrayOutputStream baos, int value) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(value);
        baos.write(buffer.array(), 0, 4);
    }

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
        writeLittleEndianInt(baos, PacSignature.KERB_CHECKSUM_HMAC_MD5);
        byte[] checksum = new byte[16];
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        baos.write(checksum);
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
        writeLittleEndianInt(baos, PacSignature.HMAC_SHA1_96_AES128);
        byte[] checksum = new byte[12];
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        baos.write(checksum);
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
        writeLittleEndianInt(baos, PacSignature.HMAC_SHA1_96_AES256);
        byte[] checksum = new byte[12];
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        baos.write(checksum);
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
        int defaultType = 99;
        writeLittleEndianInt(baos, defaultType);
        byte[] checksum = new byte[10]; // Arbitrary length
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = (byte) i;
        }
        baos.write(checksum);
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
     * Test constructor with checksum too short for KERB_CHECKSUM_HMAC_MD5.
     */
    @Test
    void testConstructorChecksumTooShort() throws IOException {
        // Prepare data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeLittleEndianInt(baos, PacSignature.KERB_CHECKSUM_HMAC_MD5);
        // Write only 10 bytes instead of 16
        baos.write(new byte[10]);
        byte[] data = baos.toByteArray();

        // Verify that PACDecodingException is thrown
        assertThrows(PACDecodingException.class, () -> {
            new PacSignature(data);
        });
    }
}
