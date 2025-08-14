package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.junit.jupiter.api.Test;

import jcifs.SmbConstants;
import jcifs.smb.SID;

public class PacDataInputStreamTest {

    // Helper to create PacDataInputStream from a byte array
    private PacDataInputStream createInputStream(byte[] data) throws IOException {
        return new PacDataInputStream(new ByteArrayInputStream(data));
    }

    @Test
    public void testAlign() throws IOException {
        // Test alignment from position 1 to 4
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        PacDataInputStream pdis = createInputStream(data);
        pdis.readByte(); // position is 1
        pdis.align(4);
        assertEquals(1, pdis.available());
        assertEquals(0x05, pdis.readByte());

        // Test no alignment needed
        pdis = createInputStream(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        pdis.readInt(); // position is 4
        pdis.align(4);
        assertEquals(0, pdis.available());

        // Test alignment with mask 0
        pdis = createInputStream(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        pdis.readByte(); // position is 1
        pdis.align(0);
        assertEquals(3, pdis.available());
    }

    @Test
    public void testAvailable() throws IOException {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals(4, pdis.available());
        pdis.readByte();
        assertEquals(3, pdis.available());
    }

    @Test
    public void testReadFully() throws IOException {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        PacDataInputStream pdis = createInputStream(data);
        byte[] buffer = new byte[4];
        pdis.readFully(buffer);
        assertArrayEquals(data, buffer);
    }

    @Test
    public void testReadFullyWithOffset() throws IOException {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        PacDataInputStream pdis = createInputStream(data);
        byte[] buffer = new byte[6];
        pdis.readFully(buffer, 1, 4);
        assertArrayEquals(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x00 }, buffer);
    }

    @Test
    public void testReadChar() throws IOException {
        // 0x0041 is 'A'
        byte[] data = new byte[] { 0x00, 0x41, 0x00, 0x00 };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals('A', pdis.readChar());
    }

    @Test
    public void testReadByte() throws IOException {
        byte[] data = new byte[] { 0x7F };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals(0x7F, pdis.readByte());
    }

    @Test
    public void testReadShort() throws IOException {
        // Little-endian 0x1234 -> 0x34 0x12
        byte[] data = new byte[] { 0x34, 0x12, 0x00, 0x00 };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals((short) 0x1234, pdis.readShort());
    }

    @Test
    public void testReadInt() throws IOException {
        // Little-endian 0x12345678 -> 0x78 0x56 0x34 0x12
        byte[] data = new byte[] { 0x78, 0x56, 0x34, 0x12 };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals(0x12345678, pdis.readInt());
    }

    @Test
    public void testReadLong() throws IOException {
        // Little-endian 0x123456789ABCDEF0 -> 0xF0 0xDE 0xBC 0x9A 0x78 0x56 0x34 0x12
        byte[] data = new byte[] { (byte) 0xF0, (byte) 0xDE, (byte) 0xBC, (byte) 0x9A, 0x78, 0x56, 0x34, 0x12 };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals(0x123456789ABCDEF0L, pdis.readLong());
    }

    @Test
    public void testReadUnsignedByte() throws IOException {
        byte[] data = new byte[] { (byte) 0xFF };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals(255, pdis.readUnsignedByte());
    }

    @Test
    public void testReadUnsignedShort() throws IOException {
        // Little-endian 0xFFFF -> 0xFF 0xFF
        byte[] data = new byte[] { (byte) 0xFF, (byte) 0xFF, 0x00, 0x00 };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals(0xFFFF, pdis.readUnsignedShort());
    }

    @Test
    public void testReadUnsignedInt() throws IOException {
        // Little-endian 0xFFFFFFFF -> 0xFF 0xFF 0xFF 0xFF
        byte[] data = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
        PacDataInputStream pdis = createInputStream(data);
        assertEquals(0xFFFFFFFFL, pdis.readUnsignedInt());
    }

    @Test
    public void testReadFiletime() throws IOException {
        // A non-null date
        long time = System.currentTimeMillis();
        BigInteger filetime = BigInteger.valueOf(time)
                .add(BigInteger.valueOf(SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601))
                .multiply(BigInteger.valueOf(10000L));

        byte[] data = new byte[8];
        long low = filetime.longValue();
        long high = filetime.shiftRight(32).longValue();

        // write little-endian
        data[0] = (byte) (low);
        data[1] = (byte) (low >> 8);
        data[2] = (byte) (low >> 16);
        data[3] = (byte) (low >> 24);
        data[4] = (byte) (high);
        data[5] = (byte) (high >> 8);
        data[6] = (byte) (high >> 16);
        data[7] = (byte) (high >> 24);

        PacDataInputStream pdis = createInputStream(data);
        Date date = pdis.readFiletime();
        assertNotNull(date);
        // Allow for a small difference due to precision loss
        assertEquals(time / 1000, date.getTime() / 1000);

        // Test with null date (0x7fffffff ffffffff)
        byte[] nullData = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x7f };
        pdis = createInputStream(nullData);
        assertNull(pdis.readFiletime());
    }

    @Test
    public void testReadUnicodeString() throws IOException, PACDecodingException {
        // length=4, maxLength=4, pointer=0x1234
        byte[] data = new byte[] { 0x04, 0x00, 0x04, 0x00, 0x34, 0x12, 0x00, 0x00 };
        PacDataInputStream pdis = createInputStream(data);
        PacUnicodeString str = pdis.readUnicodeString();
        assertEquals(4, str.getLength());
        assertEquals(4, str.getMaxLength());
        assertEquals(0x1234, str.getPointer());
    }

    @Test
    public void testReadUnicodeStringMalformed() throws IOException {
        // length > maxLength
        byte[] data = new byte[] { 0x08, 0x00, 0x04, 0x00, 0x34, 0x12, 0x00, 0x00 };
        PacDataInputStream pdis = createInputStream(data);
        assertThrows(PACDecodingException.class, () -> pdis.readUnicodeString());
    }

    @Test
    public void testReadString() throws IOException, PACDecodingException {
        // total=4, unused=1, used=2, string="AB"
        byte[] data = new byte[] { 0x04, 0x00, 0x00, 0x00, // total
                0x01, 0x00, 0x00, 0x00, // unused
                0x02, 0x00, 0x00, 0x00, // used
                0x00, 0x00, // unused char
                0x41, 0x00, // 'A'
                0x42, 0x00 // 'B'
        };
        PacDataInputStream pdis = createInputStream(data);
        String str = pdis.readString();
        assertEquals("AB", str);
    }

    @Test
    public void testReadStringMalformed() throws IOException {
        // unused > total
        byte[] data = new byte[] { 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
        PacDataInputStream pdis = createInputStream(data);
        assertThrows(PACDecodingException.class, () -> pdis.readString());
    }

    @Test
    public void testReadId() throws IOException, PACDecodingException {
        // RID = 0x12345678 (305419896 in decimal, little-endian)
        byte[] data = new byte[] { 0x78, 0x56, 0x34, 0x12 };
        PacDataInputStream pdis = createInputStream(data);
        SID sid = pdis.readId();
        // The readId method creates a SID with authority 5 and the RID value
        // Expected format: S-1-5-305419896
        String sidString = sid.toString();
        assertNotNull(sidString);
        assertEquals("S-1-5-305419896", sidString);
    }

    @Test
    public void testReadSid() throws IOException, PACDecodingException {
        // A simple SID: S-1-1-0
        byte[] data = new byte[] { 0x01, 0x00, 0x00, 0x00, // sidSize = 1
                0x01, // revision
                0x01, // sub-authority count
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // authority
                0x00, 0x00, 0x00, 0x00 // sub-authority 1
        };
        PacDataInputStream pdis = createInputStream(data);
        SID sid = pdis.readSid();
        assertEquals("S-1-1-0", sid.toString());
    }

    @Test
    public void testSkipBytes() throws IOException {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        PacDataInputStream pdis = createInputStream(data);
        int skipped = pdis.skipBytes(2);
        assertEquals(2, skipped);
        assertEquals(2, pdis.available());
        assertEquals(0x03, pdis.readByte());
    }
}
