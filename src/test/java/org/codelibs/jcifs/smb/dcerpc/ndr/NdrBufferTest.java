package org.codelibs.jcifs.smb.dcerpc.ndr;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.codelibs.jcifs.smb.util.Encdec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class NdrBufferTest {

    private byte[] buffer;
    private NdrBuffer ndrBuffer;

    @BeforeEach
    void setUp() {
        buffer = new byte[1024]; // Initialize with a reasonable size
        ndrBuffer = new NdrBuffer(buffer, 0);
    }

    @Test
    void testConstructor() {
        // Verify initial state
        assertEquals(0, ndrBuffer.start);
        assertEquals(0, ndrBuffer.index);
        assertEquals(0, ndrBuffer.length);
        assertSame(ndrBuffer, ndrBuffer.deferred);
        assertSame(buffer, ndrBuffer.buf);

        // Test with a different start offset
        NdrBuffer offsetBuffer = new NdrBuffer(buffer, 10);
        assertEquals(10, offsetBuffer.start);
        assertEquals(10, offsetBuffer.index);
        assertEquals(0, offsetBuffer.length);
    }

    @Test
    void testDerive() {
        ndrBuffer.advance(50); // Advance the original buffer
        NdrBuffer derivedBuffer = ndrBuffer.derive(10);

        // Verify derived buffer properties
        assertSame(buffer, derivedBuffer.buf);
        assertEquals(0, derivedBuffer.start); // Derived buffer starts from the original buffer's start
        assertEquals(10, derivedBuffer.index);
        assertSame(ndrBuffer.deferred, derivedBuffer.deferred); // Deferred should be the same as original

        // Ensure changes to derived buffer don't affect original's index/start
        derivedBuffer.advance(5);
        assertEquals(15, derivedBuffer.index);
        assertEquals(50, ndrBuffer.index); // Original index should be unchanged
    }

    @Test
    void testReset() {
        ndrBuffer.advance(100);
        ndrBuffer.setLength(150);
        ndrBuffer.reset();

        // Verify reset state
        assertEquals(0, ndrBuffer.index);
        assertEquals(0, ndrBuffer.length);
        assertSame(ndrBuffer, ndrBuffer.deferred);
    }

    @Test
    void testGetAndSetIndex() {
        ndrBuffer.setIndex(50);
        assertEquals(50, ndrBuffer.getIndex());
    }

    @Test
    void testGetCapacity() {
        assertEquals(buffer.length, ndrBuffer.getCapacity());

        NdrBuffer offsetBuffer = new NdrBuffer(buffer, 100);
        assertEquals(buffer.length - 100, offsetBuffer.getCapacity());
    }

    @Test
    void testGetTailSpace() {
        ndrBuffer.setIndex(100);
        assertEquals(buffer.length - 100, ndrBuffer.getTailSpace());
    }

    @Test
    void testGetBuffer() {
        assertSame(buffer, ndrBuffer.getBuffer());
    }

    @Test
    void testAlignWithValue() {
        // Align to 4-byte boundary with a fill value
        ndrBuffer.setIndex(1);
        int alignedBytes = ndrBuffer.align(4, (byte) 0xFF);
        assertEquals(3, alignedBytes); // Should advance by 3 bytes (1 -> 4)
        assertEquals(4, ndrBuffer.getIndex());
        assertEquals(4, ndrBuffer.getLength()); // Length should be updated

        // Verify filled bytes
        assertEquals((byte) 0xFF, buffer[1]);
        assertEquals((byte) 0xFF, buffer[2]);
        assertEquals((byte) 0xFF, buffer[3]);

        // Already aligned
        ndrBuffer.setIndex(4);
        alignedBytes = ndrBuffer.align(4, (byte) 0x00);
        assertEquals(0, alignedBytes);
        assertEquals(4, ndrBuffer.getIndex());
    }

    @Test
    void testWriteOctetArray() {
        byte[] data = { 0x01, 0x02, 0x03, 0x04 };
        ndrBuffer.writeOctetArray(data, 0, data.length);

        assertEquals(data.length, ndrBuffer.getIndex());
        assertEquals(data.length, ndrBuffer.getLength());
        assertArrayEquals(data, Arrays.copyOfRange(buffer, 0, data.length));

        // Write with offset and length
        ndrBuffer.setIndex(10);
        byte[] partialData = { 0x05, 0x06, 0x07, 0x08, 0x09 };
        ndrBuffer.writeOctetArray(partialData, 1, 3); // Write 0x06, 0x07, 0x08

        assertEquals(13, ndrBuffer.getIndex());
        assertEquals(13, ndrBuffer.getLength());
        assertEquals(0x06, buffer[10]);
        assertEquals(0x07, buffer[11]);
        assertEquals(0x08, buffer[12]);
    }

    @Test
    void testReadOctetArray() {
        byte[] sourceData = { 0x10, 0x11, 0x12, 0x13, 0x14 };
        System.arraycopy(sourceData, 0, buffer, 0, sourceData.length);

        byte[] destData = new byte[5];
        ndrBuffer.readOctetArray(destData, 0, sourceData.length);

        assertEquals(sourceData.length, ndrBuffer.getIndex());
        assertEquals(sourceData.length, ndrBuffer.getLength()); // Length is updated on read too
        assertArrayEquals(sourceData, destData);

        // Read with offset and length
        ndrBuffer.setIndex(0);
        Arrays.fill(destData, (byte) 0x00); // Clear destData
        ndrBuffer.readOctetArray(destData, 1, 3); // Read 0x10, 0x11, 0x12 into destData[1-3]

        assertEquals(3, ndrBuffer.getIndex());
        assertEquals(0x00, destData[0]);
        assertEquals(0x10, destData[1]);
        assertEquals(0x11, destData[2]);
        assertEquals(0x12, destData[3]);
        assertEquals(0x00, destData[4]);
    }

    @Test
    void testGetLengthAndSetLength() {
        ndrBuffer.advance(10);
        assertEquals(10, ndrBuffer.getLength());

        ndrBuffer.setLength(20);
        assertEquals(20, ndrBuffer.getLength());

        // Test with derived buffer
        NdrBuffer derived = ndrBuffer.derive(0);
        derived.setLength(5);
        assertEquals(5, derived.getLength());
        assertEquals(5, ndrBuffer.getLength()); // Should affect original's deferred length
    }

    @Test
    void testAdvance() {
        ndrBuffer.advance(10);
        assertEquals(10, ndrBuffer.getIndex());
        assertEquals(10, ndrBuffer.getLength());

        ndrBuffer.advance(5);
        assertEquals(15, ndrBuffer.getIndex());
        assertEquals(15, ndrBuffer.getLength());

        // Advance past current length
        ndrBuffer.setLength(10);
        ndrBuffer.setIndex(10);
        ndrBuffer.advance(10);
        assertEquals(20, ndrBuffer.getIndex());
        assertEquals(20, ndrBuffer.getLength()); // Length should be updated
    }

    @Test
    void testAlign() {
        // Align to 4-byte boundary
        ndrBuffer.setIndex(1);
        int alignedBytes = ndrBuffer.align(4);
        assertEquals(3, alignedBytes); // Should advance by 3 bytes (1 -> 4)
        assertEquals(4, ndrBuffer.getIndex());
        assertEquals(4, ndrBuffer.getLength()); // Length should be updated

        // Already aligned
        ndrBuffer.setIndex(4);
        alignedBytes = ndrBuffer.align(4);
        assertEquals(0, alignedBytes);
        assertEquals(4, ndrBuffer.getIndex());

        // Align to 8-byte boundary
        ndrBuffer.setIndex(5);
        alignedBytes = ndrBuffer.align(8);
        assertEquals(3, alignedBytes); // Should advance by 3 bytes (5 -> 8)
        assertEquals(8, ndrBuffer.getIndex());
    }

    @Test
    void testEncDecNdrSmall() {
        ndrBuffer.enc_ndr_small(0xAB);
        assertEquals(1, ndrBuffer.getIndex());
        assertEquals(1, ndrBuffer.getLength());
        assertEquals((byte) 0xAB, buffer[0]);

        ndrBuffer.setIndex(0); // Reset index for reading
        int val = ndrBuffer.dec_ndr_small();
        assertEquals(0xAB, val);
        assertEquals(1, ndrBuffer.getIndex());
    }

    @Test
    void testEncDecNdrShort() {
        ndrBuffer.enc_ndr_short(0xABCD);
        assertEquals(2, ndrBuffer.getIndex()); // Aligned to 2, then advanced by 2
        assertEquals(2, ndrBuffer.getLength());
        assertEquals((byte) 0xCD, buffer[0]); // Little-endian
        assertEquals((byte) 0xAB, buffer[1]);

        ndrBuffer.setIndex(0);
        int val = ndrBuffer.dec_ndr_short() & 0xFFFF;
        assertEquals(0xABCD, val);
        assertEquals(2, ndrBuffer.getIndex());

        // Test with offset and alignment
        ndrBuffer.setIndex(1);
        ndrBuffer.enc_ndr_short(0x1234);
        assertEquals(4, ndrBuffer.getIndex()); // Aligned from 1 to 2, then advanced by 2
        assertEquals(4, ndrBuffer.getLength());
        assertEquals((byte) 0x34, buffer[2]);
        assertEquals((byte) 0x12, buffer[3]);

        ndrBuffer.setIndex(2);
        val = ndrBuffer.dec_ndr_short();
        assertEquals(0x1234, val);
        assertEquals(4, ndrBuffer.getIndex());
    }

    @Test
    void testEncDecNdrLong() {
        ndrBuffer.enc_ndr_long(0xDEADBEEF);
        assertEquals(4, ndrBuffer.getIndex()); // Aligned to 4, then advanced by 4
        assertEquals(4, ndrBuffer.getLength());
        assertEquals((byte) 0xEF, buffer[0]); // Little-endian
        assertEquals((byte) 0xBE, buffer[1]);
        assertEquals((byte) 0xAD, buffer[2]);
        assertEquals((byte) 0xDE, buffer[3]);

        ndrBuffer.setIndex(0);
        int val = ndrBuffer.dec_ndr_long();
        assertEquals(0xDEADBEEF, val);
        assertEquals(4, ndrBuffer.getIndex());
    }

    @Test
    void testEncDecNdrHyper() {
        ndrBuffer.enc_ndr_hyper(0x0123456789ABCDEFL);
        assertEquals(8, ndrBuffer.getIndex()); // Aligned to 8, then advanced by 8
        assertEquals(8, ndrBuffer.getLength());
        assertEquals((byte) 0xEF, buffer[0]); // Little-endian
        assertEquals((byte) 0xCD, buffer[1]);
        assertEquals((byte) 0xAB, buffer[2]);
        assertEquals((byte) 0x89, buffer[3]);
        assertEquals((byte) 0x67, buffer[4]);
        assertEquals((byte) 0x45, buffer[5]);
        assertEquals((byte) 0x23, buffer[6]);
        assertEquals((byte) 0x01, buffer[7]);

        ndrBuffer.setIndex(0);
        long val = ndrBuffer.dec_ndr_hyper();
        assertEquals(0x0123456789ABCDEFL, val);
        assertEquals(8, ndrBuffer.getIndex());
    }

    @Test
    void testEncDecNdrString() throws NdrException {
        String testString = "Hello World";
        ndrBuffer.enc_ndr_string(testString);

        // Expected length: 4 (actual_count) + 4 (offset) + 4 (max_count) + len*2 (unicode) + 2 (null terminator)
        int expectedLength = 4 + 4 + 4 + (testString.length() * 2) + 2;
        assertEquals(expectedLength, ndrBuffer.getIndex());
        assertEquals(expectedLength, ndrBuffer.getLength());

        // Verify content (simplified check, full verification would involve decoding)
        assertEquals(testString.length() + 1, Encdec.dec_uint32le(buffer, 0)); // Actual count
        assertEquals(0, Encdec.dec_uint32le(buffer, 4)); // Offset
        assertEquals(testString.length() + 1, Encdec.dec_uint32le(buffer, 8)); // Max count

        ndrBuffer.setIndex(0);
        String decodedString = ndrBuffer.dec_ndr_string();
        assertEquals(testString, decodedString);
        assertEquals(expectedLength, ndrBuffer.getIndex());

        // Test empty string
        ndrBuffer.reset();
        String emptyString = "";
        ndrBuffer.enc_ndr_string(emptyString);
        expectedLength = 4 + 4 + 4 + (emptyString.length() * 2) + 2;
        assertEquals(expectedLength, ndrBuffer.getIndex());
        assertEquals(expectedLength, ndrBuffer.getLength());

        ndrBuffer.setIndex(0);
        decodedString = ndrBuffer.dec_ndr_string();
        assertEquals(emptyString, decodedString);
        assertEquals(expectedLength, ndrBuffer.getIndex());

        // Test null string (should encode as 0 length)
        ndrBuffer.reset();
        ndrBuffer.enc_ndr_referent(null, 2); // Use referent to encode null
        assertEquals(4, ndrBuffer.getIndex());
        assertEquals(4, ndrBuffer.getLength());
        assertEquals(0, Encdec.dec_uint32le(buffer, 0)); // Should be 0 for null referent
    }

    @Test
    void testDecNdrStringInvalidConformance() {
        // Simulate a string with invalid size
        ndrBuffer.setIndex(0);
        Encdec.enc_uint32le(0xFFFF + 1, buffer, 0); // len = 0xFFFF + 1
        Encdec.enc_uint32le(0, buffer, 4);
        Encdec.enc_uint32le(0xFFFF + 1, buffer, 8);

        ndrBuffer.setIndex(0);
        NdrException thrown = assertThrows(NdrException.class, () -> {
            ndrBuffer.dec_ndr_string();
        });
        assertEquals(NdrException.INVALID_CONFORMANCE, thrown.getMessage());
    }

    @Test
    void testEncNdrReferent() {
        Object obj1 = new Object();
        Object obj2 = new Object();

        // Test unique/ref type (type 1 or 3)
        ndrBuffer.enc_ndr_referent(obj1, 1);
        assertEquals(4, ndrBuffer.getIndex());
        assertEquals(System.identityHashCode(obj1), Encdec.dec_uint32le(buffer, 0));

        ndrBuffer.reset();
        ndrBuffer.enc_ndr_referent(obj2, 3);
        assertEquals(4, ndrBuffer.getIndex());
        assertEquals(System.identityHashCode(obj2), Encdec.dec_uint32le(buffer, 0));

        // Test ptr type (type 2) - uses internal referent map
        ndrBuffer.reset();
        ndrBuffer.enc_ndr_referent(obj1, 2);
        assertEquals(4, ndrBuffer.getIndex());
        int referent1 = Encdec.dec_uint32le(buffer, 0);
        assertTrue(referent1 > 0); // Should be a positive referent ID

        ndrBuffer.reset();
        ndrBuffer.enc_ndr_referent(obj1, 2); // Same object, should get same referent
        assertEquals(4, ndrBuffer.getIndex());
        assertEquals(referent1, Encdec.dec_uint32le(buffer, 0));

        ndrBuffer.reset();
        ndrBuffer.enc_ndr_referent(obj2, 2); // Different object, new referent
        assertEquals(4, ndrBuffer.getIndex());
        int referent2 = Encdec.dec_uint32le(buffer, 0);
        assertTrue(referent2 > 0);
        assertNotEquals(referent1, referent2);

        // Test null object
        ndrBuffer.reset();
        ndrBuffer.enc_ndr_referent(null, 1);
        assertEquals(4, ndrBuffer.getIndex());
        assertEquals(0, Encdec.dec_uint32le(buffer, 0)); // Should encode 0 for null
    }

    @Test
    void testToString() {
        ndrBuffer.setIndex(10);
        ndrBuffer.setLength(20); // Set length directly for toString test
        String expected = "start=0,index=10,length=20";
        assertEquals(expected, ndrBuffer.toString());

        NdrBuffer offsetBuffer = new NdrBuffer(buffer, 5);
        offsetBuffer.setIndex(15);
        offsetBuffer.setLength(10);
        expected = "start=5,index=15,length=10";
        assertEquals(expected, offsetBuffer.toString());
    }
}
