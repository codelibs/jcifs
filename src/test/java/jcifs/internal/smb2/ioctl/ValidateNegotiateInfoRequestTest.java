package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.internal.util.SMBUtil;

/**
 * Test class for ValidateNegotiateInfoRequest
 */
class ValidateNegotiateInfoRequestTest {

    private static final int DEFAULT_CAPABILITIES = 0x12345678;
    private static final int DEFAULT_SECURITY_MODE = 0x0003;
    private byte[] defaultClientGuid;
    private int[] defaultDialects;

    @BeforeEach
    void setUp() {
        // Initialize default GUID (16 bytes)
        defaultClientGuid = new byte[16];
        for (int i = 0; i < 16; i++) {
            defaultClientGuid[i] = (byte) (i + 1);
        }

        // Initialize default dialects
        defaultDialects = new int[] { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };
    }

    @Test
    @DisplayName("Test constructor with valid parameters")
    void testConstructor() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        assertNotNull(request);
    }

    @Test
    @DisplayName("Test size calculation with multiple dialects")
    void testSizeWithMultipleDialects() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        // Expected size: 24 (fixed) + 2 * number of dialects
        int expectedSize = 24 + 2 * defaultDialects.length;
        assertEquals(expectedSize, request.size());
    }

    @Test
    @DisplayName("Test size calculation with single dialect")
    void testSizeWithSingleDialect() {
        int[] singleDialect = new int[] { 0x0302 };
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, singleDialect);

        // Expected size: 24 (fixed) + 2 * 1
        assertEquals(26, request.size());
    }

    @Test
    @DisplayName("Test size calculation with empty dialects array")
    void testSizeWithEmptyDialects() {
        int[] emptyDialects = new int[0];
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, emptyDialects);

        // Expected size: 24 (fixed) + 0
        assertEquals(24, request.size());
    }

    @Test
    @DisplayName("Test encode with standard parameters")
    void testEncodeStandardParameters() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        byte[] buffer = new byte[request.size()];
        int encodedLength = request.encode(buffer, 0);

        // Verify encoded length matches size
        assertEquals(request.size(), encodedLength);

        // Verify capabilities (4 bytes)
        assertEquals(DEFAULT_CAPABILITIES, SMBUtil.readInt4(buffer, 0));

        // Verify client GUID (16 bytes)
        byte[] extractedGuid = new byte[16];
        System.arraycopy(buffer, 4, extractedGuid, 0, 16);
        assertArrayEquals(defaultClientGuid, extractedGuid);

        // Verify security mode (2 bytes)
        assertEquals(DEFAULT_SECURITY_MODE, SMBUtil.readInt2(buffer, 20));

        // Verify dialect count (2 bytes)
        assertEquals(defaultDialects.length, SMBUtil.readInt2(buffer, 22));

        // Verify dialects
        int dialectOffset = 24;
        for (int i = 0; i < defaultDialects.length; i++) {
            assertEquals(defaultDialects[i], SMBUtil.readInt2(buffer, dialectOffset + i * 2));
        }
    }

    @Test
    @DisplayName("Test encode with offset")
    void testEncodeWithOffset() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        int offset = 100;
        byte[] buffer = new byte[offset + request.size()];
        int encodedLength = request.encode(buffer, offset);

        // Verify encoded length
        assertEquals(request.size(), encodedLength);

        // Verify data at correct offset
        assertEquals(DEFAULT_CAPABILITIES, SMBUtil.readInt4(buffer, offset));
        assertEquals(DEFAULT_SECURITY_MODE, SMBUtil.readInt2(buffer, offset + 20));
        assertEquals(defaultDialects.length, SMBUtil.readInt2(buffer, offset + 22));
    }

    @Test
    @DisplayName("Test encode with empty dialects")
    void testEncodeWithEmptyDialects() {
        int[] emptyDialects = new int[0];
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, emptyDialects);

        byte[] buffer = new byte[request.size()];
        int encodedLength = request.encode(buffer, 0);

        assertEquals(24, encodedLength);

        // Verify dialect count is 0
        assertEquals(0, SMBUtil.readInt2(buffer, 22));
    }

    @Test
    @DisplayName("Test encode with single dialect")
    void testEncodeWithSingleDialect() {
        int[] singleDialect = new int[] { 0x0311 };
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, singleDialect);

        byte[] buffer = new byte[request.size()];
        int encodedLength = request.encode(buffer, 0);

        assertEquals(26, encodedLength);

        // Verify dialect count
        assertEquals(1, SMBUtil.readInt2(buffer, 22));

        // Verify the single dialect
        assertEquals(0x0311, SMBUtil.readInt2(buffer, 24));
    }

    @Test
    @DisplayName("Test encode with maximum capabilities value")
    void testEncodeWithMaxCapabilities() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(0xFFFFFFFF, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        byte[] buffer = new byte[request.size()];
        request.encode(buffer, 0);

        // Verify max capabilities value (comparing as unsigned long)
        assertEquals(0xFFFFFFFFL, SMBUtil.readInt4(buffer, 0) & 0xFFFFFFFFL);
    }

    @Test
    @DisplayName("Test encode with zero capabilities")
    void testEncodeWithZeroCapabilities() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(0, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        byte[] buffer = new byte[request.size()];
        request.encode(buffer, 0);

        assertEquals(0, SMBUtil.readInt4(buffer, 0));
    }

    @Test
    @DisplayName("Test encode with maximum security mode")
    void testEncodeWithMaxSecurityMode() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, 0xFFFF, defaultDialects);

        byte[] buffer = new byte[request.size()];
        request.encode(buffer, 0);

        // Verify max security mode value (2 bytes)
        assertEquals(0xFFFF, SMBUtil.readInt2(buffer, 20) & 0xFFFF);
    }

    @Test
    @DisplayName("Test encode with all zero GUID")
    void testEncodeWithZeroGuid() {
        byte[] zeroGuid = new byte[16];
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, zeroGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        byte[] buffer = new byte[request.size()];
        request.encode(buffer, 0);

        // Verify zero GUID
        byte[] extractedGuid = new byte[16];
        System.arraycopy(buffer, 4, extractedGuid, 0, 16);
        assertArrayEquals(zeroGuid, extractedGuid);
    }

    @Test
    @DisplayName("Test encode with all 0xFF GUID")
    void testEncodeWithMaxGuid() {
        byte[] maxGuid = new byte[16];
        Arrays.fill(maxGuid, (byte) 0xFF);

        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, maxGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        byte[] buffer = new byte[request.size()];
        request.encode(buffer, 0);

        // Verify max GUID
        byte[] extractedGuid = new byte[16];
        System.arraycopy(buffer, 4, extractedGuid, 0, 16);
        assertArrayEquals(maxGuid, extractedGuid);
    }

    @Test
    @DisplayName("Test encode with many dialects")
    void testEncodeWithManyDialects() {
        // Create an array with many dialects
        int[] manyDialects = new int[100];
        for (int i = 0; i < manyDialects.length; i++) {
            manyDialects[i] = 0x0200 + i;
        }

        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, manyDialects);

        byte[] buffer = new byte[request.size()];
        int encodedLength = request.encode(buffer, 0);

        // Verify size
        assertEquals(24 + 2 * manyDialects.length, encodedLength);

        // Verify dialect count
        assertEquals(manyDialects.length, SMBUtil.readInt2(buffer, 22));

        // Verify all dialects
        for (int i = 0; i < manyDialects.length; i++) {
            assertEquals(manyDialects[i], SMBUtil.readInt2(buffer, 24 + i * 2));
        }
    }

    @Test
    @DisplayName("Test encode preserves dialect order")
    void testEncodePreservesDialectOrder() {
        // Use dialects in specific order
        int[] orderedDialects = new int[] { 0x0311, 0x0302, 0x0300, 0x0210, 0x0202 };

        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, orderedDialects);

        byte[] buffer = new byte[request.size()];
        request.encode(buffer, 0);

        // Verify dialects are in same order
        for (int i = 0; i < orderedDialects.length; i++) {
            assertEquals(orderedDialects[i], SMBUtil.readInt2(buffer, 24 + i * 2));
        }
    }

    @Test
    @DisplayName("Test multiple encode calls produce identical output")
    void testMultipleEncodeCallsIdentical() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        byte[] buffer1 = new byte[request.size()];
        byte[] buffer2 = new byte[request.size()];

        request.encode(buffer1, 0);
        request.encode(buffer2, 0);

        assertArrayEquals(buffer1, buffer2);
    }

    @Test
    @DisplayName("Test encode with insufficient buffer throws exception")
    void testEncodeWithInsufficientBuffer() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        // Create buffer smaller than required size
        byte[] smallBuffer = new byte[request.size() - 1];

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            request.encode(smallBuffer, 0);
        });
    }

    @Test
    @DisplayName("Test encode with offset exceeding buffer throws exception")
    void testEncodeWithExcessiveOffset() {
        ValidateNegotiateInfoRequest request =
                new ValidateNegotiateInfoRequest(DEFAULT_CAPABILITIES, defaultClientGuid, DEFAULT_SECURITY_MODE, defaultDialects);

        byte[] buffer = new byte[request.size()];

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            request.encode(buffer, 1);
        });
    }
}
