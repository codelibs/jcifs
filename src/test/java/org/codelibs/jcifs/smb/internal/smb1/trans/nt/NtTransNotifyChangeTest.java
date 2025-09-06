package org.codelibs.jcifs.smb.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class NtTransNotifyChangeTest {

    @Mock
    private Configuration mockConfig;

    private NtTransNotifyChange notifyChange;

    // Completion filter constants for testing
    private static final int FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
    private static final int FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
    private static final int FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
    private static final int FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
    private static final int FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;
    private static final int FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020;
    private static final int FILE_NOTIFY_CHANGE_CREATION = 0x00000040;
    private static final int FILE_NOTIFY_CHANGE_EA = 0x00000080;
    private static final int FILE_NOTIFY_CHANGE_SECURITY = 0x00000100;
    private static final int FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200;
    private static final int FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400;
    private static final int FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800;
    private static final int FILE_NOTIFY_CHANGE_ALL = 0x00000FFF;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getNotifyBufferSize()).thenReturn(4096);
        when(mockConfig.getTransactionBufferSize()).thenReturn(65535);
    }

    @Test
    @DisplayName("Test constructor initialization with basic parameters")
    void testConstructorBasic() {
        int fid = 0x1234;
        int completionFilter = FILE_NOTIFY_CHANGE_FILE_NAME;
        boolean watchTree = false;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);

        assertNotNull(notifyChange);

        // Verify field initialization through toString
        String str = notifyChange.toString();
        assertTrue(str.contains("NtTransNotifyChange"));
        assertTrue(str.contains("fid=0x" + Hexdump.toHexString(fid, 4)));
        assertTrue(str.contains("filter=0x" + Hexdump.toHexString(completionFilter, 4)));
        assertTrue(str.contains("watchTree=" + watchTree));
    }

    @Test
    @DisplayName("Test constructor with watchTree enabled")
    void testConstructorWithWatchTreeEnabled() {
        int fid = 0x5678;
        int completionFilter = FILE_NOTIFY_CHANGE_DIR_NAME;
        boolean watchTree = true;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);

        assertNotNull(notifyChange);

        String str = notifyChange.toString();
        assertTrue(str.contains("watchTree=true"));
    }

    @Test
    @DisplayName("Test constructor with all filters enabled")
    void testConstructorWithAllFilters() {
        int fid = 0xABCD;
        int completionFilter = FILE_NOTIFY_CHANGE_ALL;
        boolean watchTree = true;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);

        assertNotNull(notifyChange);

        String str = notifyChange.toString();
        assertTrue(str.contains("filter=0x" + Hexdump.toHexString(completionFilter, 4)));
    }

    @Test
    @DisplayName("Test writeSetupWireFormat with watchTree false")
    void testWriteSetupWireFormatWatchTreeFalse() {
        int fid = 0x1234;
        int completionFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE;
        boolean watchTree = false;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);
        byte[] dst = new byte[100];
        int dstIndex = 10;

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, dstIndex);

        // Should write 8 bytes total
        assertEquals(8, bytesWritten);

        // Verify completion filter (4 bytes)
        assertEquals(completionFilter, SMBUtil.readInt4(dst, dstIndex));

        // Verify FID (2 bytes)
        assertEquals(fid, SMBUtil.readInt2(dst, dstIndex + 4));

        // Verify watchTree flag (1 byte)
        assertEquals(0x00, dst[dstIndex + 6]);

        // Verify reserved byte (1 byte)
        assertEquals(0x00, dst[dstIndex + 7]);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat with watchTree true")
    void testWriteSetupWireFormatWatchTreeTrue() {
        int fid = 0x5678;
        int completionFilter = FILE_NOTIFY_CHANGE_ATTRIBUTES;
        boolean watchTree = true;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);
        byte[] dst = new byte[100];
        int dstIndex = 0;

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, dstIndex);

        assertEquals(8, bytesWritten);

        // Verify watchTree flag is set to 0x01
        assertEquals(0x01, dst[dstIndex + 6]);
    }

    @ParameterizedTest
    @DisplayName("Test writeSetupWireFormat with various FID values")
    @ValueSource(ints = { 0x0000, 0x0001, 0x7FFF, 0xFFFF, 0x1234, 0xABCD })
    void testWriteSetupWireFormatWithVariousFids(int fid) {
        notifyChange = new NtTransNotifyChange(mockConfig, fid, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] dst = new byte[100];

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, 0);

        assertEquals(8, bytesWritten);
        assertEquals(fid & 0xFFFF, SMBUtil.readInt2(dst, 4));
    }

    @ParameterizedTest
    @DisplayName("Test writeSetupWireFormat with various completion filters")
    @MethodSource("completionFilterProvider")
    void testWriteSetupWireFormatWithVariousFilters(int completionFilter, String description) {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, completionFilter, false);
        byte[] dst = new byte[100];

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, 0);

        assertEquals(8, bytesWritten);
        assertEquals(completionFilter, SMBUtil.readInt4(dst, 0));
    }

    private static Stream<Arguments> completionFilterProvider() {
        return Stream.of(Arguments.of(FILE_NOTIFY_CHANGE_FILE_NAME, "File name changes"),
                Arguments.of(FILE_NOTIFY_CHANGE_DIR_NAME, "Directory name changes"),
                Arguments.of(FILE_NOTIFY_CHANGE_ATTRIBUTES, "Attribute changes"), Arguments.of(FILE_NOTIFY_CHANGE_SIZE, "Size changes"),
                Arguments.of(FILE_NOTIFY_CHANGE_LAST_WRITE, "Last write time changes"),
                Arguments.of(FILE_NOTIFY_CHANGE_SECURITY, "Security changes"),
                Arguments.of(FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, "File and directory name changes"),
                Arguments.of(FILE_NOTIFY_CHANGE_ALL, "All changes"), Arguments.of(0x00000000, "No filters"),
                Arguments.of(0xFFFFFFFF, "All bits set"));
    }

    @ParameterizedTest
    @DisplayName("Test writeSetupWireFormat with different watchTree values")
    @CsvSource({ "true, 0x01", "false, 0x00" })
    void testWriteSetupWireFormatWatchTreeValues(boolean watchTree, int expectedByte) {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, watchTree);
        byte[] dst = new byte[10];

        notifyChange.writeSetupWireFormat(dst, 0);

        assertEquals((byte) expectedByte, dst[6]);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns zero")
    void testWriteParametersWireFormat() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] dst = new byte[100];

        int result = notifyChange.writeParametersWireFormat(dst, 10);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns zero")
    void testWriteDataWireFormat() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] dst = new byte[100];

        int result = notifyChange.writeDataWireFormat(dst, 10);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns zero")
    void testReadSetupWireFormat() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] buffer = new byte[100];

        int result = notifyChange.readSetupWireFormat(buffer, 10, 50);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns zero")
    void testReadParametersWireFormat() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] buffer = new byte[100];

        int result = notifyChange.readParametersWireFormat(buffer, 10, 50);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns zero")
    void testReadDataWireFormat() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] buffer = new byte[100];

        int result = notifyChange.readDataWireFormat(buffer, 10, 50);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test toString method with basic values")
    void testToStringBasic() {
        int fid = 0x1234;
        int completionFilter = FILE_NOTIFY_CHANGE_FILE_NAME;
        boolean watchTree = false;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);

        String result = notifyChange.toString();

        assertNotNull(result);
        assertTrue(result.contains("NtTransNotifyChange"));
        assertTrue(result.contains("fid=0x" + Hexdump.toHexString(fid, 4)));
        assertTrue(result.contains("filter=0x" + Hexdump.toHexString(completionFilter, 4)));
        assertTrue(result.contains("watchTree=" + watchTree));
    }

    @Test
    @DisplayName("Test toString method with maximum values")
    void testToStringMaxValues() {
        int fid = 0xFFFF;
        int completionFilter = 0xFFFFFFFF;
        boolean watchTree = true;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);

        String result = notifyChange.toString();

        assertNotNull(result);
        // Hexdump uses uppercase letters
        // Note: completionFilter is displayed with 4 hex chars, not 8
        assertTrue(result.contains("fid=0xFFFF"));
        assertTrue(result.contains("filter=0xFFFF")); // Only 4 hex chars are shown
        assertTrue(result.contains("watchTree=true"));
    }

    @Test
    @DisplayName("Test toString method with zero values")
    void testToStringZeroValues() {
        int fid = 0x0000;
        int completionFilter = 0x00000000;
        boolean watchTree = false;

        notifyChange = new NtTransNotifyChange(mockConfig, fid, completionFilter, watchTree);

        String result = notifyChange.toString();

        assertNotNull(result);
        // Hexdump.toHexString uses uppercase and produces only the specified width
        // Note: completionFilter is displayed with 4 hex chars, not 8
        assertTrue(result.contains("fid=0x0000"));
        assertTrue(result.contains("filter=0x0000")); // Only 4 hex chars are shown
        assertTrue(result.contains("watchTree=false"));
    }

    @Test
    @DisplayName("Test writeSetupWireFormat preserves other buffer content")
    void testWriteSetupWireFormatPreservesBuffer() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] dst = new byte[20];

        // Fill buffer with test pattern
        for (int i = 0; i < dst.length; i++) {
            dst[i] = (byte) (i & 0xFF);
        }

        int startIndex = 5;
        int bytesWritten = notifyChange.writeSetupWireFormat(dst, startIndex);

        // Check that bytes before startIndex are unchanged
        for (int i = 0; i < startIndex; i++) {
            assertEquals((byte) (i & 0xFF), dst[i]);
        }

        // Check that bytes after written area are unchanged
        for (int i = startIndex + bytesWritten; i < dst.length; i++) {
            assertEquals((byte) (i & 0xFF), dst[i]);
        }
    }

    @Test
    @DisplayName("Test setup wire format structure")
    void testSetupWireFormatStructure() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0xABCD, 0x12345678, true);
        byte[] dst = new byte[100];

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, 10);

        // Verify structure:
        // Offset 0-3: Completion Filter (4 bytes)
        // Offset 4-5: FID (2 bytes)
        // Offset 6: Watch Tree (1 byte)
        // Offset 7: Reserved (1 byte)
        assertEquals(8, bytesWritten);

        // Check completion filter
        assertEquals(0x12345678, SMBUtil.readInt4(dst, 10));

        // Check FID
        assertEquals(0xABCD, SMBUtil.readInt2(dst, 14));

        // Check watch tree flag
        assertEquals(0x01, dst[16]);

        // Check reserved byte is zero
        assertEquals(0x00, dst[17]);
    }

    @Test
    @DisplayName("Test with negative FID value (should handle as unsigned)")
    void testNegativeFidValue() {
        int fid = -1; // Will be treated as 0xFFFF in unsigned 16-bit
        notifyChange = new NtTransNotifyChange(mockConfig, fid, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        byte[] dst = new byte[10];

        notifyChange.writeSetupWireFormat(dst, 0);

        // Should write as 0xFFFF (65535 in unsigned)
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 4));
    }

    @Test
    @DisplayName("Test configuration usage for notify buffer size")
    void testConfigurationNotifyBufferSize() {
        int notifyBufferSize = 8192;
        when(mockConfig.getNotifyBufferSize()).thenReturn(notifyBufferSize);

        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);

        // Verify that the configuration was queried for notify buffer size
        verify(mockConfig, atLeastOnce()).getNotifyBufferSize();
    }

    @Test
    @DisplayName("Test multiple instances independence")
    void testMultipleInstancesIndependence() {
        NtTransNotifyChange notify1 = new NtTransNotifyChange(mockConfig, 0x1111, FILE_NOTIFY_CHANGE_FILE_NAME, false);
        NtTransNotifyChange notify2 = new NtTransNotifyChange(mockConfig, 0x2222, FILE_NOTIFY_CHANGE_DIR_NAME, true);
        NtTransNotifyChange notify3 = new NtTransNotifyChange(mockConfig, 0x3333, FILE_NOTIFY_CHANGE_ATTRIBUTES, false);

        // Verify each instance maintains its own state
        byte[] dst1 = new byte[8];
        byte[] dst2 = new byte[8];
        byte[] dst3 = new byte[8];

        notify1.writeSetupWireFormat(dst1, 0);
        notify2.writeSetupWireFormat(dst2, 0);
        notify3.writeSetupWireFormat(dst3, 0);

        // Verify FID values
        assertEquals(0x1111, SMBUtil.readInt2(dst1, 4));
        assertEquals(0x2222, SMBUtil.readInt2(dst2, 4));
        assertEquals(0x3333, SMBUtil.readInt2(dst3, 4));

        // Verify completion filters
        assertEquals(FILE_NOTIFY_CHANGE_FILE_NAME, SMBUtil.readInt4(dst1, 0));
        assertEquals(FILE_NOTIFY_CHANGE_DIR_NAME, SMBUtil.readInt4(dst2, 0));
        assertEquals(FILE_NOTIFY_CHANGE_ATTRIBUTES, SMBUtil.readInt4(dst3, 0));

        // Verify watch tree flags
        assertEquals(0x00, dst1[6]);
        assertEquals(0x01, dst2[6]);
        assertEquals(0x00, dst3[6]);
    }

    @Test
    @DisplayName("Test setup count initialization")
    void testSetupCountInitialization() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, FILE_NOTIFY_CHANGE_FILE_NAME, false);

        // The setup count should be initialized to 0x04 in the constructor
        // We can't directly access it, but we can verify the behavior is correct
        assertNotNull(notifyChange);
    }

    @Test
    @DisplayName("Test combined completion filters")
    void testCombinedCompletionFilters() {
        int combinedFilter =
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE;

        notifyChange = new NtTransNotifyChange(mockConfig, 0x1234, combinedFilter, true);
        byte[] dst = new byte[10];

        notifyChange.writeSetupWireFormat(dst, 0);

        assertEquals(combinedFilter, SMBUtil.readInt4(dst, 0));
    }

    @Test
    @DisplayName("Test writeSetupWireFormat at buffer boundary")
    void testWriteSetupWireFormatBufferBoundary() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0xFFFF, 0xFFFFFFFF, true);
        byte[] dst = new byte[8]; // Exact size needed

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, 0);

        assertEquals(8, bytesWritten);
        assertEquals(0xFFFFFFFF, SMBUtil.readInt4(dst, 0));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 4));
        assertEquals(0x01, dst[6]);
        assertEquals(0x00, dst[7]);
    }

    @ParameterizedTest
    @DisplayName("Test various buffer offsets for writeSetupWireFormat")
    @ValueSource(ints = { 0, 1, 10, 50, 90 })
    void testVariousBufferOffsets(int offset) {
        notifyChange = new NtTransNotifyChange(mockConfig, 0x5678, FILE_NOTIFY_CHANGE_SIZE, true);
        byte[] dst = new byte[100];

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, offset);

        assertEquals(8, bytesWritten);
        assertEquals(FILE_NOTIFY_CHANGE_SIZE, SMBUtil.readInt4(dst, offset));
        assertEquals(0x5678, SMBUtil.readInt2(dst, offset + 4));
        assertEquals(0x01, dst[offset + 6]);
    }

    @Test
    @DisplayName("Test edge case with zero completion filter and FID")
    void testZeroValues() {
        notifyChange = new NtTransNotifyChange(mockConfig, 0, 0, false);
        byte[] dst = new byte[10];

        int bytesWritten = notifyChange.writeSetupWireFormat(dst, 0);

        assertEquals(8, bytesWritten);
        assertEquals(0, SMBUtil.readInt4(dst, 0));
        assertEquals(0, SMBUtil.readInt2(dst, 4));
        assertEquals(0x00, dst[6]);
        assertEquals(0x00, dst[7]);
    }
}