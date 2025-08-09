package jcifs.internal.smb1.trans2;

import jcifs.Configuration;
import jcifs.internal.dfs.DfsReferralRequestBuffer;
import jcifs.internal.smb1.trans.SmbComTransaction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class Trans2GetDfsReferralTest {

    @Mock
    private Configuration mockConfig;

    private Trans2GetDfsReferral trans2GetDfsReferral;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Constructor should initialize with correct values")
    void testConstructor() throws Exception {
        // Given
        String filename = "\\\\server\\share\\file.txt";
        
        // When
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, filename);
        
        // Then
        // These fields are protected in parent class, so we can't access them directly
        // We verify the object was created successfully instead
        assertNotNull(trans2GetDfsReferral);
        
        // Verify that request buffer was created with correct parameters
        Field requestField = Trans2GetDfsReferral.class.getDeclaredField("request");
        requestField.setAccessible(true);
        DfsReferralRequestBuffer request = (DfsReferralRequestBuffer) requestField.get(trans2GetDfsReferral);
        assertNotNull(request);
    }

    @Test
    @DisplayName("Constructor should handle null filename")
    void testConstructorWithNullFilename() {
        // When & Then
        assertDoesNotThrow(() -> new Trans2GetDfsReferral(mockConfig, null));
    }

    @Test
    @DisplayName("Constructor should handle empty filename")
    void testConstructorWithEmptyFilename() {
        // When & Then
        assertDoesNotThrow(() -> new Trans2GetDfsReferral(mockConfig, ""));
    }

    @Test
    @DisplayName("isForceUnicode should always return true")
    void testIsForceUnicode() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        
        // When
        boolean result = trans2GetDfsReferral.isForceUnicode();
        
        // Then
        assertTrue(result);
    }

    @Test
    @DisplayName("writeSetupWireFormat should write setup bytes correctly")
    void testWriteSetupWireFormat() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        byte[] dst = new byte[10];
        int dstIndex = 0;
        
        // When
        int bytesWritten = trans2GetDfsReferral.writeSetupWireFormat(dst, dstIndex);
        
        // Then
        assertEquals(2, bytesWritten);
        assertEquals(SmbComTransaction.TRANS2_GET_DFS_REFERRAL, dst[0]);
        assertEquals((byte) 0x00, dst[1]);
    }

    @Test
    @DisplayName("writeSetupWireFormat should handle different buffer positions")
    void testWriteSetupWireFormatWithOffset() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        byte[] dst = new byte[20];
        int dstIndex = 5;
        
        // When
        int bytesWritten = trans2GetDfsReferral.writeSetupWireFormat(dst, dstIndex);
        
        // Then
        assertEquals(2, bytesWritten);
        assertEquals(SmbComTransaction.TRANS2_GET_DFS_REFERRAL, dst[5]);
        assertEquals((byte) 0x00, dst[6]);
    }

    @Test
    @DisplayName("writeParametersWireFormat should encode request buffer")
    void testWriteParametersWireFormat() throws Exception {
        // Given
        String filename = "\\\\server\\share";
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, filename);
        byte[] dst = new byte[256];
        int dstIndex = 0;
        
        // When
        int bytesWritten = trans2GetDfsReferral.writeParametersWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(bytesWritten > 0);
        // The actual encoding depends on DfsReferralRequestBuffer implementation
    }

    @Test
    @DisplayName("writeParametersWireFormat with mock request buffer")
    void testWriteParametersWireFormatWithMock() throws Exception {
        // Given
        String filename = "\\\\server\\share";
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, filename);
        
        // Mock the request buffer
        DfsReferralRequestBuffer mockRequest = mock(DfsReferralRequestBuffer.class);
        when(mockRequest.encode(any(byte[].class), anyInt())).thenReturn(10);
        
        // Inject mock request
        Field requestField = Trans2GetDfsReferral.class.getDeclaredField("request");
        requestField.setAccessible(true);
        requestField.set(trans2GetDfsReferral, mockRequest);
        
        byte[] dst = new byte[256];
        int dstIndex = 0;
        
        // When
        int bytesWritten = trans2GetDfsReferral.writeParametersWireFormat(dst, dstIndex);
        
        // Then
        assertEquals(10, bytesWritten);
        verify(mockRequest, times(1)).encode(dst, dstIndex);
    }

    @Test
    @DisplayName("writeDataWireFormat should always return 0")
    void testWriteDataWireFormat() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        byte[] dst = new byte[10];
        int dstIndex = 0;
        
        // When
        int bytesWritten = trans2GetDfsReferral.writeDataWireFormat(dst, dstIndex);
        
        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("readSetupWireFormat should always return 0")
    void testReadSetupWireFormat() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        byte[] buffer = new byte[10];
        
        // When
        int bytesRead = trans2GetDfsReferral.readSetupWireFormat(buffer, 0, 10);
        
        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("readParametersWireFormat should always return 0")
    void testReadParametersWireFormat() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        byte[] buffer = new byte[10];
        
        // When
        int bytesRead = trans2GetDfsReferral.readParametersWireFormat(buffer, 0, 10);
        
        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("readDataWireFormat should always return 0")
    void testReadDataWireFormat() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        byte[] buffer = new byte[10];
        
        // When
        int bytesRead = trans2GetDfsReferral.readDataWireFormat(buffer, 0, 10);
        
        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("toString should return formatted string with details")
    void testToString() throws Exception {
        // Given
        String filename = "\\\\server\\share\\file.txt";
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, filename);
        
        // Set path field (inherited from parent)
        Field pathField = trans2GetDfsReferral.getClass().getSuperclass().getSuperclass().getDeclaredField("path");
        pathField.setAccessible(true);
        pathField.set(trans2GetDfsReferral, filename);
        
        // When
        String result = trans2GetDfsReferral.toString();
        
        // Then
        assertNotNull(result);
        assertTrue(result.contains("Trans2GetDfsReferral"));
        assertTrue(result.contains("maxReferralLevel=0x3"));
        assertTrue(result.contains("filename=" + filename));
    }

    @Test
    @DisplayName("toString should handle null path")
    void testToStringWithNullPath() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        
        // When
        String result = trans2GetDfsReferral.toString();
        
        // Then
        assertNotNull(result);
        assertTrue(result.contains("Trans2GetDfsReferral"));
        assertTrue(result.contains("maxReferralLevel=0x3"));
    }

    @Test
    @DisplayName("maxReferralLevel should be initialized to 3")
    void testMaxReferralLevelInitialization() throws Exception {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        
        // When
        Field maxReferralLevelField = Trans2GetDfsReferral.class.getDeclaredField("maxReferralLevel");
        maxReferralLevelField.setAccessible(true);
        int maxReferralLevel = (int) maxReferralLevelField.get(trans2GetDfsReferral);
        
        // Then
        assertEquals(3, maxReferralLevel);
    }

    @Test
    @DisplayName("Test with various filename formats")
    void testVariousFilenameFormats() {
        // Test UNC path
        assertDoesNotThrow(() -> new Trans2GetDfsReferral(mockConfig, "\\\\server\\share"));
        
        // Test forward slashes
        assertDoesNotThrow(() -> new Trans2GetDfsReferral(mockConfig, "//server/share"));
        
        // Test with spaces
        assertDoesNotThrow(() -> new Trans2GetDfsReferral(mockConfig, "\\\\server\\my share\\file.txt"));
        
        // Test with special characters
        assertDoesNotThrow(() -> new Trans2GetDfsReferral(mockConfig, "\\\\server\\share\\file$name.txt"));
    }

    @Test
    @DisplayName("Test buffer boundary conditions")
    void testBufferBoundaryConditions() {
        // Given
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, "test");
        
        // Test with minimum size buffer
        byte[] smallBuffer = new byte[2];
        assertEquals(2, trans2GetDfsReferral.writeSetupWireFormat(smallBuffer, 0));
        
        // Test with exact size buffer
        byte[] exactBuffer = new byte[2];
        assertEquals(2, trans2GetDfsReferral.writeSetupWireFormat(exactBuffer, 0));
        
        // Test read methods with empty buffer
        byte[] emptyBuffer = new byte[0];
        assertEquals(0, trans2GetDfsReferral.readSetupWireFormat(emptyBuffer, 0, 0));
        assertEquals(0, trans2GetDfsReferral.readParametersWireFormat(emptyBuffer, 0, 0));
        assertEquals(0, trans2GetDfsReferral.readDataWireFormat(emptyBuffer, 0, 0));
    }

    @Test
    @DisplayName("Test parameter encoding with long filename")
    void testParameterEncodingWithLongFilename() {
        // Given
        StringBuilder longFilename = new StringBuilder("\\\\server\\share");
        for (int i = 0; i < 100; i++) {
            longFilename.append("\\verylongdirectoryname");
        }
        
        trans2GetDfsReferral = new Trans2GetDfsReferral(mockConfig, longFilename.toString());
        byte[] dst = new byte[8192]; // Large buffer for long filename
        
        // When
        int bytesWritten = trans2GetDfsReferral.writeParametersWireFormat(dst, 0);
        
        // Then
        assertTrue(bytesWritten > 0);
        // Verify that encoding doesn't overflow
        assertTrue(bytesWritten < dst.length);
    }
}