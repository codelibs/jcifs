package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

class NtTransQuerySecurityDescTest {

    @Mock
    private Configuration mockConfig;

    private NtTransQuerySecurityDesc querySecurityDesc;

    // Security information flag constants for testing
    private static final int OWNER_SECURITY_INFORMATION = 0x00000001;
    private static final int GROUP_SECURITY_INFORMATION = 0x00000002;
    private static final int DACL_SECURITY_INFORMATION = 0x00000004;
    private static final int SACL_SECURITY_INFORMATION = 0x00000008;
    private static final int ALL_SECURITY_INFORMATION = 0x0000000F;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getTransactionBufferSize()).thenReturn(65535);
    }

    @Test
    @DisplayName("Test constructor initialization with basic parameters")
    void testConstructorBasic() {
        int fid = 0x1234;
        int securityInfo = OWNER_SECURITY_INFORMATION;
        
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, securityInfo);
        
        // Constructor should initialize the object without throwing exceptions
        assertNotNull(querySecurityDesc);
        
        // Test toString contains the expected values to verify field initialization
        String str = querySecurityDesc.toString();
        assertTrue(str.contains("fid=0x" + Hexdump.toHexString(fid, 4)));
        assertTrue(str.contains("securityInformation=0x" + Hexdump.toHexString(securityInfo, 8)));
    }

    @Test
    @DisplayName("Test constructor with different security information flags")
    void testConstructorWithDifferentSecurityFlags() {
        int fid = 0x5678;
        int securityInfo = ALL_SECURITY_INFORMATION;
        
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, securityInfo);
        
        // Constructor should initialize the object without throwing exceptions
        assertNotNull(querySecurityDesc);
        
        // Test toString contains the expected values to verify field initialization
        String str = querySecurityDesc.toString();
        assertTrue(str.contains("fid=0x" + Hexdump.toHexString(fid, 4)));
        assertTrue(str.contains("securityInformation=0x" + Hexdump.toHexString(securityInfo, 8)));
    }

    @Test
    @DisplayName("Test getPadding returns correct value")
    void testGetPadding() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1000, DACL_SECURITY_INFORMATION);
        assertEquals(4, querySecurityDesc.getPadding());
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns zero")
    void testWriteSetupWireFormat() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, OWNER_SECURITY_INFORMATION);
        byte[] dst = new byte[100];
        
        int result = querySecurityDesc.writeSetupWireFormat(dst, 10);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with valid FID and security information")
    void testWriteParametersWireFormat() {
        int fid = 0xABCD;
        int securityInfo = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, securityInfo);
        
        byte[] dst = new byte[100];
        int dstIndex = 10;
        
        int bytesWritten = querySecurityDesc.writeParametersWireFormat(dst, dstIndex);
        
        // Verify bytes written
        assertEquals(8, bytesWritten);
        
        // Verify FID (2 bytes)
        assertEquals(fid, SMBUtil.readInt2(dst, dstIndex));
        
        // Verify reserved bytes (2 bytes at positions 2-3)
        assertEquals(0x00, dst[dstIndex + 2]);
        assertEquals(0x00, dst[dstIndex + 3]);
        
        // Verify security information (4 bytes)
        assertEquals(securityInfo, SMBUtil.readInt4(dst, dstIndex + 4));
    }

    @ParameterizedTest
    @DisplayName("Test writeParametersWireFormat with various FID values")
    @ValueSource(ints = {0x0000, 0x0001, 0x7FFF, 0xFFFF, 0x1234, 0xABCD})
    void testWriteParametersWireFormatWithVariousFids(int fid) {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, OWNER_SECURITY_INFORMATION);
        byte[] dst = new byte[100];
        
        int bytesWritten = querySecurityDesc.writeParametersWireFormat(dst, 0);
        
        assertEquals(8, bytesWritten);
        assertEquals(fid & 0xFFFF, SMBUtil.readInt2(dst, 0));
    }

    @ParameterizedTest
    @DisplayName("Test writeParametersWireFormat with various security information flags")
    @MethodSource("securityInformationProvider")
    void testWriteParametersWireFormatWithVariousSecurityInfo(int securityInfo, String description) {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, securityInfo);
        byte[] dst = new byte[100];
        
        int bytesWritten = querySecurityDesc.writeParametersWireFormat(dst, 0);
        
        assertEquals(8, bytesWritten);
        assertEquals(securityInfo, SMBUtil.readInt4(dst, 4));
    }

    private static Stream<Arguments> securityInformationProvider() {
        return Stream.of(
            Arguments.of(OWNER_SECURITY_INFORMATION, "Owner security information only"),
            Arguments.of(GROUP_SECURITY_INFORMATION, "Group security information only"),
            Arguments.of(DACL_SECURITY_INFORMATION, "DACL security information only"),
            Arguments.of(SACL_SECURITY_INFORMATION, "SACL security information only"),
            Arguments.of(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, "Owner and Group"),
            Arguments.of(DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, "DACL and SACL"),
            Arguments.of(ALL_SECURITY_INFORMATION, "All security information"),
            Arguments.of(0x00000000, "No security information"),
            Arguments.of(0xFFFFFFFF, "All bits set")
        );
    }

    @Test
    @DisplayName("Test writeParametersWireFormat buffer boundary")
    void testWriteParametersWireFormatBufferBoundary() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0xFFFF, 0xFFFFFFFF);
        byte[] dst = new byte[8];
        
        int bytesWritten = querySecurityDesc.writeParametersWireFormat(dst, 0);
        
        assertEquals(8, bytesWritten);
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
        assertEquals(0xFFFFFFFF, SMBUtil.readInt4(dst, 4));
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns zero")
    void testWriteDataWireFormat() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, OWNER_SECURITY_INFORMATION);
        byte[] dst = new byte[100];
        
        int result = querySecurityDesc.writeDataWireFormat(dst, 10);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns zero")
    void testReadSetupWireFormat() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, OWNER_SECURITY_INFORMATION);
        byte[] buffer = new byte[100];
        
        int result = querySecurityDesc.readSetupWireFormat(buffer, 10, 50);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns zero")
    void testReadParametersWireFormat() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, OWNER_SECURITY_INFORMATION);
        byte[] buffer = new byte[100];
        
        int result = querySecurityDesc.readParametersWireFormat(buffer, 10, 50);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns zero")
    void testReadDataWireFormat() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, OWNER_SECURITY_INFORMATION);
        byte[] buffer = new byte[100];
        
        int result = querySecurityDesc.readDataWireFormat(buffer, 10, 50);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test toString method with basic values")
    void testToStringBasic() {
        int fid = 0x1234;
        int securityInfo = OWNER_SECURITY_INFORMATION;
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, securityInfo);
        
        String result = querySecurityDesc.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("NtTransQuerySecurityDesc"));
        assertTrue(result.contains("fid=0x" + Hexdump.toHexString(fid, 4)));
        assertTrue(result.contains("securityInformation=0x" + Hexdump.toHexString(securityInfo, 8)));
    }

    @Test
    @DisplayName("Test toString method with maximum values")
    void testToStringMaxValues() {
        int fid = 0xFFFF;
        int securityInfo = 0xFFFFFFFF;
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, securityInfo);
        
        String result = querySecurityDesc.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("fid=0x" + Hexdump.toHexString(fid, 4)));
        assertTrue(result.contains("securityInformation=0x" + Hexdump.toHexString(securityInfo, 8)));
    }

    @Test
    @DisplayName("Test toString method with zero values")
    void testToStringZeroValues() {
        int fid = 0x0000;
        int securityInfo = 0x00000000;
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, securityInfo);
        
        String result = querySecurityDesc.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("fid=0x0000"));
        assertTrue(result.contains("securityInformation=0x00000000"));
    }

    @Test
    @DisplayName("Test writeParametersWireFormat preserves other buffer content")
    void testWriteParametersWireFormatPreservesBuffer() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, OWNER_SECURITY_INFORMATION);
        byte[] dst = new byte[20];
        
        // Fill buffer with test pattern
        for (int i = 0; i < dst.length; i++) {
            dst[i] = (byte) (i & 0xFF);
        }
        
        int startIndex = 5;
        int bytesWritten = querySecurityDesc.writeParametersWireFormat(dst, startIndex);
        
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
    @DisplayName("Test multiple instances independence")
    void testMultipleInstancesIndependence() {
        NtTransQuerySecurityDesc desc1 = new NtTransQuerySecurityDesc(mockConfig, 0x1111, OWNER_SECURITY_INFORMATION);
        NtTransQuerySecurityDesc desc2 = new NtTransQuerySecurityDesc(mockConfig, 0x2222, GROUP_SECURITY_INFORMATION);
        NtTransQuerySecurityDesc desc3 = new NtTransQuerySecurityDesc(mockConfig, 0x3333, DACL_SECURITY_INFORMATION);
        
        // Verify each instance maintains its own state
        assertEquals(0x1111, desc1.fid);
        assertEquals(OWNER_SECURITY_INFORMATION, desc1.securityInformation);
        
        assertEquals(0x2222, desc2.fid);
        assertEquals(GROUP_SECURITY_INFORMATION, desc2.securityInformation);
        
        assertEquals(0x3333, desc3.fid);
        assertEquals(DACL_SECURITY_INFORMATION, desc3.securityInformation);
        
        // Verify writing doesn't affect other instances
        byte[] dst1 = new byte[8];
        byte[] dst2 = new byte[8];
        byte[] dst3 = new byte[8];
        
        desc1.writeParametersWireFormat(dst1, 0);
        desc2.writeParametersWireFormat(dst2, 0);
        desc3.writeParametersWireFormat(dst3, 0);
        
        assertEquals(0x1111, SMBUtil.readInt2(dst1, 0));
        assertEquals(0x2222, SMBUtil.readInt2(dst2, 0));
        assertEquals(0x3333, SMBUtil.readInt2(dst3, 0));
    }

    @Test
    @DisplayName("Test parameter wire format structure")
    void testParameterWireFormatStructure() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0xABCD, 0x12345678);
        byte[] dst = new byte[100];
        
        int bytesWritten = querySecurityDesc.writeParametersWireFormat(dst, 10);
        
        // Verify structure:
        // Offset 0-1: FID (2 bytes)
        // Offset 2-3: Reserved (2 bytes, should be 0x00)
        // Offset 4-7: Security Information (4 bytes)
        assertEquals(8, bytesWritten);
        
        // Check FID
        assertEquals(0xABCD, SMBUtil.readInt2(dst, 10));
        
        // Check reserved bytes are zero
        assertEquals(0x00, dst[12]);
        assertEquals(0x00, dst[13]);
        
        // Check security information
        assertEquals(0x12345678, SMBUtil.readInt4(dst, 14));
    }

    @Test
    @DisplayName("Test with negative FID value (should handle as unsigned)")
    void testNegativeFidValue() {
        int fid = -1; // Will be treated as 0xFFFF in unsigned 16-bit
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, fid, OWNER_SECURITY_INFORMATION);
        byte[] dst = new byte[10];
        
        querySecurityDesc.writeParametersWireFormat(dst, 0);
        
        // Should write as 0xFFFF (65535 in unsigned)
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
    }

    @Test
    @DisplayName("Test configuration mock is used correctly")
    void testConfigurationUsage() {
        querySecurityDesc = new NtTransQuerySecurityDesc(mockConfig, 0x1234, OWNER_SECURITY_INFORMATION);
        
        // Verify that the configuration was passed to parent constructor
        verify(mockConfig, atLeastOnce()).getTransactionBufferSize();
    }
}