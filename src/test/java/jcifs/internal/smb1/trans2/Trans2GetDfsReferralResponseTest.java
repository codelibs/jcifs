package jcifs.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.dfs.DfsReferralResponseBuffer;
import jcifs.internal.dfs.Referral;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;

/**
 * Unit tests for Trans2GetDfsReferralResponse class
 */
class Trans2GetDfsReferralResponseTest {

    @Mock
    private Configuration mockConfig;

    private Trans2GetDfsReferralResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        response = new Trans2GetDfsReferralResponse(mockConfig);
    }

    @Nested
    @DisplayName("Constructor and Initialization Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize with correct configuration")
        void testConstructorInitialization() {
            Trans2GetDfsReferralResponse localResponse = new Trans2GetDfsReferralResponse(mockConfig);
            
            assertNotNull(localResponse);
            assertEquals(SmbComTransaction.TRANS2_GET_DFS_REFERRAL, localResponse.getSubCommand());
        }

        @Test
        @DisplayName("Should initialize DfsReferralResponseBuffer")
        void testDfsResponseBufferInitialization() {
            assertNotNull(response.getDfsResponse());
            assertTrue(response.getDfsResponse() instanceof DfsReferralResponseBuffer);
        }

        @Test
        @DisplayName("Should throw NullPointerException with null configuration")
        void testConstructorWithNullConfig() {
            // The parent class requires a non-null configuration for getPid()
            assertThrows(NullPointerException.class, () -> {
                new Trans2GetDfsReferralResponse(null);
            });
        }
    }

    @Nested
    @DisplayName("Constants Tests")
    class ConstantsTests {

        @Test
        @DisplayName("Should have correct FLAGS_NAME_LIST_REFERRAL value")
        void testFlagsNameListReferralConstant() {
            assertEquals(0x0002, Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL);
        }

        @Test
        @DisplayName("Should have correct FLAGS_TARGET_SET_BOUNDARY value")
        void testFlagsTargetSetBoundaryConstant() {
            assertEquals(0x0004, Trans2GetDfsReferralResponse.FLAGS_TARGET_SET_BOUNDARY);
        }

        @Test
        @DisplayName("Should have correct TYPE_ROOT_TARGETS value")
        void testTypeRootTargetsConstant() {
            assertEquals(0x0, Trans2GetDfsReferralResponse.TYPE_ROOT_TARGETS);
        }

        @Test
        @DisplayName("Should have correct TYPE_NON_ROOT_TARGETS value")
        void testTypeNonRootTargetsConstant() {
            assertEquals(0x1, Trans2GetDfsReferralResponse.TYPE_NON_ROOT_TARGETS);
        }
    }

    @Nested
    @DisplayName("Unicode Support Tests")
    class UnicodeSupportTests {

        @Test
        @DisplayName("Should always force unicode")
        void testIsForceUnicode() {
            assertTrue(response.isForceUnicode());
        }

        @Test
        @DisplayName("Should consistently return true for unicode")
        void testIsForceUnicodeMultipleCalls() {
            for (int i = 0; i < 5; i++) {
                assertTrue(response.isForceUnicode());
            }
        }
    }

    @Nested
    @DisplayName("Wire Format Write Tests")
    class WireFormatWriteTests {

        @Test
        @DisplayName("Should return 0 for writeSetupWireFormat")
        void testWriteSetupWireFormat() {
            byte[] dst = new byte[100];
            int result = response.writeSetupWireFormat(dst, 0);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for writeSetupWireFormat with offset")
        void testWriteSetupWireFormatWithOffset() {
            byte[] dst = new byte[100];
            int result = response.writeSetupWireFormat(dst, 50);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for writeParametersWireFormat")
        void testWriteParametersWireFormat() {
            byte[] dst = new byte[100];
            int result = response.writeParametersWireFormat(dst, 0);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for writeParametersWireFormat with offset")
        void testWriteParametersWireFormatWithOffset() {
            byte[] dst = new byte[100];
            int result = response.writeParametersWireFormat(dst, 25);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for writeDataWireFormat")
        void testWriteDataWireFormat() {
            byte[] dst = new byte[100];
            int result = response.writeDataWireFormat(dst, 0);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for writeDataWireFormat with offset")
        void testWriteDataWireFormatWithOffset() {
            byte[] dst = new byte[100];
            int result = response.writeDataWireFormat(dst, 75);
            
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("Wire Format Read Tests")
    class WireFormatReadTests {

        @Test
        @DisplayName("Should return 0 for readSetupWireFormat")
        void testReadSetupWireFormat() {
            byte[] buffer = new byte[100];
            int result = response.readSetupWireFormat(buffer, 0, buffer.length);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for readSetupWireFormat with empty buffer")
        void testReadSetupWireFormatEmptyBuffer() {
            byte[] buffer = new byte[0];
            int result = response.readSetupWireFormat(buffer, 0, 0);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for readParametersWireFormat")
        void testReadParametersWireFormat() {
            byte[] buffer = new byte[100];
            int result = response.readParametersWireFormat(buffer, 0, buffer.length);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 for readParametersWireFormat with empty buffer")
        void testReadParametersWireFormatEmptyBuffer() {
            byte[] buffer = new byte[0];
            int result = response.readParametersWireFormat(buffer, 0, 0);
            
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should decode DFS referral data correctly")
        void testReadDataWireFormat() {
            byte[] buffer = createValidDfsReferralBuffer();
            
            int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);
            
            assertTrue(bytesRead > 0);
            // readDataWireFormat returns bytes consumed from header, not full buffer
            assertEquals(28, bytesRead); // Header + one referral structure
            assertNotNull(response.getDfsResponse());
        }

        @Test
        @DisplayName("Should handle readDataWireFormat with offset")
        void testReadDataWireFormatWithOffset() {
            byte[] fullBuffer = new byte[200];
            byte[] dfsData = createValidDfsReferralBuffer();
            int offset = 50;
            System.arraycopy(dfsData, 0, fullBuffer, offset, dfsData.length);
            
            int bytesRead = response.readDataWireFormat(fullBuffer, offset, dfsData.length);
            
            assertTrue(bytesRead > 0);
            // readDataWireFormat returns bytes consumed from header, not full buffer
            assertEquals(28, bytesRead); // Header + one referral structure
        }

        @Test
        @DisplayName("Should handle empty buffer in readDataWireFormat")
        void testReadDataWireFormatEmptyBuffer() {
            byte[] buffer = new byte[0];
            
            // Empty buffer causes ArrayIndexOutOfBoundsException when trying to read
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
                response.readDataWireFormat(buffer, 0, 0);
            });
        }

        @Test
        @DisplayName("Should handle minimal DFS referral buffer")
        void testReadDataWireFormatMinimalBuffer() {
            byte[] buffer = createMinimalDfsReferralBuffer();
            
            int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);
            
            assertTrue(bytesRead > 0);
            assertNotNull(response.getDfsResponse());
            assertEquals(0, response.getDfsResponse().getNumReferrals());
        }

        @Test
        @DisplayName("Should handle DFS referral with multiple referrals")
        void testReadDataWireFormatMultipleReferrals() {
            byte[] buffer = createDfsReferralBufferWithMultipleReferrals(3);
            
            int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);
            
            assertTrue(bytesRead > 0);
            assertNotNull(response.getDfsResponse());
            assertEquals(3, response.getDfsResponse().getNumReferrals());
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 2, 5, 10})
        @DisplayName("Should handle varying number of referrals")
        void testReadDataWireFormatVaryingReferrals(int numReferrals) {
            byte[] buffer = createDfsReferralBufferWithMultipleReferrals(numReferrals);
            
            int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);
            
            assertTrue(bytesRead > 0);
            assertEquals(numReferrals, response.getDfsResponse().getNumReferrals());
        }
    }

    @Nested
    @DisplayName("DfsResponse Getter Tests")
    class DfsResponseGetterTests {

        @Test
        @DisplayName("Should return same DfsResponse instance")
        void testGetDfsResponseReturnsSameInstance() {
            DfsReferralResponseBuffer buffer1 = response.getDfsResponse();
            DfsReferralResponseBuffer buffer2 = response.getDfsResponse();
            
            assertSame(buffer1, buffer2);
        }

        @Test
        @DisplayName("Should never return null DfsResponse")
        void testGetDfsResponseNeverNull() {
            assertNotNull(response.getDfsResponse());
        }

        @Test
        @DisplayName("Should maintain DfsResponse after reading data")
        void testGetDfsResponseAfterReadingData() {
            byte[] buffer = createValidDfsReferralBuffer();
            DfsReferralResponseBuffer originalBuffer = response.getDfsResponse();
            
            response.readDataWireFormat(buffer, 0, buffer.length);
            
            assertSame(originalBuffer, response.getDfsResponse());
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include class name in toString")
        void testToStringIncludesClassName() {
            String result = response.toString();
            
            assertNotNull(result);
            assertTrue(result.contains("Trans2GetDfsReferralResponse"));
        }

        @Test
        @DisplayName("Should include buffer information in toString")
        void testToStringIncludesBuffer() {
            String result = response.toString();
            
            assertNotNull(result);
            assertTrue(result.contains("buffer="));
        }

        @Test
        @DisplayName("Should have proper toString format")
        void testToStringFormat() {
            String result = response.toString();
            
            assertNotNull(result);
            assertTrue(result.startsWith("Trans2GetDfsReferralResponse["));
            assertTrue(result.endsWith("]"));
        }

        @Test
        @DisplayName("Should update toString after reading data")
        void testToStringAfterReadingData() {
            byte[] buffer = createValidDfsReferralBuffer();
            String beforeRead = response.toString();
            
            response.readDataWireFormat(buffer, 0, buffer.length);
            String afterRead = response.toString();
            
            assertNotEquals(beforeRead, afterRead);
            assertTrue(afterRead.contains("pathConsumed="));
            assertTrue(afterRead.contains("numReferrals="));
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle malformed buffer gracefully")
        void testReadDataWireFormatMalformedBuffer() {
            byte[] buffer = new byte[3]; // Too small for valid DFS referral
            
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
                response.readDataWireFormat(buffer, 0, buffer.length);
            });
        }

        @Test
        @DisplayName("Should handle buffer with invalid offset")
        void testReadDataWireFormatInvalidOffset() {
            byte[] buffer = createValidDfsReferralBuffer();
            
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
                response.readDataWireFormat(buffer, buffer.length + 1, 10);
            });
        }

        @Test
        @DisplayName("Should handle null buffer in write operations")
        void testWriteOperationsWithNullBuffer() {
            // Write operations return 0 when given null buffer - no exceptions thrown
            assertEquals(0, response.writeSetupWireFormat(null, 0));
            assertEquals(0, response.writeParametersWireFormat(null, 0));
            assertEquals(0, response.writeDataWireFormat(null, 0));
        }

        @Test
        @DisplayName("Should handle null buffer in read operations")
        void testReadOperationsWithNullBuffer() {
            // Read operations return 0 when given null buffer - no exceptions thrown
            assertEquals(0, response.readSetupWireFormat(null, 0, 0));
            assertEquals(0, response.readParametersWireFormat(null, 0, 0));
            
            // readDataWireFormat will throw when accessing null buffer
            assertThrows(NullPointerException.class, () -> {
                response.readDataWireFormat(null, 0, 0);
            });
        }
    }

    // Helper methods for creating test buffers

    private byte[] createValidDfsReferralBuffer() {
        // Create a buffer representing a valid DFS referral response
        // Need to include space for actual string data
        int stringDataStart = 28; // After the referral structure
        String testPath = "\\server\\share";
        byte[] pathBytes = testPath.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
        int bufferSize = stringDataStart + pathBytes.length + 2; // +2 for null terminator
        byte[] buffer = new byte[bufferSize];
        
        // Path consumed (2 bytes) - value: 10 * 2 = 20
        SMBUtil.writeInt2(20, buffer, 0);
        
        // Number of referrals (2 bytes) - value: 1
        SMBUtil.writeInt2(1, buffer, 2);
        
        // Flags (2 bytes)
        SMBUtil.writeInt2(0x0003, buffer, 4);
        
        // Padding (2 bytes)
        buffer[6] = 0;
        buffer[7] = 0;
        
        // First referral (minimal structure)
        // Version (2 bytes)
        SMBUtil.writeInt2(3, buffer, 8);
        
        // Size (2 bytes) - the size of this referral entry
        SMBUtil.writeInt2(20, buffer, 10);
        
        // Server type (2 bytes)
        SMBUtil.writeInt2(1, buffer, 12);
        
        // Referral flags (2 bytes)
        SMBUtil.writeInt2(0, buffer, 14);
        
        // Proximity (2 bytes for v3)
        SMBUtil.writeInt2(0, buffer, 16);
        
        // Time to live (2 bytes for v3)
        SMBUtil.writeInt2(300, buffer, 18);
        
        // DFS path offset (2 bytes) - points to string data
        SMBUtil.writeInt2(stringDataStart - 8, buffer, 20); // Offset from start of referral
        
        // DFS alternate path offset (2 bytes)
        SMBUtil.writeInt2(0, buffer, 22);
        
        // Network address offset (2 bytes)
        SMBUtil.writeInt2(0, buffer, 24);
        
        // Padding to align string data
        buffer[26] = 0;
        buffer[27] = 0;
        
        // Add the path string at stringDataStart
        System.arraycopy(pathBytes, 0, buffer, stringDataStart, pathBytes.length);
        // Null terminator
        buffer[stringDataStart + pathBytes.length] = 0;
        buffer[stringDataStart + pathBytes.length + 1] = 0;
        
        return buffer;
    }

    private byte[] createMinimalDfsReferralBuffer() {
        // Create minimal buffer with no referrals
        byte[] buffer = new byte[8];
        
        // Path consumed (2 bytes)
        SMBUtil.writeInt2(0, buffer, 0);
        
        // Number of referrals (2 bytes) - 0
        SMBUtil.writeInt2(0, buffer, 2);
        
        // Flags (2 bytes)
        SMBUtil.writeInt2(0, buffer, 4);
        
        // Padding (2 bytes)
        buffer[6] = 0;
        buffer[7] = 0;
        
        return buffer;
    }

    private byte[] createDfsReferralBufferWithMultipleReferrals(int numReferrals) {
        // Each referral structure needs 20 bytes, plus string data
        int referralSize = 20;
        int referralsDataSize = numReferrals * referralSize;
        
        // Add space for string data for each referral
        String testPath = "\\server\\share";
        byte[] pathBytes = testPath.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
        int stringDataSize = numReferrals * (pathBytes.length + 2); // +2 for null terminator per string
        
        int bufferSize = 8 + referralsDataSize + stringDataSize;
        byte[] buffer = new byte[bufferSize];
        
        // Path consumed (2 bytes)
        SMBUtil.writeInt2(10, buffer, 0);
        
        // Number of referrals (2 bytes)
        SMBUtil.writeInt2(numReferrals, buffer, 2);
        
        // Flags (2 bytes) - not using FLAGS_NAME_LIST_REFERRAL to avoid special name handling
        SMBUtil.writeInt2(0, buffer, 4);
        
        // Padding (2 bytes)
        buffer[6] = 0;
        buffer[7] = 0;
        
        // Add referrals
        int offset = 8;
        int stringOffset = 8 + referralsDataSize;
        
        for (int i = 0; i < numReferrals; i++) {
            // Version (2 bytes)
            SMBUtil.writeInt2(3, buffer, offset);
            
            // Size (2 bytes)
            SMBUtil.writeInt2(referralSize, buffer, offset + 2);
            
            // Server type (2 bytes)
            SMBUtil.writeInt2(i % 2, buffer, offset + 4);
            
            // Referral flags (2 bytes)
            SMBUtil.writeInt2(0, buffer, offset + 6);
            
            // Proximity (2 bytes for v3)
            SMBUtil.writeInt2(i, buffer, offset + 8);
            
            // Time to live (2 bytes for v3)
            SMBUtil.writeInt2(300 + i, buffer, offset + 10);
            
            // DFS path offset (2 bytes) - point to string data
            SMBUtil.writeInt2(stringOffset - offset, buffer, offset + 12);
            
            // DFS alternate path offset (2 bytes)
            SMBUtil.writeInt2(0, buffer, offset + 14);
            
            // Network address offset (2 bytes)
            SMBUtil.writeInt2(0, buffer, offset + 16);
            
            // Padding
            buffer[offset + 18] = 0;
            buffer[offset + 19] = 0;
            
            // Write string data at stringOffset
            System.arraycopy(pathBytes, 0, buffer, stringOffset, pathBytes.length);
            buffer[stringOffset + pathBytes.length] = 0;
            buffer[stringOffset + pathBytes.length + 1] = 0;
            
            offset += referralSize;
            stringOffset += pathBytes.length + 2;
        }
        
        return buffer;
    }
}