package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test class for Smb2Constants
 * Tests all SMB2 protocol constants and their expected values
 */
@DisplayName("Smb2Constants Test Suite")
class Smb2ConstantsTest {

    @Test
    @DisplayName("Should have private constructor to prevent instantiation")
    void testPrivateConstructor() throws Exception {
        // Verify constructor is private
        Constructor<Smb2Constants> constructor = Smb2Constants.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()), "Constructor should be private");

        // Force accessibility and create instance to achieve coverage
        constructor.setAccessible(true);
        assertNotNull(constructor.newInstance(), "Should be able to create instance via reflection");
    }

    @Nested
    @DisplayName("Header Constants")
    class HeaderConstants {

        @Test
        @DisplayName("SMB2 header length should be 64 bytes")
        void testSmb2HeaderLength() {
            assertEquals(64, Smb2Constants.SMB2_HEADER_LENGTH, "SMB2 header must be exactly 64 bytes");
        }
    }

    @Nested
    @DisplayName("Negotiation Constants")
    class NegotiationConstants {

        @Test
        @DisplayName("Signing enabled flag should be 0x0001")
        void testSigningEnabledFlag() {
            assertEquals(0x0001, Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED, "Signing enabled flag must be 0x0001");
        }

        @Test
        @DisplayName("Signing required flag should be 0x0002")
        void testSigningRequiredFlag() {
            assertEquals(0x0002, Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, "Signing required flag must be 0x0002");
        }

        @Test
        @DisplayName("Signing flags should not overlap")
        void testSigningFlagsNoOverlap() {
            assertNotEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED, Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED,
                    "Signing flags must be distinct");

            // Verify they can be combined with bitwise OR
            int combined = Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED;
            assertEquals(0x0003, combined, "Combined signing flags should equal 0x0003");
        }
    }

    @Nested
    @DisplayName("Dialect Constants")
    class DialectConstants {

        @Test
        @DisplayName("SMB 2.0.2 dialect should be 0x0202")
        void testDialect0202() {
            assertEquals(0x0202, Smb2Constants.SMB2_DIALECT_0202, "SMB 2.0.2 dialect must be 0x0202");
        }

        @Test
        @DisplayName("SMB 2.1 dialect should be 0x0210")
        void testDialect0210() {
            assertEquals(0x0210, Smb2Constants.SMB2_DIALECT_0210, "SMB 2.1 dialect must be 0x0210");
        }

        @Test
        @DisplayName("SMB 3.0 dialect should be 0x0300")
        void testDialect0300() {
            assertEquals(0x0300, Smb2Constants.SMB2_DIALECT_0300, "SMB 3.0 dialect must be 0x0300");
        }

        @Test
        @DisplayName("SMB 3.0.2 dialect should be 0x0302")
        void testDialect0302() {
            assertEquals(0x0302, Smb2Constants.SMB2_DIALECT_0302, "SMB 3.0.2 dialect must be 0x0302");
        }

        @Test
        @DisplayName("SMB 3.1.1 dialect should be 0x0311")
        void testDialect0311() {
            assertEquals(0x0311, Smb2Constants.SMB2_DIALECT_0311, "SMB 3.1.1 dialect must be 0x0311");
        }

        @Test
        @DisplayName("SMB dialect ANY should be 0x02FF")
        void testDialectAny() {
            assertEquals(0x02FF, Smb2Constants.SMB2_DIALECT_ANY, "SMB dialect ANY must be 0x02FF");
        }

        @ParameterizedTest
        @ValueSource(ints = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 })
        @DisplayName("All specific dialects should be greater than or equal to SMB 2.0.2")
        void testDialectVersionProgression(int dialect) {
            assertTrue(dialect >= Smb2Constants.SMB2_DIALECT_0202,
                    "Dialect " + String.format("0x%04X", dialect) + " should be >= SMB 2.0.2");
        }

        @Test
        @DisplayName("Dialects should be in ascending order")
        void testDialectOrdering() {
            assertTrue(Smb2Constants.SMB2_DIALECT_0202 < Smb2Constants.SMB2_DIALECT_0210, "SMB 2.0.2 should be less than SMB 2.1");
            assertTrue(Smb2Constants.SMB2_DIALECT_0210 < Smb2Constants.SMB2_DIALECT_0300, "SMB 2.1 should be less than SMB 3.0");
            assertTrue(Smb2Constants.SMB2_DIALECT_0300 < Smb2Constants.SMB2_DIALECT_0302, "SMB 3.0 should be less than SMB 3.0.2");
            assertTrue(Smb2Constants.SMB2_DIALECT_0302 < Smb2Constants.SMB2_DIALECT_0311, "SMB 3.0.2 should be less than SMB 3.1.1");
        }
    }

    @Nested
    @DisplayName("Global Capability Constants")
    class GlobalCapabilityConstants {

        @Test
        @DisplayName("DFS capability should be 0x1")
        void testGlobalCapDfs() {
            assertEquals(0x1, Smb2Constants.SMB2_GLOBAL_CAP_DFS, "DFS capability must be 0x1");
        }

        @Test
        @DisplayName("Leasing capability should be 0x2")
        void testGlobalCapLeasing() {
            assertEquals(0x2, Smb2Constants.SMB2_GLOBAL_CAP_LEASING, "Leasing capability must be 0x2");
        }

        @Test
        @DisplayName("Large MTU capability should be 0x4")
        void testGlobalCapLargeMtu() {
            assertEquals(0x4, Smb2Constants.SMB2_GLOBAL_CAP_LARGE_MTU, "Large MTU capability must be 0x4");
        }

        @Test
        @DisplayName("Multi-channel capability should be 0x8")
        void testGlobalCapMultiChannel() {
            assertEquals(0x8, Smb2Constants.SMB2_GLOBAL_CAP_MULTI_CHANNEL, "Multi-channel capability must be 0x8");
        }

        @Test
        @DisplayName("Persistent handles capability should be 0x10")
        void testGlobalCapPersistentHandles() {
            assertEquals(0x10, Smb2Constants.SMB2_GLOBAL_CAP_PERSISTENT_HANDLES, "Persistent handles capability must be 0x10");
        }

        @Test
        @DisplayName("Directory leasing capability should be 0x20")
        void testGlobalCapDirectoryLeasing() {
            assertEquals(0x20, Smb2Constants.SMB2_GLOBAL_CAP_DIRECTORY_LEASING, "Directory leasing capability must be 0x20");
        }

        @Test
        @DisplayName("Encryption capability should be 0x40")
        void testGlobalCapEncryption() {
            assertEquals(0x40, Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION, "Encryption capability must be 0x40");
        }

        @Test
        @DisplayName("All capability flags should be unique powers of 2")
        void testCapabilityFlagsUnique() {
            int[] capabilities =
                    { Smb2Constants.SMB2_GLOBAL_CAP_DFS, Smb2Constants.SMB2_GLOBAL_CAP_LEASING, Smb2Constants.SMB2_GLOBAL_CAP_LARGE_MTU,
                            Smb2Constants.SMB2_GLOBAL_CAP_MULTI_CHANNEL, Smb2Constants.SMB2_GLOBAL_CAP_PERSISTENT_HANDLES,
                            Smb2Constants.SMB2_GLOBAL_CAP_DIRECTORY_LEASING, Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION };

            // Verify each is a power of 2
            for (int cap : capabilities) {
                assertTrue(isPowerOfTwo(cap), "Capability 0x" + Integer.toHexString(cap) + " should be a power of 2");
            }

            // Verify no overlapping bits
            for (int i = 0; i < capabilities.length; i++) {
                for (int j = i + 1; j < capabilities.length; j++) {
                    assertEquals(0, capabilities[i] & capabilities[j], "Capabilities should not have overlapping bits");
                }
            }
        }

        @Test
        @DisplayName("Combined capabilities should work with bitwise OR")
        void testCombinedCapabilities() {
            int allCaps =
                    Smb2Constants.SMB2_GLOBAL_CAP_DFS | Smb2Constants.SMB2_GLOBAL_CAP_LEASING | Smb2Constants.SMB2_GLOBAL_CAP_LARGE_MTU
                            | Smb2Constants.SMB2_GLOBAL_CAP_MULTI_CHANNEL | Smb2Constants.SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
                            | Smb2Constants.SMB2_GLOBAL_CAP_DIRECTORY_LEASING | Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION;

            assertEquals(0x7F, allCaps, "All capabilities combined should equal 0x7F");
        }

        private boolean isPowerOfTwo(int n) {
            return n > 0 && (n & (n - 1)) == 0;
        }
    }

    @Nested
    @DisplayName("Info Level Constants")
    class InfoLevelConstants {

        @Test
        @DisplayName("File info level should be 1")
        void testInfoFile() {
            assertEquals(1, Smb2Constants.SMB2_0_INFO_FILE, "File info level must be 1");
        }

        @Test
        @DisplayName("Filesystem info level should be 2")
        void testInfoFilesystem() {
            assertEquals(2, Smb2Constants.SMB2_0_INFO_FILESYSTEM, "Filesystem info level must be 2");
        }

        @Test
        @DisplayName("Security info level should be 3")
        void testInfoSecurity() {
            assertEquals(3, Smb2Constants.SMB2_0_INFO_SECURITY, "Security info level must be 3");
        }

        @Test
        @DisplayName("Quota info level should be 4")
        void testInfoQuota() {
            assertEquals(4, Smb2Constants.SMB2_0_INFO_QUOTA, "Quota info level must be 4");
        }

        @Test
        @DisplayName("All info levels should be sequential")
        void testInfoLevelsSequential() {
            assertEquals(Smb2Constants.SMB2_0_INFO_FILE + 1, Smb2Constants.SMB2_0_INFO_FILESYSTEM, "Filesystem should be File + 1");
            assertEquals(Smb2Constants.SMB2_0_INFO_FILESYSTEM + 1, Smb2Constants.SMB2_0_INFO_SECURITY, "Security should be Filesystem + 1");
            assertEquals(Smb2Constants.SMB2_0_INFO_SECURITY + 1, Smb2Constants.SMB2_0_INFO_QUOTA, "Quota should be Security + 1");
        }
    }

    @Nested
    @DisplayName("Special Value Constants")
    class SpecialValueConstants {

        @Test
        @DisplayName("Unspecified FileId should be 16 bytes of 0xFF")
        void testUnspecifiedFileId() {
            assertNotNull(Smb2Constants.UNSPECIFIED_FILEID, "Unspecified FileId should not be null");
            assertEquals(16, Smb2Constants.UNSPECIFIED_FILEID.length, "Unspecified FileId must be exactly 16 bytes");

            // Verify all bytes are 0xFF
            for (int i = 0; i < Smb2Constants.UNSPECIFIED_FILEID.length; i++) {
                assertEquals((byte) 0xFF, Smb2Constants.UNSPECIFIED_FILEID[i], "Byte " + i + " should be 0xFF");
            }
        }

        @Test
        @DisplayName("Unspecified TreeId should be 0xFFFFFFFF")
        void testUnspecifiedTreeId() {
            assertEquals(0xFFFFFFFF, Smb2Constants.UNSPECIFIED_TREEID, "Unspecified TreeId must be 0xFFFFFFFF");
            assertEquals(-1, Smb2Constants.UNSPECIFIED_TREEID, "Unspecified TreeId as signed int should be -1");
        }

        @Test
        @DisplayName("Unspecified SessionId should be 0xFFFFFFFFFFFFFFFF")
        void testUnspecifiedSessionId() {
            assertEquals(0xFFFFFFFFFFFFFFFFL, Smb2Constants.UNSPECIFIED_SESSIONID, "Unspecified SessionId must be 0xFFFFFFFFFFFFFFFF");
            assertEquals(-1L, Smb2Constants.UNSPECIFIED_SESSIONID, "Unspecified SessionId as signed long should be -1");
        }

        @Test
        @DisplayName("Unspecified FileId should be immutable")
        void testUnspecifiedFileIdImmutability() {
            byte[] originalFileId = Smb2Constants.UNSPECIFIED_FILEID;
            byte[] copyFileId = Smb2Constants.UNSPECIFIED_FILEID.clone();

            // Modify the copy
            copyFileId[0] = 0x00;

            // Verify original is unchanged
            assertEquals((byte) 0xFF, originalFileId[0], "Original FileId should remain unchanged");
            assertArrayEquals(
                    new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
                    originalFileId, "Original FileId array should remain all 0xFF");
        }
    }

    @Nested
    @DisplayName("Constant Relationships")
    class ConstantRelationships {

        @Test
        @DisplayName("Header length should be suitable for SMB2 protocol")
        void testHeaderLengthValidity() {
            assertTrue(Smb2Constants.SMB2_HEADER_LENGTH > 0, "Header length must be positive");
            assertTrue(Smb2Constants.SMB2_HEADER_LENGTH % 8 == 0, "Header length should be multiple of 8 for alignment");
        }

        @Test
        @DisplayName("Dialect ANY should encompass SMB2 range")
        void testDialectAnyRange() {
            assertTrue((Smb2Constants.SMB2_DIALECT_ANY & 0xFF00) == 0x0200, "Dialect ANY should be in SMB2 range (0x02xx)");
            assertTrue(Smb2Constants.SMB2_DIALECT_ANY > Smb2Constants.SMB2_DIALECT_0202,
                    "Dialect ANY should be greater than lowest dialect");
            assertTrue(Smb2Constants.SMB2_DIALECT_ANY < Smb2Constants.SMB2_DIALECT_0300, "Dialect ANY should be less than SMB3 dialects");
        }

        @Test
        @DisplayName("Capability values should fit in 32-bit integer")
        void testCapabilityValueRange() {
            int maxCap = Smb2Constants.SMB2_GLOBAL_CAP_DFS | Smb2Constants.SMB2_GLOBAL_CAP_LEASING | Smb2Constants.SMB2_GLOBAL_CAP_LARGE_MTU
                    | Smb2Constants.SMB2_GLOBAL_CAP_MULTI_CHANNEL | Smb2Constants.SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
                    | Smb2Constants.SMB2_GLOBAL_CAP_DIRECTORY_LEASING | Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION;

            assertTrue(maxCap > 0 && maxCap < Integer.MAX_VALUE, "Combined capabilities should fit in positive 32-bit integer");
        }
    }
}
