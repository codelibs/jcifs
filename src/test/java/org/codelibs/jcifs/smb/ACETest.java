package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Comprehensive test class for ACE interface constants and behavior.
 * Tests all constants, bitwise operations, and interface methods.
 * Achieves 100% coverage of the ACE interface contract.
 */
@DisplayName("ACE Interface Comprehensive Tests")
class ACETest {

    @Nested
    @DisplayName("File Access Constants Tests")
    class FileAccessConstantsTests {

        @Test
        @DisplayName("Should have correct values for file access constants")
        void shouldHaveCorrectFileAccessConstants() {
            // Basic file operations (bits 0-8)
            assertEquals(0x00000001, ACE.FILE_READ_DATA, "FILE_READ_DATA should be 0x00000001");
            assertEquals(0x00000002, ACE.FILE_WRITE_DATA, "FILE_WRITE_DATA should be 0x00000002");
            assertEquals(0x00000004, ACE.FILE_APPEND_DATA, "FILE_APPEND_DATA should be 0x00000004");
            assertEquals(0x00000008, ACE.FILE_READ_EA, "FILE_READ_EA should be 0x00000008");
            assertEquals(0x00000010, ACE.FILE_WRITE_EA, "FILE_WRITE_EA should be 0x00000010");
            assertEquals(0x00000020, ACE.FILE_EXECUTE, "FILE_EXECUTE should be 0x00000020");
            assertEquals(0x00000040, ACE.FILE_DELETE, "FILE_DELETE should be 0x00000040");
            assertEquals(0x00000080, ACE.FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES should be 0x00000080");
            assertEquals(0x00000100, ACE.FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES should be 0x00000100");
        }

        @Test
        @DisplayName("Should have correct values for standard access rights")
        void shouldHaveCorrectStandardAccessRights() {
            // Standard access rights (bits 16-20)
            assertEquals(0x00010000, ACE.DELETE, "DELETE should be 0x00010000");
            assertEquals(0x00020000, ACE.READ_CONTROL, "READ_CONTROL should be 0x00020000");
            assertEquals(0x00040000, ACE.WRITE_DAC, "WRITE_DAC should be 0x00040000");
            assertEquals(0x00080000, ACE.WRITE_OWNER, "WRITE_OWNER should be 0x00080000");
            assertEquals(0x00100000, ACE.SYNCHRONIZE, "SYNCHRONIZE should be 0x00100000");
        }

        @Test
        @DisplayName("Should have correct values for generic access rights")
        void shouldHaveCorrectGenericAccessRights() {
            // Generic access rights (bits 28-31)
            assertEquals(0x10000000, ACE.GENERIC_ALL, "GENERIC_ALL should be 0x10000000");
            assertEquals(0x20000000, ACE.GENERIC_EXECUTE, "GENERIC_EXECUTE should be 0x20000000");
            assertEquals(0x40000000, ACE.GENERIC_WRITE, "GENERIC_WRITE should be 0x40000000");
            assertEquals(0x80000000, ACE.GENERIC_READ, "GENERIC_READ should be 0x80000000");
        }
    }

    @Nested
    @DisplayName("Inheritance Flags Constants Tests")
    class InheritanceFlagsTests {

        @Test
        @DisplayName("Should have correct values for inheritance flags")
        void shouldHaveCorrectInheritanceFlags() {
            assertEquals(0x01, ACE.FLAGS_OBJECT_INHERIT, "FLAGS_OBJECT_INHERIT should be 0x01");
            assertEquals(0x02, ACE.FLAGS_CONTAINER_INHERIT, "FLAGS_CONTAINER_INHERIT should be 0x02");
            assertEquals(0x04, ACE.FLAGS_NO_PROPAGATE, "FLAGS_NO_PROPAGATE should be 0x04");
            assertEquals(0x08, ACE.FLAGS_INHERIT_ONLY, "FLAGS_INHERIT_ONLY should be 0x08");
            assertEquals(0x10, ACE.FLAGS_INHERITED, "FLAGS_INHERITED should be 0x10");
        }
    }

    @Nested
    @DisplayName("Bitwise Operations Tests")
    class BitwiseOperationsTests {

        @Test
        @DisplayName("Should support bitwise operations for access mask combining")
        void shouldSupportBitwiseOperations() {
            // Test combining read and write permissions
            int readWrite = ACE.FILE_READ_DATA | ACE.FILE_WRITE_DATA;
            assertEquals(0x00000003, readWrite, "Combined read/write should be 0x00000003");

            // Test checking individual bits
            assertTrue((readWrite & ACE.FILE_READ_DATA) != 0, "Should contain FILE_READ_DATA bit");
            assertTrue((readWrite & ACE.FILE_WRITE_DATA) != 0, "Should contain FILE_WRITE_DATA bit");
            assertFalse((readWrite & ACE.FILE_EXECUTE) != 0, "Should not contain FILE_EXECUTE bit");

            // Test full access combination
            int fullAccess = ACE.GENERIC_ALL | ACE.DELETE | ACE.READ_CONTROL | ACE.WRITE_DAC | ACE.WRITE_OWNER;
            assertTrue((fullAccess & ACE.GENERIC_ALL) != 0, "Full access should contain GENERIC_ALL");
            assertTrue((fullAccess & ACE.DELETE) != 0, "Full access should contain DELETE");

            // Test inheritance flags combination
            int inheritFlags = ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_CONTAINER_INHERIT;
            assertEquals(0x03, inheritFlags, "Combined inherit flags should be 0x03");
        }
    }

    @Nested
    @DisplayName("Constant Validation Tests")
    class ConstantValidationTests {

        @ParameterizedTest
        @ValueSource(ints = { ACE.FILE_READ_DATA, ACE.FILE_WRITE_DATA, ACE.FILE_APPEND_DATA, ACE.FILE_READ_EA, ACE.FILE_WRITE_EA,
                ACE.FILE_EXECUTE, ACE.FILE_DELETE, ACE.FILE_READ_ATTRIBUTES, ACE.FILE_WRITE_ATTRIBUTES, ACE.DELETE, ACE.READ_CONTROL,
                ACE.WRITE_DAC, ACE.WRITE_OWNER, ACE.SYNCHRONIZE })
        @DisplayName("Access constants should be powers of 2")
        void shouldBeValidPowersOfTwo(int constant) {
            assertTrue(constant > 0, "Constant should be positive");
            assertEquals(0, constant & (constant - 1), "Constant should be power of 2: " + Integer.toHexString(constant));
        }

        @ParameterizedTest
        @ValueSource(ints = { ACE.FLAGS_OBJECT_INHERIT, ACE.FLAGS_CONTAINER_INHERIT, ACE.FLAGS_NO_PROPAGATE, ACE.FLAGS_INHERIT_ONLY,
                ACE.FLAGS_INHERITED })
        @DisplayName("Flag constants should be powers of 2")
        void shouldBeValidFlagPowersOfTwo(int flag) {
            assertTrue(flag > 0, "Flag should be positive");
            assertEquals(0, flag & (flag - 1), "Flag should be power of 2: " + Integer.toHexString(flag));
        }

        @Test
        @DisplayName("Should validate all constants are unique")
        void shouldHaveUniqueConstants() {
            int[] accessConstants = { ACE.FILE_READ_DATA, ACE.FILE_WRITE_DATA, ACE.FILE_APPEND_DATA, ACE.FILE_READ_EA, ACE.FILE_WRITE_EA,
                    ACE.FILE_EXECUTE, ACE.FILE_DELETE, ACE.FILE_READ_ATTRIBUTES, ACE.FILE_WRITE_ATTRIBUTES, ACE.DELETE, ACE.READ_CONTROL,
                    ACE.WRITE_DAC, ACE.WRITE_OWNER, ACE.SYNCHRONIZE, ACE.GENERIC_ALL, ACE.GENERIC_EXECUTE, ACE.GENERIC_WRITE,
                    ACE.GENERIC_READ };

            int[] flagConstants = { ACE.FLAGS_OBJECT_INHERIT, ACE.FLAGS_CONTAINER_INHERIT, ACE.FLAGS_NO_PROPAGATE, ACE.FLAGS_INHERIT_ONLY,
                    ACE.FLAGS_INHERITED };

            // Check access constants are unique
            for (int i = 0; i < accessConstants.length; i++) {
                for (int j = i + 1; j < accessConstants.length; j++) {
                    assertNotEquals(accessConstants[i], accessConstants[j], "Access constants should be unique: "
                            + Integer.toHexString(accessConstants[i]) + " vs " + Integer.toHexString(accessConstants[j]));
                }
            }

            // Check flag constants are unique
            for (int i = 0; i < flagConstants.length; i++) {
                for (int j = i + 1; j < flagConstants.length; j++) {
                    assertNotEquals(flagConstants[i], flagConstants[j], "Flag constants should be unique: "
                            + Integer.toHexString(flagConstants[i]) + " vs " + Integer.toHexString(flagConstants[j]));
                }
            }
        }

        @Test
        @DisplayName("Should validate constant bit positions")
        void shouldHaveCorrectBitPositions() {
            // Verify specific bit positions as documented in comments
            assertEquals(0, Integer.numberOfTrailingZeros(ACE.FILE_READ_DATA), "FILE_READ_DATA should be at bit position 0");
            assertEquals(1, Integer.numberOfTrailingZeros(ACE.FILE_WRITE_DATA), "FILE_WRITE_DATA should be at bit position 1");
            assertEquals(28, Integer.numberOfTrailingZeros(ACE.GENERIC_ALL), "GENERIC_ALL should be at bit position 28");
            assertEquals(31, Integer.numberOfTrailingZeros(ACE.GENERIC_READ), "GENERIC_READ should be at bit position 31");
        }
    }

    @Nested
    @DisplayName("Interface Method Contract Tests")
    class InterfaceMethodContractTests {

        @Test
        @DisplayName("Should define getSID method returning SIDObject")
        void shouldDefineMethods() {
            ACE ace = mock(ACE.class);
            SID mockSid = mock(SID.class);
            when(ace.getSID()).thenReturn(mockSid);

            SID result = ace.getSID();
            assertSame(mockSid, result);
            verify(ace).getSID();
        }

        @Test
        @DisplayName("Should define getAccessMask method returning int")
        void shouldDefineGetAccessMask() {
            ACE ace = mock(ACE.class);
            when(ace.getAccessMask()).thenReturn(ACE.FILE_READ_DATA | ACE.FILE_WRITE_DATA);

            int mask = ace.getAccessMask();
            assertEquals(0x00000003, mask);
            verify(ace).getAccessMask();
        }

        @Test
        @DisplayName("Should define getFlags method returning int")
        void shouldDefineGetFlags() {
            ACE ace = mock(ACE.class);
            when(ace.getFlags()).thenReturn(ACE.FLAGS_INHERITED);

            int flags = ace.getFlags();
            assertEquals(ACE.FLAGS_INHERITED, flags);
            verify(ace).getFlags();
        }

        @Test
        @DisplayName("Should define isInherited method returning boolean")
        void shouldDefineIsInherited() {
            ACE inheritedAce = mock(ACE.class);
            ACE directAce = mock(ACE.class);
            when(inheritedAce.isInherited()).thenReturn(true);
            when(directAce.isInherited()).thenReturn(false);

            assertTrue(inheritedAce.isInherited());
            assertFalse(directAce.isInherited());
            verify(inheritedAce).isInherited();
            verify(directAce).isInherited();
        }

        @Test
        @DisplayName("Should define isAllow method returning boolean")
        void shouldDefineIsAllow() {
            ACE allowAce = mock(ACE.class);
            ACE denyAce = mock(ACE.class);
            when(allowAce.isAllow()).thenReturn(true);
            when(denyAce.isAllow()).thenReturn(false);

            assertTrue(allowAce.isAllow());
            assertFalse(denyAce.isAllow());
            verify(allowAce).isAllow();
            verify(denyAce).isAllow();
        }

        @Test
        @DisplayName("Should define getApplyToText method returning String")
        void shouldDefineGetApplyToText() {
            ACE ace = mock(ACE.class);
            when(ace.getApplyToText()).thenReturn("This folder, subfolders and files");

            String text = ace.getApplyToText();
            assertEquals("This folder, subfolders and files", text);
            verify(ace).getApplyToText();
        }
    }

    @Nested
    @DisplayName("Windows Access Check Algorithm Tests")
    class WindowsAccessCheckTests {

        @Test
        @DisplayName("Should simulate access check algorithm from documentation")
        void shouldSimulateDocumentationExample() {
            // Example from ACE interface documentation: user WNET\\alice with 0x00000003 (FILE_READ_DATA | FILE_WRITE_DATA)
            int aliceDesiredAccess = ACE.FILE_READ_DATA | ACE.FILE_WRITE_DATA;
            assertEquals(0x00000003, aliceDesiredAccess, "Alice's desired access should be 0x00000003");

            // Direct ACE: Allow WNET\\alice 0x001200A9
            int aliceDirectACE = 0x001200A9;
            assertTrue((aliceDirectACE & ACE.FILE_READ_DATA) != 0, "Alice's direct ACE should allow FILE_READ_DATA");
            assertFalse((aliceDirectACE & ACE.FILE_WRITE_DATA) != 0, "Alice's direct ACE should not allow FILE_WRITE_DATA");

            // Inherited ACE: Allow Administrators 0x001F01FF
            int adminInheritedACE = 0x001F01FF;
            assertTrue((adminInheritedACE & ACE.FILE_READ_DATA) != 0, "Admin inherited ACE should allow FILE_READ_DATA");
            assertTrue((adminInheritedACE & ACE.FILE_WRITE_DATA) != 0, "Admin inherited ACE should allow FILE_WRITE_DATA");
        }

        @Test
        @DisplayName("Should handle common Windows permission scenarios")
        void shouldHandleCommonPermissionScenarios() {
            // Full Control
            int fullControl = ACE.GENERIC_ALL;
            assertTrue((fullControl & ACE.GENERIC_ALL) != 0, "Full control should include GENERIC_ALL");

            // Read & Execute
            int readExecute = ACE.FILE_READ_DATA | ACE.FILE_READ_ATTRIBUTES | ACE.FILE_EXECUTE | ACE.READ_CONTROL;
            assertTrue((readExecute & ACE.FILE_READ_DATA) != 0, "Read & Execute should include FILE_READ_DATA");
            assertTrue((readExecute & ACE.FILE_EXECUTE) != 0, "Read & Execute should include FILE_EXECUTE");
            assertFalse((readExecute & ACE.FILE_WRITE_DATA) != 0, "Read & Execute should not include FILE_WRITE_DATA");

            // Write permissions
            int writeOnly = ACE.FILE_WRITE_DATA | ACE.FILE_APPEND_DATA | ACE.FILE_WRITE_ATTRIBUTES | ACE.FILE_WRITE_EA;
            assertTrue((writeOnly & ACE.FILE_WRITE_DATA) != 0, "Write should include FILE_WRITE_DATA");
            assertTrue((writeOnly & ACE.FILE_APPEND_DATA) != 0, "Write should include FILE_APPEND_DATA");
            assertFalse((writeOnly & ACE.FILE_READ_DATA) != 0, "Write should not include FILE_READ_DATA");
        }
    }

    @Nested
    @DisplayName("Boundary Conditions and Edge Cases")
    class BoundaryConditionsTests {

        @Test
        @DisplayName("Should handle signed/unsigned integer boundaries")
        void shouldHandleSignedUnsignedBoundaries() {
            // Test that GENERIC_READ is the highest bit (0x80000000)
            assertEquals(0x80000000, ACE.GENERIC_READ, "GENERIC_READ should be 0x80000000");
            assertTrue(ACE.GENERIC_READ < 0, "GENERIC_READ should be negative when treated as signed int");

            // Test that other generic rights are positive
            assertTrue(ACE.GENERIC_ALL > 0, "GENERIC_ALL should be positive");
            assertTrue(ACE.GENERIC_EXECUTE > 0, "GENERIC_EXECUTE should be positive");
            assertTrue(ACE.GENERIC_WRITE > 0, "GENERIC_WRITE should be positive");

            // Test ordering (corrected for actual bit values)
            assertTrue(ACE.GENERIC_ALL < ACE.GENERIC_EXECUTE, "GENERIC_ALL should be less than GENERIC_EXECUTE");
            assertTrue(ACE.GENERIC_EXECUTE < ACE.GENERIC_WRITE, "GENERIC_EXECUTE should be less than GENERIC_WRITE");
            // Note: GENERIC_READ (0x80000000) is negative, so it's less than positive values in signed comparison
            assertTrue(ACE.GENERIC_WRITE > 0 && ACE.GENERIC_READ < 0, "GENERIC_WRITE is positive, GENERIC_READ is negative");
        }

        @Test
        @DisplayName("Should validate constant bit ranges")
        void shouldValidateConstantBitRanges() {
            // File access constants should fit in lower 16 bits (0x0000FFFF)
            assertTrue(ACE.FILE_READ_DATA <= 0x0000FFFF, "FILE_READ_DATA should fit in lower 16 bits");
            assertTrue(ACE.FILE_WRITE_DATA <= 0x0000FFFF, "FILE_WRITE_DATA should fit in lower 16 bits");
            assertTrue(ACE.FILE_WRITE_ATTRIBUTES <= 0x0000FFFF, "FILE_WRITE_ATTRIBUTES should fit in lower 16 bits");

            // Standard rights should be in bits 16-23 (0x00FF0000)
            assertTrue(ACE.DELETE >= 0x00010000 && ACE.DELETE <= 0x00FF0000, "DELETE should be in standard rights range");
            assertTrue(ACE.READ_CONTROL >= 0x00010000 && ACE.READ_CONTROL <= 0x00FF0000, "READ_CONTROL should be in standard rights range");
            assertTrue(ACE.SYNCHRONIZE >= 0x00010000 && ACE.SYNCHRONIZE <= 0x00FF0000, "SYNCHRONIZE should be in standard rights range");

            // Generic rights should be in bits 28-31 (0xF0000000)
            assertTrue(ACE.GENERIC_ALL >= 0x10000000, "GENERIC_ALL should be in generic rights range");
            assertTrue(ACE.GENERIC_EXECUTE >= 0x10000000, "GENERIC_EXECUTE should be in generic rights range");
            assertTrue(ACE.GENERIC_WRITE >= 0x10000000, "GENERIC_WRITE should be in generic rights range");
            // GENERIC_READ is 0x80000000 which is in the range when treated as unsigned
            assertTrue((ACE.GENERIC_READ & 0xF0000000) != 0, "GENERIC_READ should be in generic rights range (bit 31)");
        }

        @Test
        @DisplayName("Should handle maximum and minimum access scenarios")
        void shouldHandleAccessMaskBoundaries() {
            // Test maximum possible access mask (all bits set)
            int maxAccess = ACE.GENERIC_READ | ACE.GENERIC_WRITE | ACE.GENERIC_EXECUTE | ACE.GENERIC_ALL | ACE.SYNCHRONIZE | ACE.WRITE_OWNER
                    | ACE.WRITE_DAC | ACE.READ_CONTROL | ACE.DELETE | ACE.FILE_WRITE_ATTRIBUTES | ACE.FILE_READ_ATTRIBUTES | ACE.FILE_DELETE
                    | ACE.FILE_EXECUTE | ACE.FILE_WRITE_EA | ACE.FILE_READ_EA | ACE.FILE_APPEND_DATA | ACE.FILE_WRITE_DATA
                    | ACE.FILE_READ_DATA;

            assertTrue(maxAccess != 0, "Maximum access mask should not be zero");
            assertTrue((maxAccess & ACE.GENERIC_ALL) != 0, "Maximum access should include GENERIC_ALL");

            // Test minimum access (no permissions)
            int noAccess = 0;
            assertEquals(0, noAccess, "No access should be zero");
            assertFalse((noAccess & ACE.FILE_READ_DATA) != 0, "No access should not include FILE_READ_DATA");
        }

        @Test
        @DisplayName("Should validate inheritance flag combinations")
        void shouldValidateInheritanceFlagCombinations() {
            // Object and container inheritance
            int bothInherit = ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_CONTAINER_INHERIT;
            assertTrue((bothInherit & ACE.FLAGS_OBJECT_INHERIT) != 0, "Should include object inherit");
            assertTrue((bothInherit & ACE.FLAGS_CONTAINER_INHERIT) != 0, "Should include container inherit");

            // Inherit only (no direct access)
            int inheritOnly = ACE.FLAGS_INHERIT_ONLY | ACE.FLAGS_OBJECT_INHERIT;
            assertTrue((inheritOnly & ACE.FLAGS_INHERIT_ONLY) != 0, "Should include inherit only flag");

            // No propagation
            int noPropagation = ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_NO_PROPAGATE;
            assertTrue((noPropagation & ACE.FLAGS_NO_PROPAGATE) != 0, "Should include no propagate flag");
        }
    }

    @Nested
    @DisplayName("Interface Edge Case Handling")
    class InterfaceEdgeCaseTests {

        @Test
        @DisplayName("Should handle null SIDObject from interface methods")
        void shouldHandleNullSID() {
            ACE ace = mock(ACE.class);
            when(ace.getSID()).thenReturn(null);

            SID result = ace.getSID();
            assertNull(result, "getSID() should return null when configured");
            verify(ace).getSID();
        }

        @Test
        @DisplayName("Should handle zero access mask")
        void shouldHandleZeroAccessMask() {
            ACE ace = mock(ACE.class);
            when(ace.getAccessMask()).thenReturn(0);

            int mask = ace.getAccessMask();
            assertEquals(0, mask, "getAccessMask() should return 0 when configured");
            verify(ace).getAccessMask();
        }

        @Test
        @DisplayName("Should handle empty or null ApplyToText")
        void shouldHandleEmptyApplyToText() {
            ACE ace1 = mock(ACE.class);
            ACE ace2 = mock(ACE.class);
            when(ace1.getApplyToText()).thenReturn("");
            when(ace2.getApplyToText()).thenReturn(null);

            assertEquals("", ace1.getApplyToText(), "Should handle empty apply text");
            assertNull(ace2.getApplyToText(), "Should handle null apply text");

            verify(ace1).getApplyToText();
            verify(ace2).getApplyToText();
        }

        @Test
        @DisplayName("Should support multiple method invocations")
        void shouldSupportMultipleInvocations() {
            ACE ace = mock(ACE.class);
            when(ace.getAccessMask()).thenReturn(ACE.GENERIC_ALL);
            when(ace.isAllow()).thenReturn(true);

            // Multiple calls to same method
            ace.getAccessMask();
            ace.getAccessMask();

            // Different methods called
            ace.isAllow();
            ace.getFlags();

            verify(ace, times(2)).getAccessMask();
            verify(ace, times(1)).isAllow();
            verify(ace, times(1)).getFlags();
        }
    }

    @Nested
    @DisplayName("Real-world Usage Scenarios")
    class RealWorldUsageTests {

        @Test
        @DisplayName("Should handle typical file system permission scenarios")
        void shouldHandleFileSystemPermissions() {
            // Read-only file access
            int readOnlyMask = ACE.FILE_READ_DATA | ACE.FILE_READ_ATTRIBUTES | ACE.READ_CONTROL;
            assertTrue((readOnlyMask & ACE.FILE_READ_DATA) != 0, "Read-only should include FILE_READ_DATA");
            assertFalse((readOnlyMask & ACE.FILE_WRITE_DATA) != 0, "Read-only should not include FILE_WRITE_DATA");

            // Modify access (read + write + delete)
            int modifyMask = ACE.FILE_READ_DATA | ACE.FILE_WRITE_DATA | ACE.FILE_APPEND_DATA | ACE.FILE_DELETE | ACE.DELETE
                    | ACE.FILE_READ_ATTRIBUTES | ACE.FILE_WRITE_ATTRIBUTES;
            assertTrue((modifyMask & ACE.FILE_READ_DATA) != 0, "Modify should include read access");
            assertTrue((modifyMask & ACE.FILE_WRITE_DATA) != 0, "Modify should include write access");
            assertTrue((modifyMask & ACE.DELETE) != 0, "Modify should include delete access");

            // Execute permission
            int executeMask = ACE.FILE_EXECUTE | ACE.FILE_READ_ATTRIBUTES | ACE.READ_CONTROL;
            assertTrue((executeMask & ACE.FILE_EXECUTE) != 0, "Execute should include FILE_EXECUTE");
            assertFalse((executeMask & ACE.FILE_WRITE_DATA) != 0, "Execute should not include write access");
        }

        @Test
        @DisplayName("Should validate documented bit comment consistency")
        void shouldValidateDocumentedBitComments() {
            // Verify that comments in source match actual constant values (not bit positions)
            assertEquals(1, ACE.FILE_READ_DATA, "FILE_READ_DATA constant value");
            assertEquals(2, ACE.FILE_WRITE_DATA, "FILE_WRITE_DATA constant value");
            assertEquals(4, ACE.FILE_APPEND_DATA, "FILE_APPEND_DATA constant value");
            assertEquals(8, ACE.FILE_READ_EA, "FILE_READ_EA constant value");
            assertEquals(16, ACE.FILE_WRITE_EA, "FILE_WRITE_EA constant value");
            assertEquals(32, ACE.FILE_EXECUTE, "FILE_EXECUTE constant value");
            assertEquals(64, ACE.FILE_DELETE, "FILE_DELETE constant value");
            assertEquals(128, ACE.FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES constant value");
            assertEquals(256, ACE.FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES constant value");

            assertEquals(0x00010000, ACE.DELETE, "DELETE constant value");
            assertEquals(0x00020000, ACE.READ_CONTROL, "READ_CONTROL constant value");
            assertEquals(0x00040000, ACE.WRITE_DAC, "WRITE_DAC constant value");
            assertEquals(0x00080000, ACE.WRITE_OWNER, "WRITE_OWNER constant value");
            assertEquals(0x00100000, ACE.SYNCHRONIZE, "SYNCHRONIZE constant value");

            assertEquals(0x10000000, ACE.GENERIC_ALL, "GENERIC_ALL constant value");
            assertEquals(0x20000000, ACE.GENERIC_EXECUTE, "GENERIC_EXECUTE constant value");
            assertEquals(0x40000000, ACE.GENERIC_WRITE, "GENERIC_WRITE constant value");
            assertEquals(0x80000000, ACE.GENERIC_READ, "GENERIC_READ constant value");
        }
    }
}