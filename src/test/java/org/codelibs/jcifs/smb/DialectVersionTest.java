package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Test class for DialectVersion functionality
 */
@DisplayName("DialectVersion Tests")
class DialectVersionTest extends BaseTest {

    @Test
    @DisplayName("Should define all SMB dialect versions")
    void testDialectVersionConstants() {
        // Verify all major SMB versions are defined
        assertNotNull(DialectVersion.SMB1);
        assertNotNull(DialectVersion.SMB202);
        assertNotNull(DialectVersion.SMB210);
        assertNotNull(DialectVersion.SMB300);
        assertNotNull(DialectVersion.SMB302);
        assertNotNull(DialectVersion.SMB311);
    }

    @Test
    @DisplayName("Should have correct version ordering")
    void testVersionOrdering() {
        // SMB versions should be ordered chronologically
        assertTrue(DialectVersion.SMB1.compareTo(DialectVersion.SMB202) < 0);
        assertTrue(DialectVersion.SMB202.compareTo(DialectVersion.SMB210) < 0);
        assertTrue(DialectVersion.SMB210.compareTo(DialectVersion.SMB300) < 0);
        assertTrue(DialectVersion.SMB300.compareTo(DialectVersion.SMB302) < 0);
        assertTrue(DialectVersion.SMB302.compareTo(DialectVersion.SMB311) < 0);
    }

    @Test
    @DisplayName("Should identify SMB1 vs SMB2+ versions")
    void testSMBVersionIdentification() {
        // SMB1 should not be SMB2
        assertFalse(DialectVersion.SMB1.isSMB2());

        // SMB2+ versions should be identified as SMB2
        assertTrue(DialectVersion.SMB202.isSMB2());
        assertTrue(DialectVersion.SMB210.isSMB2());
        assertTrue(DialectVersion.SMB300.isSMB2());
        assertTrue(DialectVersion.SMB302.isSMB2());
        assertTrue(DialectVersion.SMB311.isSMB2());
    }

    @Test
    @DisplayName("Should have correct dialect codes for SMB2+ versions")
    void testDialectCodes() {
        // SMB1 should throw UnsupportedOperationException
        assertThrows(UnsupportedOperationException.class, () -> {
            DialectVersion.SMB1.getDialect();
        });

        // SMB2+ versions should have valid dialect codes
        assertTrue(DialectVersion.SMB202.getDialect() > 0);
        assertTrue(DialectVersion.SMB210.getDialect() > 0);
        assertTrue(DialectVersion.SMB300.getDialect() > 0);
        assertTrue(DialectVersion.SMB302.getDialect() > 0);
        assertTrue(DialectVersion.SMB311.getDialect() > 0);
    }

    @ParameterizedTest
    @EnumSource(DialectVersion.class)
    @DisplayName("Should have string representation for all versions")
    void testStringRepresentation(DialectVersion version) {
        // When
        String stringRep = version.toString();

        // Then
        assertNotNull(stringRep);
        assertFalse(stringRep.isEmpty());
    }

    @Test
    @DisplayName("Should handle version comparison")
    void testVersionComparison() {
        // Test equality
        assertEquals(DialectVersion.SMB311, DialectVersion.SMB311);
        assertNotEquals(DialectVersion.SMB1, DialectVersion.SMB311);

        // Test comparison
        assertTrue(DialectVersion.SMB1.compareTo(DialectVersion.SMB311) < 0);
        assertTrue(DialectVersion.SMB311.compareTo(DialectVersion.SMB1) > 0);
        assertEquals(0, DialectVersion.SMB302.compareTo(DialectVersion.SMB302));
    }

    @Test
    @DisplayName("Should return consistent ordinal values")
    void testOrdinalValues() {
        // Ordinal values should be consistent with enum declaration order
        assertTrue(DialectVersion.SMB1.ordinal() < DialectVersion.SMB202.ordinal());
        assertTrue(DialectVersion.SMB202.ordinal() < DialectVersion.SMB210.ordinal());
        assertTrue(DialectVersion.SMB210.ordinal() < DialectVersion.SMB300.ordinal());
        assertTrue(DialectVersion.SMB300.ordinal() < DialectVersion.SMB302.ordinal());
        assertTrue(DialectVersion.SMB302.ordinal() < DialectVersion.SMB311.ordinal());
    }

    @Test
    @DisplayName("Should handle dialect version sets")
    void testDialectVersionSets() {
        // Test creating sets of dialect versions
        java.util.Set<DialectVersion> smb2Versions = java.util.EnumSet.of(DialectVersion.SMB202, DialectVersion.SMB210,
                DialectVersion.SMB300, DialectVersion.SMB302, DialectVersion.SMB311);

        assertEquals(5, smb2Versions.size());
        assertTrue(smb2Versions.contains(DialectVersion.SMB311));
        assertFalse(smb2Versions.contains(DialectVersion.SMB1));
    }

    @Test
    @DisplayName("Should handle values() method")
    void testValuesMethod() {
        // When
        DialectVersion[] values = DialectVersion.values();

        // Then
        assertNotNull(values);
        assertEquals(6, values.length); // SMB1, SMB202, SMB210, SMB300, SMB302, SMB311
        assertEquals(DialectVersion.SMB1, values[0]);
        assertEquals(DialectVersion.SMB311, values[values.length - 1]);
    }

    @Test
    @DisplayName("Should handle valueOf() method")
    void testValueOfMethod() {
        // Test valueOf with valid names
        assertEquals(DialectVersion.SMB1, DialectVersion.valueOf("SMB1"));
        assertEquals(DialectVersion.SMB202, DialectVersion.valueOf("SMB202"));
        assertEquals(DialectVersion.SMB311, DialectVersion.valueOf("SMB311"));

        // Test valueOf with invalid name
        assertThrows(IllegalArgumentException.class, () -> {
            DialectVersion.valueOf("INVALID");
        });

        // Test valueOf with null
        assertThrows(NullPointerException.class, () -> {
            DialectVersion.valueOf(null);
        });
    }

    @Test
    @DisplayName("Should maintain SMB2 flag consistency")
    void testSMB2FlagConsistency() {
        // SMB1 should not be SMB2
        assertFalse(DialectVersion.SMB1.isSMB2());

        // All other versions should be SMB2
        for (DialectVersion version : DialectVersion.values()) {
            if (version != DialectVersion.SMB1) {
                assertTrue(version.isSMB2(), "Version " + version + " should be SMB2");
            }
        }
    }

    @Test
    @DisplayName("Should have distinct dialect codes")
    void testDistinctDialectCodes() {
        // Collect all dialect codes (excluding SMB1 which returns -1)
        java.util.Set<Integer> dialectCodes = new java.util.HashSet<>();

        for (DialectVersion version : DialectVersion.values()) {
            if (version.isSMB2()) {
                int dialect = version.getDialect();
                assertTrue(dialect > 0, "Dialect code should be positive for " + version);
                assertTrue(dialectCodes.add(dialect), "Dialect code should be unique for " + version);
            }
        }

        // Should have 5 unique dialect codes for SMB2+ versions
        assertEquals(5, dialectCodes.size());
    }
}