package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link ResolverType} enum.
 * This class ensures that the enum constants are defined as expected.
 */
class ResolverTypeTest {

    /**
     * Tests that all expected enum constants exist.
     */
    @Test
    void testEnumConstants() {
        // Verify that each enum constant exists and can be referenced
        assertNotNull(ResolverType.RESOLVER_WINS, "RESOLVER_WINS should not be null.");
        assertNotNull(ResolverType.RESOLVER_BCAST, "RESOLVER_BCAST should not be null.");
        assertNotNull(ResolverType.RESOLVER_DNS, "RESOLVER_DNS should not be null.");
        assertNotNull(ResolverType.RESOLVER_LMHOSTS, "RESOLVER_LMHOSTS should not be null.");
    }

    /**
     * Tests the total number of enum constants.
     */
    @Test
    void testNumberOfEnumConstants() {
        // Ensure there are exactly 4 resolver types
        assertEquals(4, ResolverType.values().length, "There should be exactly 4 resolver types.");
    }

    /**
     * Tests the names of the enum constants.
     */
    @Test
    void testEnumNames() {
        // Verify the names of the enum constants to ensure they are not accidentally changed
        assertEquals("RESOLVER_WINS", ResolverType.RESOLVER_WINS.name());
        assertEquals("RESOLVER_BCAST", ResolverType.RESOLVER_BCAST.name());
        assertEquals("RESOLVER_DNS", ResolverType.RESOLVER_DNS.name());
        assertEquals("RESOLVER_LMHOSTS", ResolverType.RESOLVER_LMHOSTS.name());
    }

    /**
     * Tests the ordinal values of the enum constants.
     */
    @Test
    void testEnumOrdinals() {
        // Verify the ordinal values, which can be important if they are used in logic
        assertEquals(0, ResolverType.RESOLVER_WINS.ordinal());
        assertEquals(1, ResolverType.RESOLVER_BCAST.ordinal());
        assertEquals(2, ResolverType.RESOLVER_DNS.ordinal());
        assertEquals(3, ResolverType.RESOLVER_LMHOSTS.ordinal());
    }
}
