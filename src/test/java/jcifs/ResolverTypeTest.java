/*
 * © 2024 S. Shinsuke
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
