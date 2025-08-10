/*
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.smb.SID;

class PacSidAttributesTest {

    private SID sidMock;
    private PacSidAttributes pacSidAttributes;
    private final int attributes = 12345;

    @BeforeEach
    void setUp() {
        // Mock the SID object
        sidMock = mock(SID.class);
        // Create a new PacSidAttributes instance before each test
        pacSidAttributes = new PacSidAttributes(sidMock, attributes);
    }

    /**
     * Test method for {@link jcifs.pac.PacSidAttributes#PacSidAttributes(jcifs.smb.SID, int)}.
     */
    @Test
    void testConstructor() {
        // Verify that the id and attributes are correctly set by the constructor
        assertEquals(sidMock, pacSidAttributes.getId(), "The SID should match the one provided in the constructor.");
        assertEquals(attributes, pacSidAttributes.getAttributes(), "The attributes should match the ones provided in the constructor.");
    }

    /**
     * Test method for {@link jcifs.pac.PacSidAttributes#getId()}.
     */
    @Test
    void testGetId() {
        // Test the getId method
        assertEquals(sidMock, pacSidAttributes.getId(), "getId should return the correct SID.");
    }

    /**
     * Test method for {@link jcifs.pac.PacSidAttributes#getAttributes()}.
     */
    @Test
    void testGetAttributes() {
        // Test the getAttributes method
        assertEquals(attributes, pacSidAttributes.getAttributes(), "getAttributes should return the correct attributes.");
    }
}
