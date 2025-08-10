/*
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
package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.smb.SID;

/**
 * Tests for the {@link PacGroup} class.
 */
class PacGroupTest {

    private SID mockSid;
    private PacGroup pacGroup;
    private final int attributes = 42;

    @BeforeEach
    void setUp() {
        // Mock the SID object
        mockSid = mock(SID.class);
        pacGroup = new PacGroup(mockSid, attributes);
    }

    /**
     * Test method for {@link jcifs.pac.PacGroup#PacGroup(jcifs.smb.SID, int)}.
     */
    @Test
    void testConstructor() {
        // Verify that the constructor correctly sets the id and attributes
        assertEquals(mockSid, pacGroup.getId(), "The SID should be correctly set in the constructor.");
        assertEquals(attributes, pacGroup.getAttributes(), "The attributes should be correctly set in the constructor.");
    }

    /**
     * Test method for {@link jcifs.pac.PacGroup#getId()}.
     */
    @Test
    void testGetId() {
        // Test the getId method
        assertEquals(mockSid, pacGroup.getId(), "getId() should return the correct SID.");
    }

    /**
     * Test method for {@link jcifs.pac.PacGroup#getAttributes()}.
     */
    @Test
    void testGetAttributes() {
        // Test the getAttributes method
        assertEquals(attributes, pacGroup.getAttributes(), "getAttributes() should return the correct attributes.");
    }
}
