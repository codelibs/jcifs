package org.codelibs.jcifs.smb.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import org.codelibs.jcifs.smb.impl.SID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
     * Test method for {@link org.codelibs.jcifs.smb.pac.PacSidAttributes#PacSidAttributes(org.codelibs.jcifs.smb.impl.SID, int)}.
     */
    @Test
    void testConstructor() {
        // Verify that the id and attributes are correctly set by the constructor
        assertEquals(sidMock, pacSidAttributes.getId(), "The SID should match the one provided in the constructor.");
        assertEquals(attributes, pacSidAttributes.getAttributes(), "The attributes should match the ones provided in the constructor.");
    }

    /**
     * Test method for {@link org.codelibs.jcifs.smb.pac.PacSidAttributes#getId()}.
     */
    @Test
    void testGetId() {
        // Test the getId method
        assertEquals(sidMock, pacSidAttributes.getId(), "getId should return the correct SID.");
    }

    /**
     * Test method for {@link org.codelibs.jcifs.smb.pac.PacSidAttributes#getAttributes()}.
     */
    @Test
    void testGetAttributes() {
        // Test the getAttributes method
        assertEquals(attributes, pacSidAttributes.getAttributes(), "getAttributes should return the correct attributes.");
    }
}
