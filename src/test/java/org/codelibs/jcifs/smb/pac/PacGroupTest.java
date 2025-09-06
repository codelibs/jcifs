package org.codelibs.jcifs.smb.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import org.codelibs.jcifs.smb.SIDObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link PacGroup} class.
 */
class PacGroupTest {

    private SIDObject mockSid;
    private PacGroup pacGroup;
    private final int attributes = 42;

    @BeforeEach
    void setUp() {
        // Mock the SIDObject object
        mockSid = mock(SIDObject.class);
        pacGroup = new PacGroup(mockSid, attributes);
    }

    /**
     * Test method for {@link org.codelibs.jcifs.smb.pac.PacGroup#PacGroup(org.codelibs.jcifs.smb.SIDObject, int)}.
     */
    @Test
    void testConstructor() {
        // Verify that the constructor correctly sets the id and attributes
        assertEquals(mockSid, pacGroup.getId(), "The SIDObject should be correctly set in the constructor.");
        assertEquals(attributes, pacGroup.getAttributes(), "The attributes should be correctly set in the constructor.");
    }

    /**
     * Test method for {@link org.codelibs.jcifs.smb.pac.PacGroup#getId()}.
     */
    @Test
    void testGetId() {
        // Test the getId method
        assertEquals(mockSid, pacGroup.getId(), "getId() should return the correct SIDObject.");
    }

    /**
     * Test method for {@link org.codelibs.jcifs.smb.pac.PacGroup#getAttributes()}.
     */
    @Test
    void testGetAttributes() {
        // Test the getAttributes method
        assertEquals(attributes, pacGroup.getAttributes(), "getAttributes() should return the correct attributes.");
    }
}
