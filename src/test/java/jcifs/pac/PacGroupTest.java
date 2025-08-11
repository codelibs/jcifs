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
