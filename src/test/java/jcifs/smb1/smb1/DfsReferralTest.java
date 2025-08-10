package jcifs.smb1.smb1;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the DfsReferral class.
 * This class tests the functionality of the DfsReferral class,
 * ensuring that objects are constructed correctly, appended properly,
 * and that the toString method returns the expected format.
 */
class DfsReferralTest {

    /**
     * Tests the default constructor of the DfsReferral class.
     * It verifies that a new DfsReferral object is initialized with its 'next'
     * property pointing to itself.
     */
    @Test
    void testDefaultConstructor() {
        // Given
        DfsReferral referral = new DfsReferral();

        // When / Then
        assertNotNull(referral, "The DfsReferral object should not be null.");
        assertEquals(referral, referral.next, "The 'next' property should point to the object itself.");
    }

    /**
     * Tests the append method of the DfsReferral class.
     * It verifies that a new DfsReferral object can be successfully appended to an existing one,
     * forming a linked list structure.
     */
    @Test
    void testAppend() {
        // Given
        DfsReferral initialReferral = new DfsReferral();
        DfsReferral appendedReferral = new DfsReferral();

        // When
        initialReferral.append(appendedReferral);

        // Then
        assertEquals(appendedReferral, initialReferral.next, "The 'next' property of the initial referral should point to the appended referral.");
        assertEquals(initialReferral, appendedReferral.next, "The 'next' property of the appended referral should point back to the initial referral, closing the loop.");
    }

    /**
     * Tests the toString method of the DfsReferral class.
     * It verifies that the toString method returns a string representation of the object
     * that accurately reflects its properties.
     */
    @Test
    void testToString() {
        // Given
        DfsReferral referral = new DfsReferral();
        referral.pathConsumed = 20;
        referral.server = "testServer";
        referral.share = "testShare";
        referral.link = "testLink";
        referral.path = "/test/path";
        referral.ttl = 300;
        referral.expiration = 1234567890L;
        referral.resolveHashes = true;

        // When
        String expectedString = "DfsReferral[pathConsumed=20,server=testServer,share=testShare,link=testLink,path=/test/path,ttl=300,expiration=1234567890,resolveHashes=true]";
        String actualString = referral.toString();

        // Then
        assertEquals(expectedString, actualString, "The toString method should return the expected string representation.");
    }
}
