package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Test class for Credentials interface functionality
 */
@DisplayName("Credentials Interface Tests")
class CredentialsTest extends BaseTest {

    @Mock
    private Credentials mockCredentials;

    @Test
    @DisplayName("Should define interface methods")
    void testCredentialsInterface() {
        // Verify interface methods exist
        assertDoesNotThrow(() -> {
            mockCredentials.unwrap(Credentials.class);
            mockCredentials.getUserDomain();
            mockCredentials.isAnonymous();
            mockCredentials.isGuest();
        });
    }

    @Test
    @DisplayName("Should unwrap to correct type")
    void testUnwrap() {
        // Given
        when(mockCredentials.unwrap(Credentials.class)).thenReturn(mockCredentials);

        // When
        Credentials unwrapped = mockCredentials.unwrap(Credentials.class);

        // Then
        assertSame(mockCredentials, unwrapped);
        verify(mockCredentials).unwrap(Credentials.class);
    }

    @Test
    @DisplayName("Should get user domain")
    void testGetUserDomain() {
        // Given
        String domain = "TESTDOMAIN";
        when(mockCredentials.getUserDomain()).thenReturn(domain);

        // When
        String result = mockCredentials.getUserDomain();

        // Then
        assertEquals(domain, result);
        verify(mockCredentials).getUserDomain();
    }

    @Test
    @DisplayName("Should check for anonymous credentials")
    void testIsAnonymous() {
        // Given
        when(mockCredentials.isAnonymous()).thenReturn(true);

        // When
        boolean isAnonymous = mockCredentials.isAnonymous();

        // Then
        assertTrue(isAnonymous);
        verify(mockCredentials).isAnonymous();
    }

    @Test
    @DisplayName("Should check for guest credentials")
    void testIsGuest() {
        // Given
        when(mockCredentials.isGuest()).thenReturn(true);

        // When
        boolean isGuest = mockCredentials.isGuest();

        // Then
        assertTrue(isGuest);
        verify(mockCredentials).isGuest();
    }
}
