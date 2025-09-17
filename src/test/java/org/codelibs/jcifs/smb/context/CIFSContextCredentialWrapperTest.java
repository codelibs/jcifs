package org.codelibs.jcifs.smb.context;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.impl.CredentialsInternal;
import org.codelibs.jcifs.smb.impl.NtlmAuthenticator;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.impl.SmbAuthException;
import org.codelibs.jcifs.smb.impl.SmbRenewableCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

class CIFSContextCredentialWrapperTest {

    @Mock
    private AbstractCIFSContext mockDelegate;
    @Mock
    private Credentials mockCredentials;
    @Mock
    private SmbRenewableCredentials mockRenewableCredentials;
    @Mock
    private CredentialsInternal mockRenewedCredentialsInternal;
    @Mock
    private NtlmAuthenticator mockNtlmAuthenticator;
    @Mock
    private NtlmPasswordAuthenticator mockNtlmPasswordAuthenticator;

    private CIFSContextCredentialWrapper wrapper;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        wrapper = new CIFSContextCredentialWrapper(mockDelegate, mockCredentials);
    }

    @Test
    @DisplayName("Should construct with delegate and credentials")
    void testConstructor() {
        // Verify that the constructor correctly sets the delegate (inherited from CIFSContextWrapper)
        // and the credentials. The delegate is tested implicitly by calling super's methods.
        // We can directly test getCredentials() to ensure it returns the initial credentials.
        assertEquals(mockCredentials, wrapper.getCredentials(), "Initial credentials should be set by constructor");
    }

    @Test
    @DisplayName("Should return the credentials provided in the constructor")
    void testGetCredentials() {
        assertEquals(mockCredentials, wrapper.getCredentials(), "getCredentials should return the initially set credentials");
    }

    @Test
    @DisplayName("Should renew credentials when they are renewable and renew() returns new credentials")
    void testRenewCredentials_RenewableAndRenewed() {
        // Set up the wrapper with renewable credentials
        wrapper = new CIFSContextCredentialWrapper(mockDelegate, mockRenewableCredentials);
        when(mockRenewableCredentials.renew()).thenReturn(mockRenewedCredentialsInternal);

        // Perform the renewal
        boolean renewed = wrapper.renewCredentials("locationHint", null);

        // Verify that renew() was called and credentials were updated
        assertTrue(renewed, "renewCredentials should return true when renewable credentials are renewed");
        assertEquals(mockRenewedCredentialsInternal, wrapper.getCredentials(), "Credentials should be updated to renewed credentials");
        verify(mockRenewableCredentials).renew();
    }

    @Test
    @DisplayName("Should not renew credentials when they are renewable but renew() returns null")
    void testRenewCredentials_RenewableButNotRenewed() {
        // Set up the wrapper with renewable credentials
        wrapper = new CIFSContextCredentialWrapper(mockDelegate, mockRenewableCredentials);
        when(mockRenewableCredentials.renew()).thenReturn(null);

        // Perform the renewal
        boolean renewed = wrapper.renewCredentials("locationHint", null);

        // Verify that renew() was called but credentials were not updated
        assertFalse(renewed, "renewCredentials should return false when renewable credentials are not renewed");
        assertEquals(mockRenewableCredentials, wrapper.getCredentials(), "Credentials should remain unchanged if renew() returns null");
        verify(mockRenewableCredentials).renew();
    }

    @Test
    @DisplayName("Should renew credentials via NtlmAuthenticator when not renewable and NtlmAuthenticator provides new credentials")
    void testRenewCredentials_NtlmAuthenticatorProvidesNew() {
        try (MockedStatic<NtlmAuthenticator> mockedNtlmAuthenticator = mockStatic(NtlmAuthenticator.class)) {
            mockedNtlmAuthenticator.when(NtlmAuthenticator::getDefault).thenReturn(mockNtlmAuthenticator);
            mockedNtlmAuthenticator.when(() -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator),
                    eq("locationHint"), eq((SmbAuthException) null))).thenReturn(mockNtlmPasswordAuthenticator);

            // Perform the renewal
            boolean renewed = wrapper.renewCredentials("locationHint", null);

            // Verify that NtlmAuthenticator was used and credentials were updated
            assertTrue(renewed, "renewCredentials should return true when NtlmAuthenticator provides new credentials");
            assertEquals(mockNtlmPasswordAuthenticator, wrapper.getCredentials(), "Credentials should be updated by NtlmAuthenticator");
            mockedNtlmAuthenticator.verify(NtlmAuthenticator::getDefault);
            mockedNtlmAuthenticator.verify(
                    () -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator), eq("locationHint"), eq(null)));
            verify(mockRenewableCredentials, never()).renew(); // Ensure renewable path was not taken
        }
    }

    @Test
    @DisplayName("Should not renew credentials via NtlmAuthenticator when not renewable and NtlmAuthenticator returns null")
    void testRenewCredentials_NtlmAuthenticatorReturnsNull() {
        try (MockedStatic<NtlmAuthenticator> mockedNtlmAuthenticator = mockStatic(NtlmAuthenticator.class)) {
            mockedNtlmAuthenticator.when(NtlmAuthenticator::getDefault).thenReturn(mockNtlmAuthenticator);
            mockedNtlmAuthenticator.when(
                    () -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator), eq("locationHint"), eq(null)))
                    .thenReturn(null);

            // Perform the renewal
            boolean renewed = wrapper.renewCredentials("locationHint", null);

            // Verify that NtlmAuthenticator was used but credentials were not updated
            assertFalse(renewed, "renewCredentials should return false when NtlmAuthenticator returns null");
            assertEquals(mockCredentials, wrapper.getCredentials(),
                    "Credentials should remain unchanged if NtlmAuthenticator returns null");
            mockedNtlmAuthenticator.verify(NtlmAuthenticator::getDefault);
            mockedNtlmAuthenticator.verify(
                    () -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator), eq("locationHint"), eq(null)));
            verify(mockRenewableCredentials, never()).renew(); // Ensure renewable path was not taken
        }
    }

    @Test
    @DisplayName("Should not renew credentials when NtlmAuthenticator.getDefault() returns null")
    void testRenewCredentials_NtlmAuthenticatorDefaultIsNull() {
        try (MockedStatic<NtlmAuthenticator> mockedNtlmAuthenticator = mockStatic(NtlmAuthenticator.class)) {
            mockedNtlmAuthenticator.when(NtlmAuthenticator::getDefault).thenReturn(null);

            // Perform the renewal
            boolean renewed = wrapper.renewCredentials("locationHint", null);

            // Verify that no renewal happened
            assertFalse(renewed, "renewCredentials should return false when NtlmAuthenticator.getDefault() is null");
            assertEquals(mockCredentials, wrapper.getCredentials(),
                    "Credentials should remain unchanged if NtlmAuthenticator.getDefault() is null");
            mockedNtlmAuthenticator.verify(NtlmAuthenticator::getDefault);
            mockedNtlmAuthenticator.verify(() -> NtlmAuthenticator.requestNtlmPasswordAuthentication(any(), any(), any()), never());
            verify(mockRenewableCredentials, never()).renew(); // Ensure renewable path was not taken
        }
    }

    @Test
    @DisplayName("Should pass SmbAuthException to NtlmAuthenticator.requestNtlmPasswordAuthentication")
    void testRenewCredentials_WithSmbAuthException() {
        SmbAuthException mockSmbAuthException = mock(SmbAuthException.class);
        try (MockedStatic<NtlmAuthenticator> mockedNtlmAuthenticator = mockStatic(NtlmAuthenticator.class)) {
            mockedNtlmAuthenticator.when(NtlmAuthenticator::getDefault).thenReturn(mockNtlmAuthenticator);
            mockedNtlmAuthenticator.when(() -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator),
                    eq("locationHint"), eq(mockSmbAuthException))).thenReturn(mockNtlmPasswordAuthenticator);

            // Perform the renewal
            boolean renewed = wrapper.renewCredentials("locationHint", mockSmbAuthException);

            // Verify that SmbAuthException was passed
            assertTrue(renewed);
            mockedNtlmAuthenticator.verify(() -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator),
                    eq("locationHint"), eq(mockSmbAuthException)));
        }
    }

    @Test
    @DisplayName("Should pass null for SmbAuthException when error is not SmbAuthException")
    void testRenewCredentials_WithErrorNotSmbAuthException() {
        Throwable genericError = new RuntimeException("Generic Error");
        try (MockedStatic<NtlmAuthenticator> mockedNtlmAuthenticator = mockStatic(NtlmAuthenticator.class)) {
            mockedNtlmAuthenticator.when(NtlmAuthenticator::getDefault).thenReturn(mockNtlmAuthenticator);
            mockedNtlmAuthenticator.when(() -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator),
                    eq("locationHint"), eq((SmbAuthException) null))).thenReturn(mockNtlmPasswordAuthenticator);

            // Perform the renewal
            boolean renewed = wrapper.renewCredentials("locationHint", genericError);

            // Verify that null was passed for SmbAuthException
            assertTrue(renewed);
            mockedNtlmAuthenticator.verify(
                    () -> NtlmAuthenticator.requestNtlmPasswordAuthentication(eq(mockNtlmAuthenticator), eq("locationHint"), eq(null)));
        }
    }

    @Test
    @DisplayName("Should return false if neither renewable nor NTLM authentication succeeds")
    void testRenewCredentials_NoRenewalPossible() {
        // Ensure credentials are not renewable
        wrapper = new CIFSContextCredentialWrapper(mockDelegate, mockCredentials); // Use non-renewable mockCredentials

        try (MockedStatic<NtlmAuthenticator> mockedNtlmAuthenticator = mockStatic(NtlmAuthenticator.class)) {
            mockedNtlmAuthenticator.when(NtlmAuthenticator::getDefault).thenReturn(mockNtlmAuthenticator);
            mockedNtlmAuthenticator.when(() -> NtlmAuthenticator.requestNtlmPasswordAuthentication(any(), any(), any())).thenReturn(null);

            // Perform the renewal
            boolean renewed = wrapper.renewCredentials("locationHint", null);

            // Verify that no renewal happened
            assertFalse(renewed, "renewCredentials should return false if no renewal mechanism succeeds");
            assertEquals(mockCredentials, wrapper.getCredentials(), "Credentials should remain unchanged if no renewal mechanism succeeds");
            // Note: Credentials interface does not have renew() method
        }
    }
}
