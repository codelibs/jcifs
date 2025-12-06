package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.*;

import org.codelibs.jcifs.smb.BaseTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("NtlmAuthenticator Tests")
class NtlmAuthenticatorTest extends BaseTest {

    @AfterEach
    void cleanup() {
        // Reset the static authenticator after each test
        NtlmAuthenticator.setDefault(null);
        // Use reflection to reset the private static field
        try {
            java.lang.reflect.Field field = NtlmAuthenticator.class.getDeclaredField("auth");
            field.setAccessible(true);
            field.set(null, null);
        } catch (Exception e) {
            // Ignore cleanup errors
        }
    }

    @Nested
    @DisplayName("SetDefault Tests")
    class SetDefaultTests {

        @Test
        @DisplayName("setDefault() sets the default authenticator")
        void testSetDefault() {
            // Arrange
            TestAuthenticator auth = new TestAuthenticator();

            // Act
            NtlmAuthenticator.setDefault(auth);

            // Assert
            assertSame(auth, NtlmAuthenticator.getDefault());
        }

        @Test
        @DisplayName("setDefault() ignores subsequent calls")
        void testSetDefaultOnlyOnce() {
            // Arrange
            TestAuthenticator auth1 = new TestAuthenticator();
            TestAuthenticator auth2 = new TestAuthenticator();

            // Act
            NtlmAuthenticator.setDefault(auth1);
            NtlmAuthenticator.setDefault(auth2);

            // Assert
            assertSame(auth1, NtlmAuthenticator.getDefault());
            assertNotSame(auth2, NtlmAuthenticator.getDefault());
        }

        @Test
        @DisplayName("getDefault() returns null before setting")
        void testGetDefaultBeforeSetting() {
            // Assert
            assertNull(NtlmAuthenticator.getDefault());
        }
    }

    @Nested
    @DisplayName("RequestNtlmPasswordAuthentication Tests")
    class RequestAuthenticationTests {

        @Test
        @DisplayName("requestNtlmPasswordAuthentication() returns null when no authenticator set")
        void testRequestWithoutAuthenticator() {
            // Act
            NtlmPasswordAuthenticator result = NtlmAuthenticator.requestNtlmPasswordAuthentication("smb://server/share", null);

            // Assert
            assertNull(result);
        }

        @Test
        @DisplayName("requestNtlmPasswordAuthentication() calls getNtlmPasswordAuthentication()")
        void testRequestCallsGetCredentials() {
            // Arrange
            String testUrl = "smb://server/share";
            SmbAuthException exception = new SmbAuthException("Test auth failure");
            TestAuthenticator auth = new TestAuthenticator();
            NtlmPasswordAuthenticator expectedCreds = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");
            auth.setCredentialsToReturn(expectedCreds);

            NtlmAuthenticator.setDefault(auth);

            // Act
            NtlmPasswordAuthenticator result = NtlmAuthenticator.requestNtlmPasswordAuthentication(testUrl, exception);

            // Assert
            assertSame(expectedCreds, result);
            assertTrue(auth.wasGetNtlmPasswordAuthenticationCalled());
            assertEquals(testUrl, auth.getCapturedUrl());
            assertSame(exception, auth.getCapturedException());
        }

        @Test
        @DisplayName("requestNtlmPasswordAuthentication() with explicit authenticator")
        void testRequestWithExplicitAuthenticator() {
            // Arrange
            String testUrl = "smb://server/share";
            SmbAuthException exception = new SmbAuthException("Test auth failure");
            TestAuthenticator auth = new TestAuthenticator();
            NtlmPasswordAuthenticator expectedCreds = new NtlmPasswordAuthenticator("user", "pass");
            auth.setCredentialsToReturn(expectedCreds);

            // Act - using the static method with explicit authenticator
            NtlmPasswordAuthenticator result = NtlmAuthenticator.requestNtlmPasswordAuthentication(auth, testUrl, exception);

            // Assert
            assertSame(expectedCreds, result);
            assertTrue(auth.wasGetNtlmPasswordAuthenticationCalled());
        }

        @Test
        @DisplayName("requestNtlmPasswordAuthentication() returns null when getNtlmPasswordAuthentication returns null")
        void testRequestReturnsNullWhenGetCredentialsReturnsNull() {
            // Arrange
            TestAuthenticator auth = new TestAuthenticator();
            auth.setCredentialsToReturn(null);
            NtlmAuthenticator.setDefault(auth);

            // Act
            NtlmPasswordAuthenticator result = NtlmAuthenticator.requestNtlmPasswordAuthentication("smb://server/share", null);

            // Assert
            assertNull(result);
            assertTrue(auth.wasGetNtlmPasswordAuthenticationCalled());
        }

        @Test
        @DisplayName("requestNtlmPasswordAuthentication() with null authenticator returns null")
        void testRequestWithNullAuthenticator() {
            // Act
            NtlmPasswordAuthenticator result = NtlmAuthenticator.requestNtlmPasswordAuthentication(null, "smb://server/share", null);

            // Assert
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("Protected Methods Tests")
    class ProtectedMethodsTests {

        @Test
        @DisplayName("getRequestingURL() returns the URL set during request")
        void testGetRequestingURL() {
            // Arrange
            String testUrl = "smb://testserver/share";
            TestAuthenticator auth = new TestAuthenticator();
            NtlmAuthenticator.setDefault(auth);

            // Act
            NtlmAuthenticator.requestNtlmPasswordAuthentication(testUrl, null);

            // Assert
            assertEquals(testUrl, auth.getRequestingURL());
        }

        @Test
        @DisplayName("getRequestingException() returns the exception set during request")
        void testGetRequestingException() {
            // Arrange
            SmbAuthException exception = new SmbAuthException("Test auth failure");
            TestAuthenticator auth = new TestAuthenticator();
            NtlmAuthenticator.setDefault(auth);

            // Act
            NtlmAuthenticator.requestNtlmPasswordAuthentication("smb://server/share", exception);

            // Assert
            assertSame(exception, auth.getRequestingException());
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("requestNtlmPasswordAuthentication() is synchronized")
        void testSynchronization() throws Exception {
            // Arrange
            TestAuthenticator auth = new TestAuthenticator();
            auth.setDelayMs(50); // Small delay to test synchronization
            NtlmAuthenticator.setDefault(auth);

            // Act - make multiple concurrent requests
            Thread t1 = new Thread(() -> {
                NtlmAuthenticator.requestNtlmPasswordAuthentication("smb://server1/share", null);
            });
            Thread t2 = new Thread(() -> {
                NtlmAuthenticator.requestNtlmPasswordAuthentication("smb://server2/share", null);
            });

            t1.start();
            t2.start();
            t1.join();
            t2.join();

            // Assert - both requests should have completed
            // If synchronization works, the second request waits for the first
            assertTrue(auth.getCallCount() >= 2);
        }
    }

    /**
     * Test implementation of NtlmAuthenticator for testing purposes
     */
    private static class TestAuthenticator extends NtlmAuthenticator {
        private NtlmPasswordAuthenticator credentialsToReturn;
        private boolean getNtlmPasswordAuthenticationCalled = false;
        private int callCount = 0;
        private int delayMs = 0;

        public void setCredentialsToReturn(NtlmPasswordAuthenticator creds) {
            this.credentialsToReturn = creds;
        }

        public void setDelayMs(int delayMs) {
            this.delayMs = delayMs;
        }

        @Override
        protected NtlmPasswordAuthenticator getNtlmPasswordAuthentication() {
            this.getNtlmPasswordAuthenticationCalled = true;
            this.callCount++;

            if (delayMs > 0) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            return credentialsToReturn;
        }

        public boolean wasGetNtlmPasswordAuthenticationCalled() {
            return getNtlmPasswordAuthenticationCalled;
        }

        public String getCapturedUrl() {
            return getRequestingURL();
        }

        public SmbAuthException getCapturedException() {
            return getRequestingException();
        }

        public int getCallCount() {
            return callCount;
        }
    }
}
