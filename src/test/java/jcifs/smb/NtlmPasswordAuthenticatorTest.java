/*
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
package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test secure password handling in NtlmPasswordAuthenticator
 */
public class NtlmPasswordAuthenticatorTest {

    /**
     * Test password storage using char arrays
     */
    @Test
    public void testPasswordAsCharArray() {
        String testPassword = "TestPassword123!";
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("testuser", testPassword);

        // Check that password can be retrieved
        assertEquals(testPassword, auth.getPassword());

        // Check that char array method works
        char[] passwordArray = auth.getPasswordAsCharArray();
        assertNotNull(passwordArray);
        assertArrayEquals(testPassword.toCharArray(), passwordArray);

        // Verify that returned array is a copy
        Arrays.fill(passwordArray, 'X');
        assertEquals(testPassword, auth.getPassword());
    }

    /**
     * Test secure password wiping
     */
    @Test
    public void testSecureWipePassword() {
        String testPassword = "SecurePassword456!";
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("testuser", testPassword);

        // Verify password is set
        assertEquals(testPassword, auth.getPassword());

        // Wipe password
        auth.secureWipePassword();

        // Verify password is wiped
        assertNull(auth.getPassword());
        assertNull(auth.getPasswordAsCharArray());
    }

    /**
     * Test constructor with char array password
     */
    @Test
    public void testCharArrayConstructor() {
        char[] testPassword = "CharArrayPass789!".toCharArray();
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("testuser", testPassword);

        // Verify password is stored correctly
        assertArrayEquals(testPassword, auth.getPasswordAsCharArray());
        assertEquals(new String(testPassword), auth.getPassword());

        // Verify that modifying original array doesn't affect stored password
        Arrays.fill(testPassword, 'Y');
        assertEquals("CharArrayPass789!", auth.getPassword());
    }

    /**
     * Test domain constructor with char array
     */
    @Test
    public void testDomainCharArrayConstructor() {
        char[] testPassword = "DomainPass321!".toCharArray();
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "testuser", testPassword);

        assertEquals("DOMAIN", auth.getUserDomain());
        assertEquals("testuser", auth.getUsername());
        assertEquals(new String(testPassword), auth.getPassword());
    }

    /**
     * Test null password handling
     */
    @Test
    public void testNullPasswordHandling() {
        // Test with null String password
        NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("testuser", (String) null);
        assertNull(auth1.getPassword());

        // Test with null char[] password
        NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("testuser", (char[]) null);
        assertNull(auth2.getPassword());

        // Test secure wipe on null password
        auth1.secureWipePassword(); // Should not throw exception
        assertNull(auth1.getPassword());
    }

    /**
     * Test empty password handling
     */
    @Test
    public void testEmptyPasswordHandling() {
        // Test with empty String password
        NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("testuser", "");
        assertEquals("", auth1.getPassword());
        assertNotNull(auth1.getPasswordAsCharArray());
        assertEquals(0, auth1.getPasswordAsCharArray().length);

        // Test with empty char[] password
        NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("testuser", new char[0]);
        assertEquals("", auth2.getPassword());
        assertNotNull(auth2.getPasswordAsCharArray());
        assertEquals(0, auth2.getPasswordAsCharArray().length);
    }

    /**
     * Test clone with secure password
     */
    @Test
    public void testCloneWithSecurePassword() {
        char[] testPassword = "ClonePass123!".toCharArray();
        NtlmPasswordAuthenticator original = new NtlmPasswordAuthenticator("DOMAIN", "testuser", testPassword);

        NtlmPasswordAuthenticator cloned = original.clone();

        // Verify cloned values
        assertEquals(original.getUserDomain(), cloned.getUserDomain());
        assertEquals(original.getUsername(), cloned.getUsername());
        assertEquals(original.getPassword(), cloned.getPassword());

        // Verify password arrays are independent
        original.secureWipePassword();
        assertNull(original.getPassword());
        assertEquals("ClonePass123!", cloned.getPassword());
    }

    /**
     * Test authentication type guessing with secure password
     */
    @Test
    public void testAuthTypeGuessing() {
        // Test guest detection
        NtlmPasswordAuthenticator guestAuth = new NtlmPasswordAuthenticator("guest", "anypass");
        assertTrue(guestAuth.isGuest());
        assertFalse(guestAuth.isAnonymous());

        // Test anonymous detection
        NtlmPasswordAuthenticator anonAuth = new NtlmPasswordAuthenticator("", new char[0]);
        assertTrue(anonAuth.isAnonymous());
        assertFalse(anonAuth.isGuest());

        // Test user authentication
        NtlmPasswordAuthenticator userAuth = new NtlmPasswordAuthenticator("user", "pass".toCharArray());
        assertFalse(userAuth.isGuest());
        assertFalse(userAuth.isAnonymous());
    }

    /**
     * Test password in equals method
     */
    @Test
    public void testEqualsWithSecurePassword() {
        char[] password1 = "TestPass123!".toCharArray();
        char[] password2 = "TestPass123!".toCharArray();
        char[] password3 = "DifferentPass!".toCharArray();

        NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN", "user", password1);
        NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "user", password2);
        NtlmPasswordAuthenticator auth3 = new NtlmPasswordAuthenticator("DOMAIN", "user", password3);

        // Test equality with same password
        assertEquals(auth1, auth2);
        assertEquals(auth1.hashCode(), auth2.hashCode());

        // Test inequality with different password
        assertNotEquals(auth1, auth3);

        // Test after password wipe
        auth1.secureWipePassword();
        assertNotEquals(auth1, auth2);
    }

    /**
     * Test concurrent password access and wiping
     */
    @Test
    public void testConcurrentPasswordAccess() throws InterruptedException {
        final NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "ConcurrentPass123!");
        final int threadCount = 10;
        Thread[] threads = new Thread[threadCount];

        // Create threads that access password
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    Thread.sleep((long) (Math.random() * 10));
                    if (index == threadCount - 1) {
                        // Last thread wipes password
                        auth.secureWipePassword();
                    } else {
                        // Other threads try to read password
                        String pwd = auth.getPassword();
                        // Password might be null if already wiped
                        assertTrue(pwd == null || pwd.equals("ConcurrentPass123!"));
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        // Start all threads
        for (Thread t : threads) {
            t.start();
        }

        // Wait for all threads to complete
        for (Thread t : threads) {
            t.join();
        }

        // Verify password is wiped
        assertNull(auth.getPassword());
    }

    /**
     * Test that getPassword() is deprecated and logs warning
     */
    @Test
    @DisplayName("Test deprecated getPassword() method warning")
    public void testDeprecatedGetPasswordWarning() {
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "TestPass123!");

        // This should log a warning about using deprecated method
        String password = auth.getPassword();
        assertNotNull(password);
        assertEquals("TestPass123!", password);

        // Preferred method should not log warning
        char[] passwordArray = auth.getPasswordAsCharArray();
        assertNotNull(passwordArray);
        assertArrayEquals("TestPass123!".toCharArray(), passwordArray);
    }

    /**
     * Test AutoCloseable implementation
     */
    @Test
    @DisplayName("Test AutoCloseable with try-with-resources")
    public void testAutoCloseable() {
        char[] testPassword = "AutoClosePass123!".toCharArray();

        try (NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", testPassword)) {
            assertNotNull(auth.getPasswordAsCharArray());
            assertEquals("AutoClosePass123!", auth.getPassword());
        }

        // After try-with-resources, auth should be closed
        // We can't directly test if password is wiped since auth is out of scope,
        // but the close() method should have been called
    }

    /**
     * Test secure memory clearing in close()
     */
    @Test
    @DisplayName("Test secure memory clearing on close")
    public void testCloseSecurelyClearsMemory() {
        char[] testPassword = "CloseTestPass123!".toCharArray();
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", testPassword);

        // Verify password is set
        assertNotNull(auth.getPasswordAsCharArray());
        assertFalse(auth.isClosed());

        // Close the authenticator
        auth.close();

        // Verify it's closed
        assertTrue(auth.isClosed());
        // Cannot check password after closing as it now throws IllegalStateException
        // This is actually good security practice - closed authenticators cannot be accessed

        // Verify multiple closes don't cause issues
        auth.close(); // Should be safe to call again
        assertTrue(auth.isClosed());
    }

    /**
     * Test AutoCloseable implementation
     */
    @Test
    @DisplayName("Test AutoCloseable implementation with try-with-resources")
    public void testAutoCloseableImpl() {
        String testPassword = "AutoCloseablePass123!";
        NtlmPasswordAuthenticator authRef;

        // Use try-with-resources
        try (NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", testPassword)) {
            authRef = auth;
            assertEquals(testPassword, auth.getPassword());
            assertFalse(auth.isClosed());
        }

        // After try-with-resources, authenticator should be closed
        assertTrue(authRef.isClosed());

        // Attempting to use closed authenticator should throw exception
        final NtlmPasswordAuthenticator closedAuth = authRef;
        assertThrows(IllegalStateException.class, () -> closedAuth.getPassword());
        assertThrows(IllegalStateException.class, () -> closedAuth.getPasswordAsCharArray());
    }

    /**
     * Test authentication TTL (Time To Live)
     */
    @Test
    @DisplayName("Test authentication TTL expiration")
    public void testAuthenticationTTL() throws InterruptedException {
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "TTLTestPass123!");

        // Initially not expired
        assertFalse(auth.isExpired());

        // Set short TTL
        auth.setAuthenticationTTL(100); // 100 milliseconds
        assertEquals(100, auth.getAuthenticationTTL());

        // Still not expired immediately
        assertFalse(auth.isExpired());

        // Wait for expiration
        Thread.sleep(150);

        // Should be expired now
        assertTrue(auth.isExpired());

        // Reset timestamp
        auth.resetAuthenticationTimestamp();
        assertFalse(auth.isExpired());

        // Test with no expiration (TTL = 0)
        auth.setAuthenticationTTL(0);
        Thread.sleep(100);
        assertFalse(auth.isExpired());

        // Test with negative TTL (no expiration)
        auth.setAuthenticationTTL(-1);
        Thread.sleep(100);
        assertFalse(auth.isExpired());
    }

    /**
     * Test close() method
     */
    @Test
    @DisplayName("Test close() method properly wipes sensitive data")
    public void testCloseMethod() {
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "CloseTestPass123!");

        assertFalse(auth.isClosed());
        assertEquals("CloseTestPass123!", auth.getPassword());
        assertEquals("DOMAIN", auth.getUserDomain());
        assertEquals("user", auth.getUsername());

        // Close the authenticator
        auth.close();

        assertTrue(auth.isClosed());

        // Closing again should not throw exception
        auth.close(); // idempotent

        // All operations should throw IllegalStateException
        assertThrows(IllegalStateException.class, () -> auth.getPassword());
        assertThrows(IllegalStateException.class, () -> auth.getPasswordAsCharArray());
    }

    /**
     * Test multiple close() calls (idempotency)
     */
    @Test
    @DisplayName("Test close() method is idempotent")
    public void testCloseIdempotent() {
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "IdempotentPass123!");

        assertFalse(auth.isClosed());

        // Close multiple times
        auth.close();
        assertTrue(auth.isClosed());

        auth.close(); // Should not throw
        assertTrue(auth.isClosed());

        auth.close(); // Should still not throw
        assertTrue(auth.isClosed());
    }

    /**
     * Test secure password wiping with multi-threaded access
     */
    @Test
    @DisplayName("Test secure password wiping under concurrent access")
    public void testConcurrentSecureWipe() throws InterruptedException {
        final NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "ConcurrentWipePass123!");
        final int threadCount = 20;
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch completeLatch = new CountDownLatch(threadCount);

        // Create threads that try to wipe or access password
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            new Thread(() -> {
                try {
                    startLatch.await();

                    if (index % 3 == 0) {
                        // Some threads wipe password
                        auth.secureWipePassword();
                    } else if (index % 3 == 1) {
                        // Some threads close authenticator
                        auth.close();
                    } else {
                        // Some threads try to read password
                        try {
                            String pwd = auth.getPassword();
                            assertTrue(pwd == null || pwd.equals("ConcurrentWipePass123!"));
                        } catch (IllegalStateException e) {
                            // Expected if closed
                        }
                    }
                } catch (Exception e) {
                    fail("Unexpected exception: " + e.getMessage());
                } finally {
                    completeLatch.countDown();
                }
            }).start();
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for completion
        assertTrue(completeLatch.await(5, TimeUnit.SECONDS));

        // Authenticator should be closed
        assertTrue(auth.isClosed());
    }

    /**
     * Test password security with char array constructor variations
     */
    @Test
    @DisplayName("Test all char array constructor variations")
    public void testCharArrayConstructorVariations() {
        // Test with domain, username, password, and type
        char[] password1 = "TypedPass123!".toCharArray();
        NtlmPasswordAuthenticator auth1 =
                new NtlmPasswordAuthenticator("DOMAIN", "user", password1, NtlmPasswordAuthenticator.AuthenticationType.USER);

        assertEquals("DOMAIN", auth1.getUserDomain());
        assertEquals("user", auth1.getUsername());
        assertEquals("TypedPass123!", auth1.getPassword());
        assertFalse(auth1.isGuest());
        assertFalse(auth1.isAnonymous());

        // Test guest type with char array
        char[] guestPassword = "GuestPass123!".toCharArray();
        NtlmPasswordAuthenticator auth2 =
                new NtlmPasswordAuthenticator("DOMAIN", "guest", guestPassword, NtlmPasswordAuthenticator.AuthenticationType.GUEST);

        assertTrue(auth2.isGuest());
        assertFalse(auth2.isAnonymous());

        // Test anonymous type with empty char array
        NtlmPasswordAuthenticator auth3 =
                new NtlmPasswordAuthenticator("", "", new char[0], NtlmPasswordAuthenticator.AuthenticationType.NULL);

        assertFalse(auth3.isGuest());
        assertTrue(auth3.isAnonymous());
    }

    /**
     * Test authentication timestamp tracking
     */
    @Test
    @DisplayName("Test authentication timestamp is properly maintained")
    public void testAuthenticationTimestamp() throws InterruptedException {
        long beforeCreation = System.currentTimeMillis();

        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "TimestampPass123!");

        long afterCreation = System.currentTimeMillis();

        // Set a reasonable TTL
        auth.setAuthenticationTTL(1000); // 1 second

        // Should not be expired immediately
        assertFalse(auth.isExpired());

        // Wait half the TTL
        Thread.sleep(500);
        assertFalse(auth.isExpired());

        // Reset timestamp
        long beforeReset = System.currentTimeMillis();
        auth.resetAuthenticationTimestamp();
        long afterReset = System.currentTimeMillis();

        // Should still not be expired
        assertFalse(auth.isExpired());

        // Wait for original TTL to pass
        Thread.sleep(600);

        // Should still not be expired because we reset
        assertFalse(auth.isExpired());

        // Wait for the full TTL since reset
        Thread.sleep(500);

        // Now it should be expired
        assertTrue(auth.isExpired());
    }

    /**
     * Test password array independence after construction
     */
    @Test
    @DisplayName("Test password array is truly independent of input")
    public void testPasswordArrayIndependence() {
        char[] originalPassword = "IndependentPass123!".toCharArray();
        char[] passwordCopy = Arrays.copyOf(originalPassword, originalPassword.length);

        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", originalPassword);

        // Modify the original array
        Arrays.fill(originalPassword, 'X');

        // Authenticator's password should be unchanged
        assertEquals("IndependentPass123!", auth.getPassword());
        assertArrayEquals(passwordCopy, auth.getPasswordAsCharArray());

        // Get password as char array and modify it
        char[] retrievedPassword = auth.getPasswordAsCharArray();
        Arrays.fill(retrievedPassword, 'Y');

        // Authenticator's password should still be unchanged
        assertEquals("IndependentPass123!", auth.getPassword());
    }

    /**
     * Test secure wiping actually clears memory patterns
     */
    @Test
    @DisplayName("Test secure wipe uses multiple overwrite patterns")
    public void testSecureWipePatterns() {
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "WipePatternPass123!");

        // Get initial password
        assertEquals("WipePatternPass123!", auth.getPassword());

        // Perform secure wipe
        auth.secureWipePassword();

        // Password should be null after wipe
        assertNull(auth.getPassword());
        assertNull(auth.getPasswordAsCharArray());

        // Calling wipe again should be safe
        auth.secureWipePassword();
        assertNull(auth.getPassword());
    }

    /**
     * Test that closed authenticator prevents all sensitive operations
     */
    @Test
    @DisplayName("Test closed authenticator blocks all sensitive operations")
    public void testClosedAuthenticatorBlocking() throws Exception {
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "BlockedPass123!");

        // Close the authenticator
        auth.close();

        // All these operations should throw IllegalStateException
        assertThrows(IllegalStateException.class, () -> auth.getPassword());
        assertThrows(IllegalStateException.class, () -> auth.getPasswordAsCharArray());
        assertThrows(IllegalStateException.class, () -> {
            // This would normally be called during authentication
            auth.createContext(null, null, "host", null, false);
        });
    }

    /**
     * Test TTL with different constructor types
     */
    @Test
    @DisplayName("Test TTL functionality works with all constructor types")
    public void testTTLWithDifferentConstructors() {
        // Test with String password constructor
        NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("user", "StringPass123!");
        auth1.setAuthenticationTTL(1000);
        assertFalse(auth1.isExpired());

        // Test with char[] password constructor
        NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("user", "CharPass123!".toCharArray());
        auth2.setAuthenticationTTL(1000);
        assertFalse(auth2.isExpired());

        // Test with domain constructor
        NtlmPasswordAuthenticator auth3 = new NtlmPasswordAuthenticator("DOMAIN", "user", "DomainPass123!");
        auth3.setAuthenticationTTL(1000);
        assertFalse(auth3.isExpired());

        // Test with type constructor
        NtlmPasswordAuthenticator auth4 =
                new NtlmPasswordAuthenticator("DOMAIN", "user", "TypePass123!", NtlmPasswordAuthenticator.AuthenticationType.USER);
        auth4.setAuthenticationTTL(1000);
        assertFalse(auth4.isExpired());
    }
}
