/*
 * © 2025 CodeLibs, Inc.
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
package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for NtlmPasswordAuthenticator security enhancements
 */
public class NtlmPasswordAuthenticatorSecurityTest {

    private NtlmPasswordAuthenticator authenticator;

    @BeforeEach
    public void setUp() {
        authenticator = null;
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (authenticator != null) {
            authenticator.close();
        }
    }

    @Test
    @DisplayName("Test password stored as char array")
    void testPasswordStoredAsCharArray() throws Exception {
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", "password123");

        // Use reflection to verify password is stored as char[]
        Field passwordField = NtlmPasswordAuthenticator.class.getDeclaredField("password");
        passwordField.setAccessible(true);
        Object passwordValue = passwordField.get(authenticator);

        assertTrue(passwordValue instanceof char[], "Password should be stored as char[]");
        assertArrayEquals("password123".toCharArray(), (char[]) passwordValue, "Password content should match");
    }

    @Test
    @DisplayName("Test secure password wipe")
    void testSecureWipePassword() throws Exception {
        String testPassword = "testPassword123";
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", testPassword);

        // Get the password field using reflection
        Field passwordField = NtlmPasswordAuthenticator.class.getDeclaredField("password");
        passwordField.setAccessible(true);

        // Verify password exists before wipe
        char[] passwordBefore = (char[]) passwordField.get(authenticator);
        assertNotNull(passwordBefore, "Password should exist before wipe");
        assertArrayEquals(testPassword.toCharArray(), passwordBefore, "Password should match before wipe");

        // Wipe the password
        authenticator.secureWipePassword();

        // Verify password is cleared after wipe
        char[] passwordAfter = (char[]) passwordField.get(authenticator);
        assertNull(passwordAfter, "Password should be null after wipe");
    }

    @Test
    @DisplayName("Test session ID generation")
    void testSessionIdGeneration() throws Exception {
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", "password");

        // Get the sessionId field using reflection
        Field sessionIdField = NtlmPasswordAuthenticator.class.getDeclaredField("sessionId");
        sessionIdField.setAccessible(true);

        // Initially sessionId should be null
        String initialSessionId = (String) sessionIdField.get(authenticator);
        assertNull(initialSessionId, "SessionId should initially be null");
    }

    @Test
    @DisplayName("Test get password as char array")
    void testGetPasswordAsCharArray() {
        String testPassword = "securePassword456";
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", testPassword);

        char[] password = authenticator.getPasswordAsCharArray();
        assertNotNull(password, "Password char array should not be null");
        assertArrayEquals(testPassword.toCharArray(), password, "Password should match");

        // Verify it returns a clone, not the original
        password[0] = 'X';
        char[] password2 = authenticator.getPasswordAsCharArray();
        assertNotEquals(password[0], password2[0], "Should return a clone, not the original");
    }

    @Test
    public void testPasswordConstructorWithCharArray() {
        char[] passwordChars = "charArrayPassword".toCharArray();
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", passwordChars);

        String retrievedPassword = authenticator.getPassword();
        assertEquals("charArrayPassword", retrievedPassword, "Password should match");

        // Modify original array - should not affect stored password
        passwordChars[0] = 'X';
        String retrievedPassword2 = authenticator.getPassword();
        assertEquals("charArrayPassword", retrievedPassword2, "Stored password should not be affected by external changes");
    }

    @Test
    public void testNullPasswordHandling() {
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", (String) null);

        assertNull(authenticator.getPassword(), "getPassword should return null for null password");
        assertNull(authenticator.getPasswordAsCharArray(), "getPasswordAsCharArray should return null for null password");

        // secureWipePassword should not throw exception
        authenticator.secureWipePassword();
    }

    @Test
    public void testEmptyPasswordHandling() {
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", "");

        assertEquals("", authenticator.getPassword(), "getPassword should return empty string");
        assertArrayEquals(new char[0], authenticator.getPasswordAsCharArray(), "getPasswordAsCharArray should return empty array");
    }

    @Test
    public void testCloneDoesNotSharePassword() throws Exception {
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", "originalPassword");
        NtlmPasswordAuthenticator cloned = authenticator.clone();

        // Get password fields using reflection
        Field passwordField = NtlmPasswordAuthenticator.class.getDeclaredField("password");
        passwordField.setAccessible(true);

        char[] originalPassword = (char[]) passwordField.get(authenticator);
        char[] clonedPassword = (char[]) passwordField.get(cloned);

        assertNotSame(originalPassword, clonedPassword, "Cloned password should be a different array instance");
        assertArrayEquals(originalPassword, clonedPassword, "Cloned password content should match");

        // Wipe original - should not affect clone
        authenticator.secureWipePassword();

        char[] originalAfterWipe = (char[]) passwordField.get(authenticator);
        char[] clonedAfterWipe = (char[]) passwordField.get(cloned);

        assertNull(originalAfterWipe, "Original password should be null after wipe");
        assertNotNull(clonedAfterWipe, "Cloned password should still exist");
        assertArrayEquals("originalPassword".toCharArray(), clonedAfterWipe, "Cloned password should still have original value");
    }

    @Test
    public void testEqualsWithPassword() {
        NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass123");
        NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass123");
        NtlmPasswordAuthenticator auth3 = new NtlmPasswordAuthenticator("DOMAIN", "user", "differentPass");

        assertEquals(auth1, auth2, "Authenticators with same credentials should be equal");
        assertNotEquals(auth1, auth3, "Authenticators with different passwords should not be equal");
    }

    @Test
    public void testMultipleSecureWipes() {
        authenticator = new NtlmPasswordAuthenticator("DOMAIN", "username", "password");

        // Multiple wipes should not cause errors
        authenticator.secureWipePassword();
        authenticator.secureWipePassword();
        authenticator.secureWipePassword();

        assertNull(authenticator.getPassword(), "Password should remain null after multiple wipes");
    }
}
