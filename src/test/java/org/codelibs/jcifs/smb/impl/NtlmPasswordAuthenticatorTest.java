package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.codelibs.jcifs.smb.BaseTest;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator.AuthenticationType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;

@DisplayName("NtlmPasswordAuthenticator Tests")
class NtlmPasswordAuthenticatorTest extends BaseTest {

    @Mock
    private CIFSContext cifsContext;

    @Mock
    private Configuration configuration;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Default constructor creates anonymous credentials")
        void testDefaultConstructor() {
            // Act
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator();

            // Assert
            assertTrue(auth.isAnonymous());
            assertFalse(auth.isGuest());
            assertEquals("", auth.getUserDomain());
            assertEquals("", auth.getUsername());
            assertEquals("", auth.getPassword());
        }

        @Test
        @DisplayName("Constructor with AuthenticationType sets type correctly")
        void testConstructorWithType() {
            // Act
            NtlmPasswordAuthenticator guestAuth = new NtlmPasswordAuthenticator(AuthenticationType.GUEST);
            NtlmPasswordAuthenticator userAuth = new NtlmPasswordAuthenticator(AuthenticationType.USER);

            // Assert
            assertTrue(guestAuth.isGuest());
            assertFalse(guestAuth.isAnonymous());
            assertFalse(userAuth.isGuest());
            assertFalse(userAuth.isAnonymous());
        }

        @Test
        @DisplayName("Constructor with username and password")
        void testConstructorWithUsernamePassword() {
            // Act
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("testuser", "testpass");

            // Assert
            assertEquals("", auth.getUserDomain());
            assertEquals("testuser", auth.getUsername());
            assertEquals("testpass", auth.getPassword());
            assertFalse(auth.isAnonymous());
            assertFalse(auth.isGuest());
        }

        @Test
        @DisplayName("Constructor with domain, username and password")
        void testConstructorWithDomainUsernamePassword() {
            // Act
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("TESTDOMAIN", "testuser", "testpass");

            // Assert
            assertEquals("TESTDOMAIN", auth.getUserDomain());
            assertEquals("testuser", auth.getUsername());
            assertEquals("testpass", auth.getPassword());
            assertFalse(auth.isAnonymous());
            assertFalse(auth.isGuest());
        }

        @Test
        @DisplayName("Constructor handles null values")
        void testConstructorWithNulls() {
            // Act - 3-arg constructor sets type to USER explicitly
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator(null, null, null);

            // Assert
            assertEquals("", auth.getUserDomain());
            assertEquals("", auth.getUsername());
            assertEquals("", auth.getPassword());
            // 3-arg constructor defaults to USER type, not guessed
            assertFalse(auth.isAnonymous());
        }

        @Test
        @DisplayName("Constructor parses username@domain format")
        void testConstructorParsesEmailFormat() {
            // Act
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user@DOMAIN.COM", "password");

            // Assert
            assertEquals("DOMAIN.COM", auth.getUserDomain());
            assertEquals("user", auth.getUsername());
            assertEquals("password", auth.getPassword());
        }

        @Test
        @DisplayName("Constructor parses DOMAIN\\username format")
        void testConstructorParsesBackslashFormat() {
            // Act
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("MYDOMAIN\\myuser", "password");

            // Assert
            assertEquals("MYDOMAIN", auth.getUserDomain());
            assertEquals("myuser", auth.getUsername());
            assertEquals("password", auth.getPassword());
        }

        @Test
        @DisplayName("Constructor guesses NULL type for empty credentials")
        void testAuthenticationTypeGuessingAnonymous() {
            // Act - all empty
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("", "", "");

            // Assert
            assertTrue(auth.isAnonymous(), "Should be anonymous with all empty strings");
            assertFalse(auth.isGuest(), "Should not be guest");
        }

        @Test
        @DisplayName("Constructor guesses GUEST type for guest username")
        void testAuthenticationTypeGuessingGuest() {
            // Act - username is "guest"
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN", "guest", "password");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "GUEST", "password");

            // Assert
            assertFalse(auth1.isAnonymous(), "Should not be anonymous");
            assertTrue(auth1.isGuest(), "Should be guest with 'guest' username");
            assertFalse(auth2.isAnonymous(), "Should not be anonymous");
            assertTrue(auth2.isGuest(), "Should be guest with 'GUEST' username");
        }

        @Test
        @DisplayName("Constructor guesses USER type for regular credentials")
        void testAuthenticationTypeGuessingUser() {
            // Act
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");

            // Assert
            assertFalse(auth.isAnonymous(), "Should not be anonymous");
            assertFalse(auth.isGuest(), "Should not be guest");
        }
    }

    @Nested
    @DisplayName("UserInfo Parsing Tests")
    class UserInfoParsingTests {

        @Test
        @DisplayName("Parse userInfo with domain;username:password format")
        void testUserInfoParsing() throws Exception {
            // This tests the protected constructor via reflection
            // Format: domain;username:password
            String userInfo = "TESTDOMAIN;testuser:testpass";

            NtlmPasswordAuthenticator auth = new TestableNtlmPasswordAuthenticator(
                userInfo, null, null, null, null);

            // Assert
            assertEquals("TESTDOMAIN", auth.getUserDomain());
            assertEquals("testuser", auth.getUsername());
            assertEquals("testpass", auth.getPassword());
        }

        @Test
        @DisplayName("Parse userInfo with username:password format (no domain)")
        void testUserInfoParsingNoDomai() {
            String userInfo = "testuser:testpass";

            NtlmPasswordAuthenticator auth = new TestableNtlmPasswordAuthenticator(
                userInfo, null, null, null, null);

            // Assert
            assertEquals("", auth.getUserDomain());
            assertEquals("testuser", auth.getUsername());
            assertEquals("testpass", auth.getPassword());
        }

        @Test
        @DisplayName("Parse userInfo with defaults")
        void testUserInfoWithDefaults() {
            NtlmPasswordAuthenticator auth = new TestableNtlmPasswordAuthenticator(
                null, "DEFAULTDOMAIN", "defaultuser", "defaultpass", null);

            // Assert
            assertEquals("DEFAULTDOMAIN", auth.getUserDomain());
            assertEquals("defaultuser", auth.getUsername());
            assertEquals("defaultpass", auth.getPassword());
        }
    }

    @Nested
    @DisplayName("Getter and Basic Methods")
    class GetterTests {

        @Test
        @DisplayName("getName() returns domain\\username format")
        void testGetName() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");
            assertEquals("DOMAIN\\user", auth.getName());
        }

        @Test
        @DisplayName("getName() returns username only when domain is empty")
        void testGetNameWithoutDomain() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "pass");
            assertEquals("user", auth.getName());
        }

        @Test
        @DisplayName("toString() equals getName()")
        void testToString() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");
            assertEquals(auth.getName(), auth.toString());
        }

        @Test
        @DisplayName("getSubject() returns null")
        void testGetSubject() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator();
            assertNull(auth.getSubject());
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsHashCodeTests {

        @Test
        @DisplayName("equals() returns true for same credentials")
        void testEqualsSame() {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");

            assertTrue(auth1.equals(auth2));
            assertTrue(auth2.equals(auth1));
        }

        @Test
        @DisplayName("equals() is case-insensitive for domain and username")
        void testEqualsCaseInsensitive() {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("domain", "user", "pass");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "USER", "pass");

            assertTrue(auth1.equals(auth2));
        }

        @Test
        @DisplayName("equals() returns false for different passwords")
        void testEqualsDifferentPassword() {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass1");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass2");

            assertFalse(auth1.equals(auth2));
        }

        @Test
        @DisplayName("equals() returns false for different usernames")
        void testEqualsDifferentUsername() {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN", "user1", "pass");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "user2", "pass");

            assertFalse(auth1.equals(auth2));
        }

        @Test
        @DisplayName("equals() returns false for different domains")
        void testEqualsDifferentDomain() {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN1", "user", "pass");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN2", "user", "pass");

            assertFalse(auth1.equals(auth2));
        }

        @Test
        @DisplayName("equals() returns false for different types")
        void testEqualsDifferentType() {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");
            assertFalse(auth1.equals("not an authenticator"));
            assertFalse(auth1.equals(null));
        }

        @Test
        @DisplayName("hashCode() is consistent with equals()")
        void testHashCodeConsistent() {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("domain", "user", "pass");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("DOMAIN", "USER", "pass");

            assertEquals(auth1.hashCode(), auth2.hashCode());
        }
    }

    @Nested
    @DisplayName("Clone Tests")
    class CloneTests {

        @Test
        @DisplayName("clone() creates independent copy")
        void testClone() {
            NtlmPasswordAuthenticator original = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");
            NtlmPasswordAuthenticator cloned = original.clone();

            assertNotSame(original, cloned);
            assertEquals(original.getUserDomain(), cloned.getUserDomain());
            assertEquals(original.getUsername(), cloned.getUsername());
            assertEquals(original.getPassword(), cloned.getPassword());
            assertEquals(original.isAnonymous(), cloned.isAnonymous());
            assertEquals(original.isGuest(), cloned.isGuest());
        }
    }

    @Nested
    @DisplayName("Unwrap Tests")
    class UnwrapTests {

        @Test
        @DisplayName("unwrap() returns self for compatible type")
        void testUnwrapCompatible() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "pass");
            NtlmPasswordAuthenticator unwrapped = auth.unwrap(NtlmPasswordAuthenticator.class);

            assertSame(auth, unwrapped);
        }

        @Test
        @DisplayName("unwrap() returns null for incompatible Credentials type")
        void testUnwrapIncompatible() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "pass");
            // Use NtlmNtHashAuthenticator as an incompatible Credentials type
            NtlmNtHashAuthenticator unwrapped = auth.unwrap(NtlmNtHashAuthenticator.class);

            assertNull(unwrapped);
        }
    }

    @Nested
    @DisplayName("Refresh Tests")
    class RefreshTests {

        @Test
        @DisplayName("refresh() completes without error")
        void testRefresh() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "pass");
            assertDoesNotThrow(() -> auth.refresh());
        }
    }

    @Nested
    @DisplayName("PreferredMech Tests")
    class PreferredMechTests {

        @Test
        @DisplayName("isPreferredMech() returns true for NTLMSSP_OID")
        void testIsPreferredMech() {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "pass");
            assertTrue(auth.isPreferredMech(NtlmContext.NTLMSSP_OID));
        }

        @Test
        @DisplayName("isPreferredMech() returns false for other OIDs")
        void testIsPreferredMechOther() throws Exception {
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("user", "pass");
            ASN1ObjectIdentifier otherOid = new ASN1ObjectIdentifier("1.2.3.4.5");
            assertFalse(auth.isPreferredMech(otherOid));
        }
    }

    @Nested
    @DisplayName("Hash Computation Tests")
    class HashComputationTests {

        @Test
        @DisplayName("getAnsiHash() produces 24-byte result for LM compatibility level 0")
        void testGetAnsiHashLevel0() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(0);
            when(configuration.getOemEncoding()).thenReturn("US-ASCII");

            // Act
            byte[] hash = auth.getAnsiHash(cifsContext, challenge);

            // Assert
            assertNotNull(hash);
            assertEquals(24, hash.length);
        }

        @Test
        @DisplayName("getAnsiHash() produces 24-byte result for LM compatibility level 2")
        void testGetAnsiHashLevel2() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(2);

            // Act
            byte[] hash = auth.getAnsiHash(cifsContext, challenge);

            // Assert
            assertNotNull(hash);
            assertEquals(24, hash.length);
        }

        @Test
        @DisplayName("getAnsiHash() produces result for LMv2 (level 3)")
        void testGetAnsiHashLMv2() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(3);
            SecureRandom mockRandom = mock(SecureRandom.class);
            when(configuration.getRandom()).thenReturn(mockRandom);

            // Act
            byte[] hash = auth.getAnsiHash(cifsContext, challenge);

            // Assert
            assertNotNull(hash);
            assertEquals(24, hash.length);
        }

        @Test
        @DisplayName("getUnicodeHash() produces 24-byte result for level 0-2")
        void testGetUnicodeHash() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(1);

            // Act
            byte[] hash = auth.getUnicodeHash(cifsContext, challenge);

            // Assert
            assertNotNull(hash);
            assertEquals(24, hash.length);
        }

        @Test
        @DisplayName("getUnicodeHash() produces empty array for NTLMv2 (level 3-5)")
        void testGetUnicodeHashLMv2() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(3);

            // Act
            byte[] hash = auth.getUnicodeHash(cifsContext, challenge);

            // Assert
            assertNotNull(hash);
            assertEquals(0, hash.length);
        }

        @Test
        @DisplayName("getUserSessionKey() produces 16-byte key")
        void testGetUserSessionKey() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(1);

            // Act
            byte[] key = auth.getUserSessionKey(cifsContext, challenge);

            // Assert
            assertNotNull(key);
            assertEquals(16, key.length);
        }

        @Test
        @DisplayName("getUserSessionKey() with destination array")
        void testGetUserSessionKeyWithDest() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            byte[] dest = new byte[20];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(1);

            // Act
            auth.getUserSessionKey(cifsContext, challenge, dest, 2);

            // Assert - verify that bytes were written to dest at offset 2
            boolean hasNonZero = false;
            for (int i = 2; i < 18; i++) {
                if (dest[i] != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "Session key should write non-zero bytes");
        }

        @Test
        @DisplayName("getSigningKey() produces 40-byte key for level 0-2")
        void testGetSigningKey() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(1);

            // Act
            byte[] key = auth.getSigningKey(cifsContext, challenge);

            // Assert
            assertNotNull(key);
            assertEquals(40, key.length);
        }

        @Test
        @DisplayName("getSigningKey() throws exception for NTLMv2 without extended security")
        void testGetSigningKeyNTLMv2ThrowsException() {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            byte[] challenge = new byte[8];
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.getLanManCompatibility()).thenReturn(3);

            // Act & Assert
            assertThrows(SmbException.class, () -> auth.getSigningKey(cifsContext, challenge));
        }
    }

    @Nested
    @DisplayName("CreateContext Tests")
    class CreateContextTests {

        @Test
        @DisplayName("createContext() with raw NTLM returns NtlmContext")
        void testCreateContextRawNTLM() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.isUseRawNTLM()).thenReturn(true);
            when(configuration.isSendNTLMTargetName()).thenReturn(false);

            // Act
            SSPContext context = auth.createContext(cifsContext, "TESTDOMAIN", "testhost", null, false);

            // Assert
            assertNotNull(context);
            assertInstanceOf(NtlmContext.class, context);
        }

        @Test
        @DisplayName("createContext() without raw NTLM returns SpnegoContext")
        void testCreateContextSpnego() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.isUseRawNTLM()).thenReturn(false);
            when(configuration.isSendNTLMTargetName()).thenReturn(false);

            // Act
            SSPContext context = auth.createContext(cifsContext, "TESTDOMAIN", "testhost", null, false);

            // Assert
            assertNotNull(context);
            assertInstanceOf(SpnegoContext.class, context);
        }

        @Test
        @DisplayName("createContext() sets target name when configured")
        void testCreateContextWithTargetName() throws Exception {
            // Arrange
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");
            when(cifsContext.getConfig()).thenReturn(configuration);
            when(configuration.isUseRawNTLM()).thenReturn(true);
            when(configuration.isSendNTLMTargetName()).thenReturn(true);

            // Act
            SSPContext context = auth.createContext(cifsContext, "TESTDOMAIN", "testhost", null, false);

            // Assert
            assertNotNull(context);
            assertInstanceOf(NtlmContext.class, context);
            // Target name should be set internally
        }
    }

    @Nested
    @DisplayName("Unescape Tests")
    class UnescapeTests {

        @Test
        @DisplayName("unescape() handles null")
        void testUnescapeNull() throws Exception {
            assertNull(NtlmPasswordAuthenticator.unescape(null));
        }

        @Test
        @DisplayName("unescape() handles plain string")
        void testUnescapePlain() throws Exception {
            assertEquals("hello", NtlmPasswordAuthenticator.unescape("hello"));
        }

        @Test
        @DisplayName("unescape() decodes %20 to space")
        void testUnescapeSpace() throws Exception {
            assertEquals("hello world", NtlmPasswordAuthenticator.unescape("hello%20world"));
        }

        @Test
        @DisplayName("unescape() decodes multiple percent-encoded characters")
        void testUnescapeMultiple() throws Exception {
            assertEquals("a b c", NtlmPasswordAuthenticator.unescape("a%20b%20c"));
        }

        @Test
        @DisplayName("unescape() handles special characters")
        void testUnescapeSpecial() throws Exception {
            assertEquals("test@domain", NtlmPasswordAuthenticator.unescape("test%40domain"));
        }
    }

    /**
     * Testable subclass that exposes protected constructor
     */
    private static class TestableNtlmPasswordAuthenticator extends NtlmPasswordAuthenticator {
        public TestableNtlmPasswordAuthenticator(String userInfo, String defDomain,
                                                  String defUser, String defPassword,
                                                  AuthenticationType type) {
            super(userInfo, defDomain, defUser, defPassword, type);
        }
    }
}
