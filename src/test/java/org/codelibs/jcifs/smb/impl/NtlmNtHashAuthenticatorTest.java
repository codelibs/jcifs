package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.*;

import org.codelibs.jcifs.smb.BaseTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("NtlmNtHashAuthenticator Tests")
class NtlmNtHashAuthenticatorTest extends BaseTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor with byte array accepts valid 16-byte hash")
        void testConstructorWithValidHash() {
            // Arrange
            byte[] hash = new byte[16];
            for (int i = 0; i < 16; i++) {
                hash[i] = (byte) i;
            }

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);

            // Assert
            assertNotNull(auth);
            assertEquals("DOMAIN", auth.getUserDomain());
            assertEquals("user", auth.getUsername());
            assertEquals("", auth.getPassword()); // Password is empty string when using hash, not null
        }

        @Test
        @DisplayName("Constructor with hex string creates authenticator")
        void testConstructorWithHexString() {
            // Arrange
            String hexHash = "0123456789ABCDEF0123456789ABCDEF"; // 32 hex chars = 16 bytes

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hexHash);

            // Assert
            assertNotNull(auth);
            assertEquals("DOMAIN", auth.getUserDomain());
            assertEquals("user", auth.getUsername());
            assertEquals("", auth.getPassword());  // Password is empty string, not null
        }

        @Test
        @DisplayName("Constructor throws exception for null hash")
        void testConstructorWithNullHash() {
            // Act & Assert
            assertThrows(IllegalArgumentException.class, () -> {
                new NtlmNtHashAuthenticator("DOMAIN", "user", (byte[]) null);
            });
        }

        @Test
        @DisplayName("Constructor throws exception for wrong hash length")
        void testConstructorWithWrongLength() {
            // Arrange
            byte[] shortHash = new byte[8];
            byte[] longHash = new byte[32];

            // Act & Assert
            IllegalArgumentException ex1 = assertThrows(IllegalArgumentException.class, () -> {
                new NtlmNtHashAuthenticator("DOMAIN", "user", shortHash);
            });
            IllegalArgumentException ex2 = assertThrows(IllegalArgumentException.class, () -> {
                new NtlmNtHashAuthenticator("DOMAIN", "user", longHash);
            });

            assertTrue(ex1.getMessage().contains("expected length 16"));
            assertTrue(ex2.getMessage().contains("expected length 16"));
        }

        @Test
        @DisplayName("Constructor with empty hash array throws exception")
        void testConstructorWithEmptyHash() {
            // Arrange
            byte[] emptyHash = new byte[0];

            // Act & Assert
            assertThrows(IllegalArgumentException.class, () -> {
                new NtlmNtHashAuthenticator("DOMAIN", "user", emptyHash);
            });
        }

        @Test
        @DisplayName("Constructor handles null domain and username")
        void testConstructorWithNullDomainUsername() {
            // Arrange
            byte[] hash = new byte[16];

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator(null, null, hash);

            // Assert
            assertNotNull(auth);
            assertEquals("", auth.getUserDomain());
            assertEquals("", auth.getUsername());
        }
    }

    @Nested
    @DisplayName("GetNTHash Tests")
    class GetNTHashTests {

        @Test
        @DisplayName("getNTHash() returns the provided hash")
        void testGetNTHash() {
            // Arrange
            byte[] originalHash = new byte[16];
            for (int i = 0; i < 16; i++) {
                originalHash[i] = (byte) (i * 2);
            }
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", originalHash);

            // Act
            byte[] retrievedHash = auth.getNTHash();

            // Assert
            assertNotNull(retrievedHash);
            assertEquals(16, retrievedHash.length);
            assertArrayEquals(originalHash, retrievedHash);
        }

        @Test
        @DisplayName("getNTHash() returns same reference")
        void testGetNTHashReference() {
            // Arrange
            byte[] hash = new byte[16];
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);

            // Act
            byte[] hash1 = auth.getNTHash();
            byte[] hash2 = auth.getNTHash();

            // Assert
            assertSame(hash1, hash2);
        }

        @Test
        @DisplayName("getNTHash() different from password-based hash")
        void testGetNTHashDifferentFromPasswordBased() {
            // Arrange
            byte[] providedHash = new byte[16];
            for (int i = 0; i < 16; i++) {
                providedHash[i] = (byte) 0xFF;
            }
            NtlmNtHashAuthenticator hashAuth = new NtlmNtHashAuthenticator("DOMAIN", "user", providedHash);
            NtlmPasswordAuthenticator pwdAuth = new NtlmPasswordAuthenticator("DOMAIN", "user", "password");

            // Act
            byte[] hash1 = hashAuth.getNTHash();
            byte[] hash2 = pwdAuth.getNTHash();

            // Assert - hashes should be different
            assertFalse(java.util.Arrays.equals(hash1, hash2));
        }
    }

    @Nested
    @DisplayName("Clone Tests")
    class CloneTests {

        @Test
        @DisplayName("clone() creates independent copy")
        void testClone() {
            // Arrange
            byte[] hash = new byte[16];
            for (int i = 0; i < 16; i++) {
                hash[i] = (byte) i;
            }
            NtlmNtHashAuthenticator original = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);

            // Act
            NtlmPasswordAuthenticator cloned = original.clone();

            // Assert
            assertNotNull(cloned);
            assertNotSame(original, cloned);
            assertInstanceOf(NtlmNtHashAuthenticator.class, cloned);

            NtlmNtHashAuthenticator clonedHash = (NtlmNtHashAuthenticator) cloned;
            assertEquals(original.getUserDomain(), clonedHash.getUserDomain());
            assertEquals(original.getUsername(), clonedHash.getUsername());
            assertArrayEquals(original.getNTHash(), clonedHash.getNTHash());
        }

        @Test
        @DisplayName("clone() preserves hash data")
        void testClonePreservesHash() {
            // Arrange
            byte[] hash = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x01, 0x23, 0x45, 0x67, (byte) 0x89,
                          (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98, 0x76, 0x54, 0x32, 0x10};
            NtlmNtHashAuthenticator original = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);

            // Act
            NtlmPasswordAuthenticator cloned = original.clone();

            // Assert
            assertInstanceOf(NtlmNtHashAuthenticator.class, cloned);
            byte[] clonedHash = ((NtlmNtHashAuthenticator) cloned).getNTHash();
            assertArrayEquals(hash, clonedHash);
            assertNotSame(hash, clonedHash); // Should be a copy, not same reference
        }
    }

    @Nested
    @DisplayName("Hex String Constructor Tests")
    class HexStringTests {

        @Test
        @DisplayName("Constructor with lowercase hex string")
        void testConstructorWithLowercaseHex() {
            // Arrange
            String hexHash = "0123456789abcdef0123456789abcdef";

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hexHash);

            // Assert
            assertNotNull(auth);
            byte[] hash = auth.getNTHash();
            assertEquals(16, hash.length);
            assertEquals(0x01, hash[0] & 0xFF);
            assertEquals(0xef, hash[7] & 0xFF);
        }

        @Test
        @DisplayName("Constructor with uppercase hex string")
        void testConstructorWithUppercaseHex() {
            // Arrange
            String hexHash = "FEDCBA9876543210FEDCBA9876543210";

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hexHash);

            // Assert
            assertNotNull(auth);
            byte[] hash = auth.getNTHash();
            assertEquals(16, hash.length);
            assertEquals(0xFE, hash[0] & 0xFF);
            assertEquals(0x10, hash[15] & 0xFF);
        }

        @Test
        @DisplayName("Constructor with mixed case hex string")
        void testConstructorWithMixedCaseHex() {
            // Arrange
            String hexHash = "0a1B2c3D4e5F6789fEdCbA9876543210";

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hexHash);

            // Assert
            assertNotNull(auth);
            assertEquals(16, auth.getNTHash().length);
        }

        @Test
        @DisplayName("Constructor throws exception for invalid hex string")
        void testConstructorWithInvalidHex() {
            // Arrange
            String invalidHex = "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"; // Invalid hex chars

            // Act & Assert
            assertThrows(Exception.class, () -> {
                new NtlmNtHashAuthenticator("DOMAIN", "user", invalidHex);
            });
        }

        @Test
        @DisplayName("Constructor throws exception for wrong length hex string")
        void testConstructorWithWrongLengthHex() {
            // Arrange
            String shortHex = "0123456789ABCDEF"; // Only 8 bytes = 16 hex chars
            String longHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"; // 24 bytes

            // Act & Assert
            assertThrows(Exception.class, () -> {
                new NtlmNtHashAuthenticator("DOMAIN", "user", shortHex);
            });
            assertThrows(Exception.class, () -> {
                new NtlmNtHashAuthenticator("DOMAIN", "user", longHex);
            });
        }
    }

    @Nested
    @DisplayName("Inheritance Tests")
    class InheritanceTests {

        @Test
        @DisplayName("NtlmNtHashAuthenticator extends NtlmPasswordAuthenticator")
        void testInheritance() {
            // Arrange
            byte[] hash = new byte[16];
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);

            // Assert
            assertInstanceOf(NtlmPasswordAuthenticator.class, auth);
        }

        @Test
        @DisplayName("Inherited methods work correctly")
        void testInheritedMethods() {
            // Arrange
            byte[] hash = new byte[16];
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);

            // Act & Assert
            assertEquals("DOMAIN\\user", auth.getName());
            assertEquals("DOMAIN\\user", auth.toString());
            assertFalse(auth.isAnonymous());
            assertFalse(auth.isGuest());
            assertEquals("", auth.getPassword());  // Password is empty string, not null
        }

        @Test
        @DisplayName("Equals works with parent class")
        void testEqualsWithParent() {
            // Arrange
            byte[] hash = new byte[16];
            NtlmNtHashAuthenticator auth1 = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);
            NtlmNtHashAuthenticator auth2 = new NtlmNtHashAuthenticator("DOMAIN", "user", hash);

            // Act & Assert
            assertTrue(auth1.equals(auth2));
            assertTrue(auth2.equals(auth1));
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Use case: authentication with known NT hash")
        void testAuthenticationWithKnownHash() {
            // Arrange - simulate using a known NT hash
            // This is the NT hash for "password"
            String knownHash = "8846F7EAEE8FB117AD06BDD830B7586C";

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator("TESTDOMAIN", "testuser", knownHash);

            // Assert
            assertNotNull(auth);
            assertEquals("TESTDOMAIN", auth.getUserDomain());
            assertEquals("testuser", auth.getUsername());
            assertEquals("", auth.getPassword());  // Password is empty string, not null
            assertEquals(16, auth.getNTHash().length);

            // Verify the hash matches
            byte[] hash = auth.getNTHash();
            assertEquals(0x88, hash[0] & 0xFF);
            assertEquals(0x6C, hash[15] & 0xFF);
        }

        @Test
        @DisplayName("Use case: domain\\user format parsing")
        void testDomainUserParsing() {
            // Arrange
            byte[] hash = new byte[16];

            // Act
            NtlmNtHashAuthenticator auth = new NtlmNtHashAuthenticator(null, "DOMAIN\\user", hash);

            // Assert - parent class should parse the domain from username
            assertEquals("DOMAIN", auth.getUserDomain());
            assertEquals("user", auth.getUsername());
        }

        @Test
        @DisplayName("Multiple authenticators with different hashes are independent")
        void testMultipleAuthenticators() {
            // Arrange
            byte[] hash1 = new byte[16];
            byte[] hash2 = new byte[16];
            for (int i = 0; i < 16; i++) {
                hash1[i] = (byte) i;
                hash2[i] = (byte) (i + 1);
            }

            // Act
            NtlmNtHashAuthenticator auth1 = new NtlmNtHashAuthenticator("DOMAIN1", "user1", hash1);
            NtlmNtHashAuthenticator auth2 = new NtlmNtHashAuthenticator("DOMAIN2", "user2", hash2);

            // Assert
            assertNotEquals(auth1.getUserDomain(), auth2.getUserDomain());
            assertNotEquals(auth1.getUsername(), auth2.getUsername());
            assertFalse(java.util.Arrays.equals(auth1.getNTHash(), auth2.getNTHash()));
        }
    }
}
