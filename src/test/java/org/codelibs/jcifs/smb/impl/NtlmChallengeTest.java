package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import java.net.InetAddress;

import org.codelibs.jcifs.smb.BaseTest;
import org.codelibs.jcifs.smb.netbios.UniAddress;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("NtlmChallenge Tests")
class NtlmChallengeTest extends BaseTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor sets challenge and dc fields")
        void testConstructor() throws Exception {
            // Arrange
            byte[] challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            UniAddress dc = new UniAddress(InetAddress.getByName("192.168.1.1"));

            // Act
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, dc);

            // Assert
            assertNotNull(ntlmChallenge);
            assertSame(challenge, ntlmChallenge.challenge);
            assertSame(dc, ntlmChallenge.dc);
        }

        @Test
        @DisplayName("Constructor accepts null challenge")
        void testConstructorWithNullChallenge() throws Exception {
            // Arrange
            UniAddress dc = new UniAddress(InetAddress.getByName("127.0.0.1"));

            // Act
            NtlmChallenge ntlmChallenge = new NtlmChallenge(null, dc);

            // Assert
            assertNotNull(ntlmChallenge);
            assertNull(ntlmChallenge.challenge);
            assertSame(dc, ntlmChallenge.dc);
        }

        @Test
        @DisplayName("Constructor accepts null dc")
        void testConstructorWithNullDc() {
            // Arrange
            byte[] challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

            // Act
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, null);

            // Assert
            assertNotNull(ntlmChallenge);
            assertSame(challenge, ntlmChallenge.challenge);
            assertNull(ntlmChallenge.dc);
        }

        @Test
        @DisplayName("Constructor with various challenge lengths")
        void testConstructorWithVariousChallenges() throws Exception {
            // Arrange
            UniAddress dc = new UniAddress(InetAddress.getByName("192.168.1.1"));
            byte[] challenge8 = new byte[8];
            byte[] challenge16 = new byte[16];
            byte[] challenge0 = new byte[0];

            // Act
            NtlmChallenge nc8 = new NtlmChallenge(challenge8, dc);
            NtlmChallenge nc16 = new NtlmChallenge(challenge16, dc);
            NtlmChallenge nc0 = new NtlmChallenge(challenge0, dc);

            // Assert
            assertEquals(8, nc8.challenge.length);
            assertEquals(16, nc16.challenge.length);
            assertEquals(0, nc0.challenge.length);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("toString() includes challenge hex string")
        void testToStringWithChallenge() throws Exception {
            // Arrange
            byte[] challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            UniAddress dc = new UniAddress(InetAddress.getByName("192.168.1.1"));
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, dc);

            // Act
            String result = ntlmChallenge.toString();

            // Assert
            assertNotNull(result);
            assertTrue(result.contains("NtlmChallenge"), "Should contain class name");
            assertTrue(result.contains("challenge="), "Should contain 'challenge='");
            assertTrue(result.contains("0x"), "Should contain hex prefix");
            assertTrue(result.contains("dc="), "Should contain 'dc='");
        }

        @Test
        @DisplayName("toString() includes hex representation of challenge bytes")
        void testToStringHexFormat() throws Exception {
            // Arrange
            byte[] challenge = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x01, 0x23, 0x45, 0x67, (byte) 0x89};
            UniAddress dc = new UniAddress(InetAddress.getByName("127.0.0.1"));
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, dc);

            // Act
            String result = ntlmChallenge.toString();

            // Assert
            assertTrue(result.contains("AB") || result.contains("ab"), "Should contain AB in hex");
            assertTrue(result.contains("CD") || result.contains("cd"), "Should contain CD in hex");
            assertTrue(result.contains("EF") || result.contains("ef"), "Should contain EF in hex");
        }

        @Test
        @DisplayName("toString() with empty challenge")
        void testToStringWithEmptyChallenge() throws Exception {
            // Arrange
            byte[] challenge = new byte[0];
            UniAddress dc = new UniAddress(InetAddress.getByName("127.0.0.1"));
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, dc);

            // Act
            String result = ntlmChallenge.toString();

            // Assert
            assertNotNull(result);
            assertTrue(result.contains("NtlmChallenge"));
            assertTrue(result.contains("challenge="));
        }

        @Test
        @DisplayName("toString() with different UniAddress formats")
        void testToStringWithDifferentAddresses() throws Exception {
            // Arrange
            byte[] challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            UniAddress dcByIp = new UniAddress(InetAddress.getByName("10.0.0.1"));
            UniAddress dcByName = new UniAddress(InetAddress.getByName("127.0.0.1"));

            NtlmChallenge nc1 = new NtlmChallenge(challenge, dcByIp);
            NtlmChallenge nc2 = new NtlmChallenge(challenge, dcByName);

            // Act
            String result1 = nc1.toString();
            String result2 = nc2.toString();

            // Assert
            assertNotNull(result1);
            assertNotNull(result2);
            assertTrue(result1.contains("dc="));
            assertTrue(result2.contains("dc="));
        }
    }

    @Nested
    @DisplayName("Serialization Tests")
    class SerializationTests {

        @Test
        @DisplayName("NtlmChallenge is serializable")
        void testSerializable() throws Exception {
            // Arrange
            byte[] challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            UniAddress dc = new UniAddress(InetAddress.getByName("192.168.1.1"));
            NtlmChallenge original = new NtlmChallenge(challenge, dc);

            // Act - serialize and deserialize
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos);
            oos.writeObject(original);
            oos.close();

            byte[] serialized = bos.toByteArray();
            java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(serialized);
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bis);
            NtlmChallenge deserialized = (NtlmChallenge) ois.readObject();
            ois.close();

            // Assert
            assertNotNull(deserialized);
            assertArrayEquals(original.challenge, deserialized.challenge);
            // Note: UniAddress may not serialize exactly the same way, so we just check it's not null
            assertNotNull(deserialized.dc);
        }

        @Test
        @DisplayName("Serialization preserves challenge data")
        void testSerializationPreservesData() throws Exception {
            // Arrange
            byte[] challenge = {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC,
                               (byte) 0xBB, (byte) 0xAA, 0x11, 0x22};
            UniAddress dc = new UniAddress(InetAddress.getByName("testserver"));
            NtlmChallenge original = new NtlmChallenge(challenge, dc);

            // Act
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos);
            oos.writeObject(original);
            oos.close();

            java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(bos.toByteArray());
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bis);
            NtlmChallenge deserialized = (NtlmChallenge) ois.readObject();
            ois.close();

            // Assert
            assertArrayEquals(challenge, deserialized.challenge);
            for (int i = 0; i < challenge.length; i++) {
                assertEquals(challenge[i], deserialized.challenge[i],
                    "Challenge byte at index " + i + " should match");
            }
        }
    }

    @Nested
    @DisplayName("Field Access Tests")
    class FieldAccessTests {

        @Test
        @DisplayName("Challenge field is directly accessible")
        void testChallengeFieldAccess() throws Exception {
            // Arrange
            byte[] challenge = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
            UniAddress dc = new UniAddress(InetAddress.getByName("server"));
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, dc);

            // Act & Assert
            assertSame(challenge, ntlmChallenge.challenge);
            assertEquals(0x11, ntlmChallenge.challenge[0] & 0xFF);
            assertEquals(0x88, ntlmChallenge.challenge[7] & 0xFF);
        }

        @Test
        @DisplayName("DC field is directly accessible")
        void testDcFieldAccess() throws Exception {
            // Arrange
            UniAddress dc = new UniAddress(InetAddress.getByName("192.168.100.1"));
            NtlmChallenge ntlmChallenge = new NtlmChallenge(new byte[8], dc);

            // Act & Assert
            assertSame(dc, ntlmChallenge.dc);
        }

        @Test
        @DisplayName("Challenge field can be modified after construction")
        void testChallengeFieldModifiable() throws Exception {
            // Arrange
            byte[] challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            UniAddress dc = new UniAddress(InetAddress.getByName("server"));
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, dc);

            // Act
            challenge[0] = (byte) 0xFF;

            // Assert - modification affects the stored reference
            assertEquals((byte) 0xFF, ntlmChallenge.challenge[0]);
        }

        @Test
        @DisplayName("Challenge field can be replaced")
        void testChallengeFieldReplaceable() throws Exception {
            // Arrange
            byte[] oldChallenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            byte[] newChallenge = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
            UniAddress dc = new UniAddress(InetAddress.getByName("server"));
            NtlmChallenge ntlmChallenge = new NtlmChallenge(oldChallenge, dc);

            // Act
            ntlmChallenge.challenge = newChallenge;

            // Assert
            assertSame(newChallenge, ntlmChallenge.challenge);
            assertArrayEquals(newChallenge, ntlmChallenge.challenge);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Typical NTLM challenge scenario")
        void testTypicalScenario() throws Exception {
            // Arrange - simulate a typical 8-byte NTLM challenge
            byte[] challenge = new byte[8];
            new java.security.SecureRandom().nextBytes(challenge);
            UniAddress dc = new UniAddress(InetAddress.getByName("dc.example.com"));

            // Act
            NtlmChallenge ntlmChallenge = new NtlmChallenge(challenge, dc);

            // Assert
            assertNotNull(ntlmChallenge);
            assertEquals(8, ntlmChallenge.challenge.length);
            assertNotNull(ntlmChallenge.dc);

            // Verify toString doesn't throw
            String str = ntlmChallenge.toString();
            assertNotNull(str);
            assertTrue(str.length() > 0);
        }

        @Test
        @DisplayName("Multiple NtlmChallenge instances are independent")
        void testMultipleInstancesIndependent() throws Exception {
            // Arrange
            byte[] challenge1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            byte[] challenge2 = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
            UniAddress dc1 = new UniAddress(InetAddress.getByName("dc1.example.com"));
            UniAddress dc2 = new UniAddress(InetAddress.getByName("dc2.example.com"));

            // Act
            NtlmChallenge nc1 = new NtlmChallenge(challenge1, dc1);
            NtlmChallenge nc2 = new NtlmChallenge(challenge2, dc2);

            // Assert
            assertNotSame(nc1.challenge, nc2.challenge);
            assertNotSame(nc1.dc, nc2.dc);
            assertArrayEquals(challenge1, nc1.challenge);
            assertArrayEquals(challenge2, nc2.challenge);
        }
    }
}
