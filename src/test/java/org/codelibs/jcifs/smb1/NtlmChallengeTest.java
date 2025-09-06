package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link NtlmChallenge}.
 */
class NtlmChallengeTest {

    @Nested
    @DisplayName("Constructor and Field Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor sets fields correctly")
        void testConstructorSetsFields() {
            byte[] challenge = new byte[] { 1, 2, 3 };
            UniAddress dc = mock(UniAddress.class);

            NtlmChallenge nc = new NtlmChallenge(challenge, dc);

            assertSame(challenge, nc.challenge);
            assertSame(dc, nc.dc);
        }

        @Test
        @DisplayName("Constructor accepts null challenge")
        void testConstructorAcceptsNullChallenge() {
            UniAddress dc = mock(UniAddress.class);

            NtlmChallenge nc = new NtlmChallenge(null, dc);

            assertNull(nc.challenge);
            assertSame(dc, nc.dc);
        }

        @Test
        @DisplayName("Constructor accepts null dc")
        void testConstructorAcceptsNullDc() {
            byte[] challenge = new byte[] { 1, 2, 3 };

            NtlmChallenge nc = new NtlmChallenge(challenge, null);

            assertSame(challenge, nc.challenge);
            assertNull(nc.dc);
        }
    }

    @Nested
    @DisplayName("toString() Tests")
    class ToStringTests {

        @Test
        @DisplayName("toString with valid data produces expected format")
        void testToStringWithValidData() {
            byte[] challenge = new byte[] { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0xFF };
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("SERVER123");

            NtlmChallenge nc = new NtlmChallenge(challenge, dc);
            String result = nc.toString();

            // The format is: NtlmChallenge[challenge=0x<hex>,dc=<dc_string>]
            assertTrue(result.startsWith("NtlmChallenge[challenge=0x"));
            assertTrue(result.endsWith(",dc=SERVER123]"));

            // Hexdump.toHexString with size = length * 2 produces 8 uppercase hex chars
            // The hex should be "010203FF"
            assertTrue(result.contains("010203FF"));
        }

        @Test
        @DisplayName("toString with empty challenge array")
        void testToStringWithEmptyChallenge() {
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("EMPTYSERVER");

            NtlmChallenge nc = new NtlmChallenge(new byte[0], dc);
            String result = nc.toString();

            assertEquals("NtlmChallenge[challenge=0x,dc=EMPTYSERVER]", result);
        }

        @Test
        @DisplayName("toString with single byte challenge")
        void testToStringWithSingleByte() {
            byte[] challenge = new byte[] { (byte) 0xAB };
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("TESTDC");

            NtlmChallenge nc = new NtlmChallenge(challenge, dc);
            String result = nc.toString();

            // With size = 1 * 2 = 2, Hexdump.toHexString produces "AB"
            assertTrue(result.contains("challenge=0xAB"));
            assertTrue(result.contains("dc=TESTDC"));
        }

        @Test
        @DisplayName("toString with null challenge throws NPE")
        void testToStringWithNullChallengeThrowsNPE() {
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("ANYSERVER");

            NtlmChallenge nc = new NtlmChallenge(null, dc);

            // Hexdump.toHexString will throw NPE when accessing challenge.length
            assertThrows(NullPointerException.class, nc::toString);
        }

        @Test
        @DisplayName("toString with null dc throws NPE")
        void testToStringWithNullDcThrowsNPE() {
            byte[] challenge = new byte[] { 1, 2, 3 };

            NtlmChallenge nc = new NtlmChallenge(challenge, null);

            // dc.toString() will throw NPE
            assertThrows(NullPointerException.class, nc::toString);
        }
    }

    @Nested
    @DisplayName("Hex Conversion Tests")
    class HexConversionTests {

        @Test
        @DisplayName("Various byte values are converted to uppercase hex")
        void testHexConversion() {
            byte[] challenge = new byte[] { (byte) 0x00, (byte) 0x0F, (byte) 0x10, (byte) 0x7F, (byte) 0x80, (byte) 0xFF };
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("DC");

            NtlmChallenge nc = new NtlmChallenge(challenge, dc);
            String result = nc.toString();

            // With size = 6 * 2 = 12, should produce "000F107F80FF"
            assertTrue(result.contains("000F107F80FF"));
        }

        @Test
        @DisplayName("Large challenge array is handled correctly")
        void testLargeChallengeArray() {
            byte[] challenge = new byte[16];
            for (int i = 0; i < 16; i++) {
                challenge[i] = (byte) i;
            }
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("LARGEDC");

            NtlmChallenge nc = new NtlmChallenge(challenge, dc);
            String result = nc.toString();

            // Should contain hex representation of 0-15
            assertTrue(result.contains("0x"));
            assertTrue(result.contains("dc=LARGEDC"));
            // The hex string should be 32 chars long (16 bytes * 2)
            String hexPart = result.substring(result.indexOf("0x") + 2, result.indexOf(",dc="));
            assertEquals(32, hexPart.length());
        }
    }
}