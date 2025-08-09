package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link NtlmChallenge}.
 */
class NtlmChallengeTest {

    @Nested
    @DisplayName("Happy Path")
    class HappyPath {

        @Test
        @DisplayName("toString produces expected hex and dc string")
        void testToString() {
            byte[] challenge = new byte[]{1, 2, 3, (byte) 0xFF};
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("SERVER123");

            NtlmChallenge nc = new NtlmChallenge(challenge, dc);
            String result = nc.toString();

            assertTrue(result.startsWith("NtlmChallenge[challenge=0x"));
            assertTrue(result.endsWith(",dc=SERVER123]"));
            assertTrue(result.contains("010203ff"));
        }

        @Test
        @DisplayName("Challenge can be empty – no hex characters appear")
        void testEmptyChallenge() {
            UniAddress dc = mock(UniAddress.class);
            when(dc.toString()).thenReturn("EMPTYSERVER");
            NtlmChallenge nc = new NtlmChallenge(new byte[0], dc);
            assertEquals("NtlmChallenge[challenge=0x,dc=EMPTYSERVER]", nc.toString());
        }
    }

    @Nested
    @DisplayName("Invalid Inputs")
    class InvalidInputs {

        @Test
        @DisplayName("Null challenge causes NPE during toString")
        void testNullChallenge() {
            UniAddress dc = mock(UniAddress.class);
            NtlmChallenge nc = new NtlmChallenge(null, dc);
            assertThrows(NullPointerException.class, nc::toString);
        }

        @Test
        @DisplayName("Null dc causes NPE during toString")
        void testNullDc() {
            byte[] challenge = new byte[]{1, 2, 3};
            assertThrows(NullPointerException.class, () -> new NtlmChallenge(challenge, null));
        }
    }

    @Test
    @DisplayName("Dependency interaction – UniAddress#toString invoked once")
    void dependencyInteraction() {
        byte[] ch = {10, 20, 30};
        UniAddress mockDc = mock(UniAddress.class);
        when(mockDc.toString()).thenReturn("MOCKSERVER");
        NtlmChallenge challenge = new NtlmChallenge(ch, mockDc);

        String result = challenge.toString();

        assertTrue(result.contains("MOCKSERVER"));
        verify(mockDc, times(1)).toString();
    }
}
