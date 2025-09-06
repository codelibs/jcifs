package org.codelibs.jcifs.smb.spnego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for SpnegoToken.
 * Uses a minimal concrete subclass to exercise abstract methods.
 */
class SpnegoTokenTest {

    /**
     * Minimal concrete implementation for testing.
     * - parse: sets mechanismToken, throws on null
     * - toByteArray: returns mechanismToken or empty array if null
     */
    static class TestSpnegoToken extends SpnegoToken {
        private boolean parsed = false;

        @Override
        public byte[] toByteArray() {
            byte[] tok = getMechanismToken();
            return tok == null ? new byte[0] : tok;
        }

        @Override
        protected void parse(byte[] token) throws IOException {
            if (token == null) {
                throw new IOException("token is null");
            }
            setMechanismToken(token);
            this.parsed = true;
        }

        boolean isParsed() {
            return parsed;
        }
    }

    @Test
    @DisplayName("Default state is null for both fields")
    void defaultStateIsNull() {
        TestSpnegoToken t = new TestSpnegoToken();
        assertNull(t.getMechanismToken(), "mechanismToken should default to null");
        assertNull(t.getMechanismListMIC(), "mechanismListMIC should default to null");
    }

    @Test
    @DisplayName("Setter and getter for mechanismToken work")
    void setGetMechanismToken() {
        TestSpnegoToken t = new TestSpnegoToken();
        byte[] data = new byte[] { 1, 2, 3 };
        t.setMechanismToken(data);
        assertArrayEquals(data, t.getMechanismToken(), "mechanismToken should round-trip");

        // Document current behavior: no defensive copy (reference exposed)
        data[0] = 9;
        assertEquals(9, t.getMechanismToken()[0], "no defensive copy; reflects external mutation");
    }

    @Test
    @DisplayName("Setter and getter for mechanismListMIC work")
    void setGetMechanismListMIC() {
        TestSpnegoToken t = new TestSpnegoToken();
        byte[] mic = new byte[] { 7, 8, 9, 10 };
        t.setMechanismListMIC(mic);
        assertArrayEquals(mic, t.getMechanismListMIC(), "mechanismListMIC should round-trip");

        // Document current behavior: no defensive copy (reference exposed)
        mic[1] = 42;
        assertEquals(42, t.getMechanismListMIC()[1], "no defensive copy; reflects external mutation");
    }

    @Test
    @DisplayName("parse sets mechanismToken and flags parsed")
    void parseSetsMechanismToken() throws IOException {
        TestSpnegoToken t = new TestSpnegoToken();
        byte[] raw = new byte[] { 5, 6 };
        t.parse(raw);
        assertTrue(t.isParsed(), "parse should mark parsed");
        assertArrayEquals(raw, t.getMechanismToken(), "parse should set mechanismToken");
    }

    @Test
    @DisplayName("parse throws IOException on null input")
    void parseThrowsOnNull() {
        TestSpnegoToken t = new TestSpnegoToken();
        IOException ex = assertThrows(IOException.class, () -> t.parse(null), "parse should throw IOException on null");
        assertTrue(ex.getMessage().toLowerCase().contains("null"));
    }

    @Test
    @DisplayName("toByteArray returns empty when no mechanismToken")
    void toByteArrayWhenNull() {
        TestSpnegoToken t = new TestSpnegoToken();
        assertArrayEquals(new byte[0], t.toByteArray(), "empty array expected when mechanismToken is null");
    }

    @Test
    @DisplayName("toByteArray returns mechanismToken reference when present")
    void toByteArrayReturnsToken() throws IOException {
        TestSpnegoToken t = new TestSpnegoToken();
        byte[] raw = new byte[] { 11, 12, 13 };
        t.parse(raw);
        // Current behavior of test impl: returns same reference
        assertSame(raw, t.toByteArray(), "should return the same reference as mechanismToken");
    }

    @Test
    @DisplayName("Setters accept null and getters return null")
    void settersAcceptNull() {
        TestSpnegoToken t = new TestSpnegoToken();
        t.setMechanismToken(null);
        t.setMechanismListMIC(null);
        assertNull(t.getMechanismToken(), "mechanismToken should be null after setting null");
        assertNull(t.getMechanismListMIC(), "mechanismListMIC should be null after setting null");
    }
}
