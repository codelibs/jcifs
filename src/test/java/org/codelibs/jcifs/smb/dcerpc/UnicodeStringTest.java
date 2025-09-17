package org.codelibs.jcifs.smb.dcerpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UnicodeStringTest {

    @Test
    void testConstructorWithZterm() {
        // Test with zterm = true
        UnicodeString unicodeStringTrue = new UnicodeString(true);
        assertTrue(unicodeStringTrue.zterm, "zterm should be true");
        assertEquals(0, unicodeStringTrue.length, "Length should be 0 for empty string");
        assertEquals(0, unicodeStringTrue.maximum_length, "Maximum length should be 0 for empty string");
        assertNull(unicodeStringTrue.buffer, "Buffer should be null for empty string");

        // Test with zterm = false
        UnicodeString unicodeStringFalse = new UnicodeString(false);
        assertFalse(unicodeStringFalse.zterm, "zterm should be false");
        assertEquals(0, unicodeStringFalse.length, "Length should be 0 for empty string");
        assertEquals(0, unicodeStringFalse.maximum_length, "Maximum length should be 0 for empty string");
        assertNull(unicodeStringFalse.buffer, "Buffer should be null for empty string");
    }

    @Test
    void testConstructorWithRpcUnicodeStringAndZterm() {
        // Create a dummy rpc.unicode_string
        rpc.unicode_string dummyRus = new rpc.unicode_string();
        dummyRus.length = 10;
        dummyRus.maximum_length = 20;
        dummyRus.buffer = new short[] { 'H', 'e', 'l', 'l', 'o' };

        // Test with zterm = true
        UnicodeString unicodeStringTrue = new UnicodeString(dummyRus, true);
        assertEquals(dummyRus.length, unicodeStringTrue.length, "Length should be copied");
        assertEquals(dummyRus.maximum_length, unicodeStringTrue.maximum_length, "Maximum length should be copied");
        assertArrayEquals(dummyRus.buffer, unicodeStringTrue.buffer, "Buffer should be copied");
        assertTrue(unicodeStringTrue.zterm, "zterm should be true");

        // Test with zterm = false
        UnicodeString unicodeStringFalse = new UnicodeString(dummyRus, false);
        assertEquals(dummyRus.length, unicodeStringFalse.length, "Length should be copied");
        assertEquals(dummyRus.maximum_length, unicodeStringFalse.maximum_length, "Maximum length should be copied");
        assertArrayEquals(dummyRus.buffer, unicodeStringFalse.buffer, "Buffer should be copied");
        assertFalse(unicodeStringFalse.zterm, "zterm should be false");
    }

    @Test
    void testConstructorWithStringAndZterm() {
        // Test with a non-empty string and zterm = true
        String testStringTrue = "Test";
        UnicodeString unicodeStringTrue = new UnicodeString(testStringTrue, true);
        assertTrue(unicodeStringTrue.zterm, "zterm should be true");
        assertEquals((testStringTrue.length() + 1) * 2, unicodeStringTrue.length, "Length should include zterm");
        assertEquals((testStringTrue.length() + 1) * 2, unicodeStringTrue.maximum_length, "Maximum length should include zterm");
        assertNotNull(unicodeStringTrue.buffer, "Buffer should not be null");
        assertEquals(testStringTrue.length() + 1, unicodeStringTrue.buffer.length, "Buffer length should include zterm");
        for (int i = 0; i < testStringTrue.length(); i++) {
            assertEquals(testStringTrue.charAt(i), (char) unicodeStringTrue.buffer[i], "Character mismatch");
        }
        assertEquals(0, unicodeStringTrue.buffer[testStringTrue.length()], "Last character should be zero");

        // Test with a non-empty string and zterm = false
        String testStringFalse = "Hello";
        UnicodeString unicodeStringFalse = new UnicodeString(testStringFalse, false);
        assertFalse(unicodeStringFalse.zterm, "zterm should be false");
        assertEquals(testStringFalse.length() * 2, unicodeStringFalse.length, "Length should not include zterm");
        assertEquals(testStringFalse.length() * 2, unicodeStringFalse.maximum_length, "Maximum length should not include zterm");
        assertNotNull(unicodeStringFalse.buffer, "Buffer should not be null");
        assertEquals(testStringFalse.length(), unicodeStringFalse.buffer.length, "Buffer length should not include zterm");
        for (int i = 0; i < testStringFalse.length(); i++) {
            assertEquals(testStringFalse.charAt(i), (char) unicodeStringFalse.buffer[i], "Character mismatch");
        }

        // Test with an empty string and zterm = true
        String emptyStringTrue = "";
        UnicodeString emptyUnicodeStringTrue = new UnicodeString(emptyStringTrue, true);
        assertTrue(emptyUnicodeStringTrue.zterm, "zterm should be true for empty string");
        assertEquals(2, emptyUnicodeStringTrue.length, "Length should be 2 for empty string with zterm");
        assertEquals(2, emptyUnicodeStringTrue.maximum_length, "Maximum length should be 2 for empty string with zterm");
        assertNotNull(emptyUnicodeStringTrue.buffer, "Buffer should not be null for empty string with zterm");
        assertEquals(1, emptyUnicodeStringTrue.buffer.length, "Buffer length should be 1 for empty string with zterm");
        assertEquals(0, emptyUnicodeStringTrue.buffer[0], "Buffer should contain only zero for empty string with zterm");

        // Test with an empty string and zterm = false
        String emptyStringFalse = "";
        UnicodeString emptyUnicodeStringFalse = new UnicodeString(emptyStringFalse, false);
        assertFalse(emptyUnicodeStringFalse.zterm, "zterm should be false for empty string");
        assertEquals(0, emptyUnicodeStringFalse.length, "Length should be 0 for empty string without zterm");
        assertEquals(0, emptyUnicodeStringFalse.maximum_length, "Maximum length should be 0 for empty string without zterm");
        assertNotNull(emptyUnicodeStringFalse.buffer, "Buffer should not be null for empty string without zterm");
        assertEquals(0, emptyUnicodeStringFalse.buffer.length, "Buffer length should be 0 for empty string without zterm");
    }

    @Test
    void testToString() {
        // Test toString with zterm = true
        String originalStringTrue = "HelloWorld";
        UnicodeString unicodeStringTrue = new UnicodeString(originalStringTrue, true);
        assertEquals(originalStringTrue, unicodeStringTrue.toString(), "toString should return original string with zterm");

        // Test toString with zterm = false
        String originalStringFalse = "AnotherTest";
        UnicodeString unicodeStringFalse = new UnicodeString(originalStringFalse, false);
        assertEquals(originalStringFalse, unicodeStringFalse.toString(), "toString should return original string without zterm");

        // Test toString with empty string and zterm = true
        UnicodeString emptyUnicodeStringTrue = new UnicodeString("", true);
        assertEquals("", emptyUnicodeStringTrue.toString(), "toString should return empty string for empty input with zterm");

        // Test toString with empty string and zterm = false
        UnicodeString emptyUnicodeStringFalse = new UnicodeString("", false);
        assertEquals("", emptyUnicodeStringFalse.toString(), "toString should return empty string for empty input without zterm");

        // Test toString with a manually constructed UnicodeString (simulating rpc.unicode_string input)
        rpc.unicode_string dummyRus = new rpc.unicode_string();
        dummyRus.buffer = new short[] { 'T', 'e', 's', 't', 'i', 'n', 'g' };
        dummyRus.length = 14; // 7 characters * 2 bytes/char
        dummyRus.maximum_length = 14;
        UnicodeString manualUnicodeString = new UnicodeString(dummyRus, false);
        assertEquals("Testing", manualUnicodeString.toString(), "toString should work with manually set buffer and length (no zterm)");

        // Test toString with a manually constructed UnicodeString with zterm
        rpc.unicode_string dummyRusZterm = new rpc.unicode_string();
        dummyRusZterm.buffer = new short[] { 'Z', 't', 'e', 'r', 'm', 0 };
        dummyRusZterm.length = 12; // 5 characters + 1 zterm * 2 bytes/char
        dummyRusZterm.maximum_length = 12;
        UnicodeString manualUnicodeStringZterm = new UnicodeString(dummyRusZterm, true);
        assertEquals("Zterm", manualUnicodeStringZterm.toString(), "toString should work with manually set buffer and length (with zterm)");

        // Test toString with buffer containing non-printable characters or special unicode
        String unicodeChars = "你好世界"; // "Hello World" in Chinese
        UnicodeString unicodeStringChinese = new UnicodeString(unicodeChars, false);
        assertEquals(unicodeChars, unicodeStringChinese.toString(), "toString should handle unicode characters correctly");

        // Test toString with buffer containing only zero (should result in empty string)
        rpc.unicode_string zeroBufferRus = new rpc.unicode_string();
        zeroBufferRus.buffer = new short[] { 0 };
        zeroBufferRus.length = 2;
        zeroBufferRus.maximum_length = 2;
        UnicodeString zeroBufferUnicodeString = new UnicodeString(zeroBufferRus, true);
        assertEquals("", zeroBufferUnicodeString.toString(), "toString should return empty string for buffer with only zero and zterm");
    }
}
