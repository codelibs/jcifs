/*
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
package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;
import jcifs.pac.PACDecodingException;

/**
 * Tests for the {@link PacUnicodeString} class.
 */
class PacUnicodeStringTest {

    /**
     * Tests the constructor and getter methods.
     */
    @Test
    void testConstructorAndGetters() {
        // Create a new instance with some test data
        short length = 10;
        short maxLength = 20;
        int pointer = 100;
        PacUnicodeString pacString = new PacUnicodeString(length, maxLength, pointer);

        // Verify that the object was created
        assertNotNull(pacString, "The PacUnicodeString object should not be null.");

        // Verify that the getters return the correct values
        assertEquals(length, pacString.getLength(), "The length should match the value provided in the constructor.");
        assertEquals(maxLength, pacString.getMaxLength(), "The maxLength should match the value provided in the constructor.");
        assertEquals(pointer, pacString.getPointer(), "The pointer should match the value provided in the constructor.");
    }

    /**
     * Tests the {@link PacUnicodeString#check(String)} method with a valid string.
     *
     * @throws PACDecodingException if the check fails, which is not expected in this test.
     */
    @Test
    void testCheck_withValidString() throws PACDecodingException {
        // Corresponds to a string of length 5 (10 bytes for UTF-16)
        PacUnicodeString pacString = new PacUnicodeString((short) 10, (short) 20, 100);
        String testString = "abcde";

        // The check method should return the same string instance
        String result = pacString.check(testString);
        assertSame(testString, result, "The check method should return the original string on success.");
    }

    /**
     * Tests the {@link PacUnicodeString#check(String)} method with a null string when the pointer is zero.
     *
     * @throws PACDecodingException if the check fails, which is not expected in this test.
     */
    @Test
    void testCheck_withNullStringAndZeroPointer() throws PACDecodingException {
        // A zero pointer indicates a null string
        PacUnicodeString pacString = new PacUnicodeString((short) 0, (short) 0, 0);
        String testString = null;

        // The check method should return null
        String result = pacString.check(testString);
        assertEquals(testString, result, "The check method should return null for a null input with a zero pointer.");
    }

    /**
     * Tests the {@link PacUnicodeString#check(String)} method with a non-empty string when the pointer is zero.
     * This is an invalid state and should throw an exception.
     */
    @Test
    void testCheck_withNonNullStringAndZeroPointer_throwsException() {
        // A zero pointer should mean the string is null
        PacUnicodeString pacString = new PacUnicodeString((short) 0, (short) 0, 0);
        String testString = "not-null";

        // Expect a PACDecodingException to be thrown
        PACDecodingException exception = assertThrows(PACDecodingException.class, () -> {
            pacString.check(testString);
        }, "A PACDecodingException should be thrown for a non-empty string with a zero pointer.");

        // Verify the exception message
        assertEquals("Non-empty string", exception.getMessage(), "The exception message is not correct.");
    }

    /**
     * Tests the {@link PacUnicodeString#check(String)} method with a string of incorrect length.
     */
    @Test
    void testCheck_withInvalidLength_throwsException() {
        // Length is 10 bytes, so expected string length is 5 characters
        PacUnicodeString pacString = new PacUnicodeString((short) 10, (short) 20, 100);
        String testString = "too-long"; // Length is 8

        // Expect a PACDecodingException to be thrown
        PACDecodingException exception = assertThrows(PACDecodingException.class, () -> {
            pacString.check(testString);
        }, "A PACDecodingException should be thrown for a string with an invalid length.");

        // Verify the exception message
        String expectedMessage = "Invalid string length, expected 5, have 8";
        assertEquals(expectedMessage, exception.getMessage(), "The exception message is not correct.");
    }

    /**
     * Tests the {@link PacUnicodeString#check(String)} method with an empty string.
     *
     * @throws PACDecodingException if the check fails, which is not expected in this test.
     */
    @Test
    void testCheck_withEmptyString() throws PACDecodingException {
        // Length is 0, so an empty string is expected
        PacUnicodeString pacString = new PacUnicodeString((short) 0, (short) 10, 100);
        String testString = "";

        // The check method should return the empty string
        String result = pacString.check(testString);
        assertSame(testString, result, "The check method should return the original empty string.");
    }
}