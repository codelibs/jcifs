package jcifs.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class AvTargetNameTest {

    /**
     * Test constructor with raw bytes.
     * Verifies that the AvPair type is correctly set and raw bytes are stored.
     */
    @Test
    void testConstructorWithRawBytes() {
        byte[] rawBytes = "TEST_TARGET_NAME".getBytes(StandardCharsets.UTF_16LE);
        AvTargetName avTargetName = new AvTargetName(rawBytes);

        // Verify the AvPair type is MsvAvTargetName
        assertEquals(AvPair.MsvAvTargetName, avTargetName.getType(), "AvPair type should be MsvAvTargetName");
        // Verify the raw bytes are correctly stored
        assertArrayEquals(rawBytes, avTargetName.getRaw(), "Raw bytes should match the input");
    }

    /**
     * Test constructor with a target name string.
     * Verifies that the string is correctly encoded to UTF-16LE bytes and stored.
     */
    @Test
    void testConstructorWithString() {
        String targetName = "AnotherTargetName";
        AvTargetName avTargetName = new AvTargetName(targetName);

        // Verify the AvPair type is MsvAvTargetName
        assertEquals(AvPair.MsvAvTargetName, avTargetName.getType(), "AvPair type should be MsvAvTargetName");
        // Verify the raw bytes are the UTF-16LE encoding of the input string
        assertArrayEquals(targetName.getBytes(StandardCharsets.UTF_16LE), avTargetName.getRaw(),
                "Raw bytes should be UTF-16LE encoded string");
    }

    /**
     * Test getTargetName() method with a string input.
     * Verifies that the original string is returned after encoding and decoding.
     */
    @Test
    void testGetTargetNameFromStringConstructor() {
        String targetName = "MyService/Host.Domain.com";
        AvTargetName avTargetName = new AvTargetName(targetName);

        // Verify that getTargetName returns the original string
        assertEquals(targetName, avTargetName.getTargetName(), "Retrieved target name should match the original string");
    }

    /**
     * Test getTargetName() method with raw bytes input.
     * Verifies that the correct string is reconstructed from raw UTF-16LE bytes.
     */
    @Test
    void testGetTargetNameFromRawBytesConstructor() {
        String originalString = "RawBytesTarget";
        byte[] rawBytes = originalString.getBytes(StandardCharsets.UTF_16LE);
        AvTargetName avTargetName = new AvTargetName(rawBytes);

        // Verify that getTargetName correctly decodes the raw bytes
        assertEquals(originalString, avTargetName.getTargetName(), "Retrieved target name should correctly decode raw bytes");
    }

    /**
     * Test with an empty string for both constructors.
     */
    @Test
    void testEmptyString() {
        String emptyString = "";
        AvTargetName avTargetNameFromString = new AvTargetName(emptyString);
        assertEquals(emptyString, avTargetNameFromString.getTargetName(),
                "Empty string should be handled correctly from string constructor");
        assertArrayEquals(emptyString.getBytes(StandardCharsets.UTF_16LE), avTargetNameFromString.getRaw(),
                "Raw bytes for empty string should be empty");

        byte[] emptyBytes = new byte[0];
        AvTargetName avTargetNameFromBytes = new AvTargetName(emptyBytes);
        assertEquals(emptyString, avTargetNameFromBytes.getTargetName(),
                "Empty string should be handled correctly from raw bytes constructor");
        assertArrayEquals(emptyBytes, avTargetNameFromBytes.getRaw(), "Raw bytes for empty string should be empty");
    }

    /**
     * Test with special characters in the target name.
     */
    @Test
    void testSpecialCharacters() {
        String specialChars = "サーバー名/ドメイン.com-123!@#$"; // Japanese characters and symbols
        AvTargetName avTargetName = new AvTargetName(specialChars);
        assertEquals(specialChars, avTargetName.getTargetName(), "Special characters should be handled correctly");
    }
}
