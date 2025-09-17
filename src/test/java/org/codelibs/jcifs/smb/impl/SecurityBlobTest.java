package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Field;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SecurityBlobTest {

    // Parameter source for toString() hex rendering cases
    static Stream<Arguments> hexCases() {
        return Stream.of(Arguments.of(new byte[] {}, ""), Arguments.of(new byte[] { (byte) 0x00 }, "00"),
                Arguments.of(new byte[] { (byte) 0x0F }, "0f"), Arguments.of(new byte[] { (byte) 0x10 }, "10"),
                Arguments.of(new byte[] { (byte) 0xAB }, "ab"),
                Arguments.of(new byte[] { (byte) 0x7F, (byte) 0x80, (byte) 0xFF }, "7f80ff"));
    }

    // Verifies that toString() formats bytes as lower-case hex with zero-padding
    @ParameterizedTest(name = "toString renders hex for {0}")
    @MethodSource("hexCases")
    @DisplayName("toString() renders lower-case hex with zero-padding")
    void toString_rendersHex(byte[] input, String expected) {
        // Arrange
        SecurityBlob blob = new SecurityBlob(input);

        // Act
        String actual = blob.toString();

        // Assert
        assertEquals(expected, actual, "Hex string should match expected format");
    }

    // Ensures a default-constructed blob starts empty and stable across APIs
    @Test
    @DisplayName("Default constructor yields empty state")
    void defaultConstructor_initialState() {
        // Arrange & Act
        SecurityBlob blob = new SecurityBlob();

        // Assert
        assertNotNull(blob.get(), "get() should never return null for default instance");
        assertEquals(0, blob.get().length, "Internal array should be empty");
        assertEquals(0, blob.length(), "length() should be 0 for empty");
        assertEquals("", blob.toString(), "toString() of empty should be empty string");
        assertTrue(blob.equals(blob), "Object should be equal to itself");
        assertEquals(blob.get().hashCode(), blob.hashCode(), "hashCode should delegate to internal array");
    }

    // Confirms constructor handles null by producing an empty buffer
    @Test
    @DisplayName("Constructor with null sets empty buffer")
    void constructor_withNull_setsEmpty() {
        // Arrange & Act
        SecurityBlob blob = new SecurityBlob(null);

        // Assert
        assertNotNull(blob.get(), "Internal array should be non-null");
        assertEquals(0, blob.length(), "length() should be 0 when constructed with null");
        assertEquals("", blob.toString(), "toString() should be empty for empty buffer");
    }

    // Ensures set(null) resets the buffer to empty and does not NPE
    @Test
    @DisplayName("set(null) resets to empty")
    void set_null_resetsToEmpty() {
        // Arrange
        SecurityBlob blob = new SecurityBlob(new byte[] { 1, 2, 3 });

        // Act
        blob.set(null);

        // Assert
        assertNotNull(blob.get(), "get() should return non-null after set(null)");
        assertEquals(0, blob.length(), "length() should be 0 after set(null)");
        assertEquals("", blob.toString(), "toString() should be empty after set(null)");
    }

    // Verifies constructor stores the exact array reference and exposes it via get()
    @Test
    @DisplayName("Constructor stores and exposes same array reference")
    void constructor_and_get_referenceSemantics() {
        // Arrange
        byte[] data = new byte[] { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF };

        // Act
        SecurityBlob blob = new SecurityBlob(data);

        // Assert
        assertSame(data, blob.get(), "get() should expose the same array reference passed in");
        assertEquals(data.length, blob.length(), "length() should match underlying array length");
        assertEquals("deadbeef", blob.toString(), "toString() should reflect underlying content");
        assertEquals(data.hashCode(), blob.hashCode(), "hashCode should equal the array's hashCode");
    }

    // Validates equals() returns true for same-sized, equal-content blobs
    @Test
    @DisplayName("equals: identical content and size -> true")
    void equals_identicalContent_true() {
        // Arrange
        byte[] a = new byte[] { 1, 2, 3 };
        byte[] b = new byte[] { 1, 2, 3 };
        SecurityBlob left = new SecurityBlob(a);
        SecurityBlob right = new SecurityBlob(b);

        // Act & Assert
        assertTrue(left.equals(right), "Blobs with equal content should be equal");
        assertTrue(right.equals(left), "Equality should be symmetric for identical content");
    }

    // Demonstrates observed equals() asymmetry when this is shorter than argument
    @Test
    @DisplayName("equals: this shorter but same prefix -> true (observed behavior)")
    void equals_thisShorterSamePrefix_true_dueToImplementation() {
        // Arrange: left shorter than right but with identical prefix
        SecurityBlob shorter = new SecurityBlob(new byte[] { 1, 2 });
        SecurityBlob longer = new SecurityBlob(new byte[] { 1, 2, 9 });

        // Act & Assert
        // Due to implementation, iteration uses this.b.length and ignores extra bytes in argument
        assertTrue(shorter.equals(longer), "Shorter equals longer when prefix matches (implementation behavior)");

        // In the opposite direction, an out-of-bounds occurs internally and is caught as false
        assertFalse(longer.equals(shorter), "Longer does not equal shorter (implementation behavior)");
    }

    // Confirms equals() returns false when content differs
    @Test
    @DisplayName("equals: different content -> false")
    void equals_differentContent_false() {
        // Arrange
        SecurityBlob a = new SecurityBlob(new byte[] { 1, 2, 3 });
        SecurityBlob b = new SecurityBlob(new byte[] { 1, 9, 3 });

        // Act & Assert
        assertFalse(a.equals(b), "Different content should not be equal");
    }

    // Confirms equals() rejects null and different types
    @Test
    @DisplayName("equals: null or different type -> false")
    void equals_nullAndDifferentType_false() {
        // Arrange
        SecurityBlob a = new SecurityBlob(new byte[] { 1 });

        // Act & Assert
        assertFalse(a.equals(null), "equals(null) should be false");
        assertFalse(a.equals("not a blob"), "equals(other type) should be false");
    }

    // Ensures clone() returns a deep copy; mutations are independent across instances
    @Test
    @DisplayName("clone: returns deep copy and independent state")
    void clone_returnsDeepCopy() {
        // Arrange
        byte[] data = new byte[] { 10, 20, 30 };
        SecurityBlob original = new SecurityBlob(data);

        // Act
        SecurityBlob copy = assertDoesNotThrow(() -> (SecurityBlob) original.clone(), "clone() should not throw");

        // Assert
        assertNotSame(original, copy, "clone should return a different instance");
        assertTrue(original.equals(copy), "Cloned instance should be equal by content");

        // Mutate original backing array; clone should remain based on previous snapshot
        data[0] = 99;
        assertFalse(original.equals(copy), "After mutation, original should not equal previous clone");

        // Ensure arrays are independent: mutate clone's buffer via getter
        copy.get()[1] = 77;
        assertNotEquals(original.toString(), copy.toString(), "Mutating clone should not affect original");
    }

    // Uses reflection to set internal array to null to exercise defensive branch in length()
    @Test
    @DisplayName("length(): handles internal null defensively")
    void length_handlesNullInternalArray() throws Exception {
        // Arrange
        SecurityBlob blob = new SecurityBlob(new byte[] { 1, 2, 3 });

        // Force internal field to null via reflection to exercise defensive branch
        Field field = SecurityBlob.class.getDeclaredField("b");
        field.setAccessible(true);
        field.set(blob, null);

        // Act & Assert
        assertEquals(0, blob.length(), "length() should return 0 when internal array is null");
    }

    @Spy
    SecurityBlob spyBlob = new SecurityBlob();

    // Illustrates Mockito interaction verification by spying on set() and validating behavior
    @Test
    @DisplayName("Mockito spy: verify set() interaction and resulting behavior")
    void spy_verifySetInteraction() {
        // Arrange
        byte[] payload = new byte[] { 5, 6 };

        // Act
        spyBlob.set(payload);

        // Assert
        verify(spyBlob, times(1)).set(payload);
        assertSame(payload, spyBlob.get(), "Spy should behave like real object exposing same array");
        assertEquals(2, spyBlob.length(), "length() should reflect the set payload length");
    }
}
