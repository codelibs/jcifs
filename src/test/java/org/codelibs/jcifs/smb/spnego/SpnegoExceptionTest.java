package org.codelibs.jcifs.smb.spnego;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.codelibs.jcifs.smb.BaseTest;
import org.codelibs.jcifs.smb.CIFSException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for SpnegoException constructors and behavior.
 */
@DisplayName("SpnegoException Tests")
class SpnegoExceptionTest extends BaseTest {

    @Test
    @DisplayName("Should create SpnegoException with default constructor")
    void testDefaultConstructor() {
        // When
        SpnegoException ex = new SpnegoException();

        // Then
        assertNotNull(ex, "Exception should be created");
        assertNull(ex.getMessage(), "Default message should be null");
        assertNull(ex.getCause(), "Default cause should be null");
        assertTrue(ex instanceof CIFSException, "Should be a CIFSException");
        assertTrue(ex instanceof IOException, "Should be an IOException");
    }

    @Test
    @DisplayName("Should create SpnegoException with message")
    void testWithMessage() {
        // Given
        String message = "SPNEGO failed";

        // When
        SpnegoException ex = new SpnegoException(message);

        // Then
        assertNotNull(ex);
        assertEquals(message, ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    @DisplayName("Should create SpnegoException with cause")
    void testWithCause() {
        // Given
        IllegalArgumentException cause = new IllegalArgumentException("bad arg");

        // When
        SpnegoException ex = new SpnegoException(cause);

        // Then
        assertNotNull(ex);
        assertEquals(cause, ex.getCause());
        // IOException(Throwable) sets message to cause.toString()
        assertEquals(cause.toString(), ex.getMessage());
    }

    @Test
    @DisplayName("Should create SpnegoException with message and cause")
    void testWithMessageAndCause() {
        // Given
        String message = "SPNEGO handshake error";
        RuntimeException cause = new RuntimeException("root cause");

        // When
        SpnegoException ex = new SpnegoException(message, cause);

        // Then
        assertNotNull(ex);
        assertEquals(message, ex.getMessage());
        assertEquals(cause, ex.getCause());
    }

    @Test
    @DisplayName("Should handle null message and/or cause without throwing")
    void testNullInputs() {
        assertDoesNotThrow(() -> {
            SpnegoException ex1 = new SpnegoException((String) null);
            assertNotNull(ex1);
            assertNull(ex1.getMessage());
            assertNull(ex1.getCause());
        });

        assertDoesNotThrow(() -> {
            SpnegoException ex2 = new SpnegoException("msg", null);
            assertNotNull(ex2);
            assertEquals("msg", ex2.getMessage());
            assertNull(ex2.getCause());
        });

        assertDoesNotThrow(() -> {
            SpnegoException ex3 = new SpnegoException((Throwable) null);
            assertNotNull(ex3);
            assertNull(ex3.getCause());
            assertNull(ex3.getMessage());
        });
    }

    @Test
    @DisplayName("toString should include class name and message")
    void testToString() {
        // Given
        SpnegoException ex = new SpnegoException("hello");

        // When
        String s = ex.toString();

        // Then
        assertTrue(s.contains("org.codelibs.jcifs.smb.spnego.SpnegoException"));
        assertTrue(s.contains("hello"));
    }

    @Test
    @DisplayName("Should serialize and deserialize preserving message and cause")
    void testJavaSerialization() throws Exception {
        // Given
        SpnegoException original = new SpnegoException("serialize me", new IllegalArgumentException("iaex"));

        // When
        byte[] bytes;
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream(); ObjectOutputStream oout = new ObjectOutputStream(bout)) {
            oout.writeObject(original);
            oout.flush();
            bytes = bout.toByteArray();
        }

        SpnegoException restored;
        try (ByteArrayInputStream bin = new ByteArrayInputStream(bytes); ObjectInputStream oin = new ObjectInputStream(bin)) {
            restored = (SpnegoException) oin.readObject();
        }

        // Then
        assertNotNull(restored);
        assertEquals("serialize me", restored.getMessage());
        assertNotNull(restored.getCause());
        assertEquals(IllegalArgumentException.class, restored.getCause().getClass());
        assertEquals("iaex", restored.getCause().getMessage());
    }
}
