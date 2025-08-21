/*
 * © 2025 CodeLibs, Inc.
 */
package jcifs.tests.persistent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import jcifs.internal.smb2.persistent.HandleGuid;

/**
 * Test class for HandleGuid functionality
 */
public class HandleGuidTest {

    @Test
    public void testHandleGuidGeneration() {
        HandleGuid guid1 = new HandleGuid();
        HandleGuid guid2 = new HandleGuid();

        assertNotEquals(guid1, guid2);
        assertEquals(16, guid1.toBytes().length);
        assertEquals(16, guid2.toBytes().length);
    }

    @Test
    public void testHandleGuidRoundTrip() {
        HandleGuid original = new HandleGuid();
        byte[] bytes = original.toBytes();
        HandleGuid reconstructed = new HandleGuid(bytes);

        assertEquals(original, reconstructed);
        assertEquals(original.toString(), reconstructed.toString());
        assertEquals(original.hashCode(), reconstructed.hashCode());
    }

    @Test
    public void testHandleGuidFromUuid() {
        UUID uuid = UUID.randomUUID();
        HandleGuid guid1 = new HandleGuid(uuid);
        HandleGuid guid2 = new HandleGuid(guid1.toBytes());

        assertEquals(guid1, guid2);
        assertEquals(uuid, guid1.getUuid());
    }

    @Test
    public void testHandleGuidInvalidBytes() {
        assertThrows(IllegalArgumentException.class, () -> {
            new HandleGuid(new byte[8]); // Wrong length
        });

        assertThrows(IllegalArgumentException.class, () -> {
            new HandleGuid(new byte[20]); // Wrong length
        });
    }

    @Test
    public void testHandleGuidEqualsAndHashCode() {
        UUID uuid = UUID.randomUUID();
        HandleGuid guid1 = new HandleGuid(uuid);
        HandleGuid guid2 = new HandleGuid(uuid);
        HandleGuid guid3 = new HandleGuid();

        assertEquals(guid1, guid2);
        assertEquals(guid1.hashCode(), guid2.hashCode());
        assertNotEquals(guid1, guid3);
        assertNotEquals(guid1.hashCode(), guid3.hashCode());

        assertNotEquals(guid1, null);
        assertNotEquals(guid1, "not a guid");
    }

    @Test
    public void testHandleGuidToString() {
        UUID uuid = UUID.randomUUID();
        HandleGuid guid = new HandleGuid(uuid);

        assertEquals(uuid.toString(), guid.toString());
    }
}
