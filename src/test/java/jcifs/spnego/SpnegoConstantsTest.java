package jcifs.spnego;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for SpnegoConstants interface.
 * Verifies constant values, modifiers, types, and structural properties.
 */
class SpnegoConstantsTest {

    // Simple OID format: numbers separated by dots (at least one dot)
    private static final Pattern OID_PATTERN = Pattern.compile("\\d+(?:\\.\\d+)+");

    @Test
    @DisplayName("Constant values match expected OIDs")
    void constantValues() {
        assertEquals("1.3.6.1.5.5.2", SpnegoConstants.SPNEGO_MECHANISM, "SPNEGO_MECHANISM mismatch");
        assertEquals("1.2.840.113554.1.2.2", SpnegoConstants.KERBEROS_MECHANISM, "KERBEROS_MECHANISM mismatch");
        assertEquals("1.2.840.48018.1.2.2", SpnegoConstants.LEGACY_KERBEROS_MECHANISM, "LEGACY_KERBEROS_MECHANISM mismatch");
        assertEquals("1.3.6.1.4.1.311.2.2.10", SpnegoConstants.NTLMSSP_MECHANISM, "NTLMSSP_MECHANISM mismatch");
    }

    @Test
    @DisplayName("Interface structure is as expected")
    void interfaceStructure() {
        Class<?> c = SpnegoConstants.class;
        assertTrue(c.isInterface(), "SpnegoConstants must be an interface");
        assertEquals(4, c.getDeclaredFields().length, "Unexpected number of fields");
        assertEquals(0, c.getDeclaredMethods().length, "No declared methods expected");
        assertEquals(0, c.getDeclaredConstructors().length, "Interfaces have no constructors");
    }

    @Test
    @DisplayName("Fields are public static final Strings with expected values")
    void fieldModifiersAndTypes() throws Exception {
        Map<String, String> expected = Map.of(
            "SPNEGO_MECHANISM", "1.3.6.1.5.5.2",
            "KERBEROS_MECHANISM", "1.2.840.113554.1.2.2",
            "LEGACY_KERBEROS_MECHANISM", "1.2.840.48018.1.2.2",
            "NTLMSSP_MECHANISM", "1.3.6.1.4.1.311.2.2.10"
        );

        for (Map.Entry<String, String> e : expected.entrySet()) {
            Field f = SpnegoConstants.class.getField(e.getKey());
            int m = f.getModifiers();

            assertTrue(Modifier.isPublic(m), e.getKey() + " must be public");
            assertTrue(Modifier.isStatic(m), e.getKey() + " must be static");
            assertTrue(Modifier.isFinal(m), e.getKey() + " must be final");
            assertEquals(String.class, f.getType(), e.getKey() + " must be String");
            assertEquals(e.getValue(), f.get(null), e.getKey() + " value mismatch");
        }
    }

    @Test
    @DisplayName("OID values have valid dotted numeric format")
    void oidFormat() {
        assertAll(
            () -> assertTrue(OID_PATTERN.matcher(SpnegoConstants.SPNEGO_MECHANISM).matches(), "Invalid OID: SPNEGO_MECHANISM"),
            () -> assertTrue(OID_PATTERN.matcher(SpnegoConstants.KERBEROS_MECHANISM).matches(), "Invalid OID: KERBEROS_MECHANISM"),
            () -> assertTrue(OID_PATTERN.matcher(SpnegoConstants.LEGACY_KERBEROS_MECHANISM).matches(), "Invalid OID: LEGACY_KERBEROS_MECHANISM"),
            () -> assertTrue(OID_PATTERN.matcher(SpnegoConstants.NTLMSSP_MECHANISM).matches(), "Invalid OID: NTLMSSP_MECHANISM")
        );
    }

    @Test
    @DisplayName("Interface cannot be instantiated")
    @SuppressWarnings("deprecation") // Using Class#newInstance for explicit InstantiationException
    void cannotInstantiateInterface() {
        assertThrows(InstantiationException.class, () -> SpnegoConstants.class.newInstance(), "Interfaces cannot be instantiated");
    }
}

