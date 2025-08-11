package jcifs.internal.dtyp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for SecurityInfo interface constants
 */
class SecurityInfoTest {

    @Test
    @DisplayName("Test OWNER_SECURITY_INFO constant value")
    void testOwnerSecurityInfo() {
        assertEquals(0x1, SecurityInfo.OWNER_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test GROUP_SECURITY_INFO constant value")
    void testGroupSecurityInfo() {
        assertEquals(0x2, SecurityInfo.GROUP_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test DACL_SECURITY_INFO constant value")
    void testDaclSecurityInfo() {
        assertEquals(0x4, SecurityInfo.DACL_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test SACL_SECURITY_INFO constant value")
    void testSaclSecurityInfo() {
        assertEquals(0x8, SecurityInfo.SACL_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test LABEL_SECURITY_INFO constant value")
    void testLabelSecurityInfo() {
        assertEquals(0x10, SecurityInfo.LABEL_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test ATTRIBUTE_SECURITY_INFO constant value")
    void testAttributeSecurityInfo() {
        assertEquals(0x20, SecurityInfo.ATTRIBUTE_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test SCOPE_SECURITY_INFO constant value")
    void testScopeSecurityInfo() {
        assertEquals(0x40, SecurityInfo.SCOPE_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test BACKUP_SECURITY_INFO constant value")
    void testBackupSecurityInfo() {
        assertEquals(0x1000, SecurityInfo.BACKUP_SECURITY_INFO);
    }

    @Test
    @DisplayName("Test all constants are public static final")
    void testConstantsArePublicStaticFinal() {
        Field[] fields = SecurityInfo.class.getDeclaredFields();
        
        for (Field field : fields) {
            int modifiers = field.getModifiers();
            assertTrue(Modifier.isPublic(modifiers), 
                "Field " + field.getName() + " should be public");
            assertTrue(Modifier.isStatic(modifiers), 
                "Field " + field.getName() + " should be static");
            assertTrue(Modifier.isFinal(modifiers), 
                "Field " + field.getName() + " should be final");
        }
    }

    @Test
    @DisplayName("Test constant values are unique")
    void testConstantValuesAreUnique() throws IllegalAccessException {
        Field[] fields = SecurityInfo.class.getDeclaredFields();
        Set<Integer> values = new HashSet<>();
        
        for (Field field : fields) {
            if (field.getType() == int.class) {
                int value = field.getInt(null);
                assertTrue(values.add(value), 
                    "Duplicate value found for field: " + field.getName());
            }
        }
    }

    @Test
    @DisplayName("Test constant values follow bit flag pattern")
    void testConstantsBitFlagPattern() {
        // Most values should be powers of 2 for bit flag usage
        assertTrue(isPowerOfTwo(SecurityInfo.OWNER_SECURITY_INFO));
        assertTrue(isPowerOfTwo(SecurityInfo.GROUP_SECURITY_INFO));
        assertTrue(isPowerOfTwo(SecurityInfo.DACL_SECURITY_INFO));
        assertTrue(isPowerOfTwo(SecurityInfo.SACL_SECURITY_INFO));
        assertTrue(isPowerOfTwo(SecurityInfo.LABEL_SECURITY_INFO));
        assertTrue(isPowerOfTwo(SecurityInfo.ATTRIBUTE_SECURITY_INFO));
        assertTrue(isPowerOfTwo(SecurityInfo.SCOPE_SECURITY_INFO));
        assertTrue(isPowerOfTwo(SecurityInfo.BACKUP_SECURITY_INFO));
    }

    @Test
    @DisplayName("Test combining security info flags")
    void testCombiningFlags() {
        // Test that flags can be combined using bitwise OR
        int combined = SecurityInfo.OWNER_SECURITY_INFO | SecurityInfo.GROUP_SECURITY_INFO;
        assertEquals(0x3, combined);
        
        combined = SecurityInfo.DACL_SECURITY_INFO | SecurityInfo.SACL_SECURITY_INFO;
        assertEquals(0xC, combined);
        
        // Test all standard security info combined
        int allStandard = SecurityInfo.OWNER_SECURITY_INFO 
            | SecurityInfo.GROUP_SECURITY_INFO 
            | SecurityInfo.DACL_SECURITY_INFO 
            | SecurityInfo.SACL_SECURITY_INFO;
        assertEquals(0xF, allStandard);
    }

    @Test
    @DisplayName("Test flag checking with bitwise AND")
    void testFlagChecking() {
        int flags = SecurityInfo.OWNER_SECURITY_INFO | SecurityInfo.DACL_SECURITY_INFO;
        
        // Test presence of flags
        assertTrue((flags & SecurityInfo.OWNER_SECURITY_INFO) != 0);
        assertTrue((flags & SecurityInfo.DACL_SECURITY_INFO) != 0);
        
        // Test absence of flags
        assertTrue((flags & SecurityInfo.GROUP_SECURITY_INFO) == 0);
        assertTrue((flags & SecurityInfo.SACL_SECURITY_INFO) == 0);
    }

    @Test
    @DisplayName("Test interface extends Decodable")
    void testExtendsDecodable() {
        Class<?>[] interfaces = SecurityInfo.class.getInterfaces();
        assertTrue(Arrays.asList(interfaces).contains(jcifs.Decodable.class),
            "SecurityInfo should extend Decodable interface");
    }

    @Test
    @DisplayName("Test all constant fields count")
    void testConstantFieldsCount() {
        Field[] fields = SecurityInfo.class.getDeclaredFields();
        long constantCount = Arrays.stream(fields)
            .filter(f -> f.getType() == int.class)
            .filter(f -> Modifier.isStatic(f.getModifiers()))
            .filter(f -> Modifier.isFinal(f.getModifiers()))
            .count();
        
        assertEquals(8, constantCount, "Should have exactly 8 constant fields");
    }

    @Test
    @DisplayName("Test constant naming convention")
    void testConstantNamingConvention() {
        Field[] fields = SecurityInfo.class.getDeclaredFields();
        
        for (Field field : fields) {
            if (field.getType() == int.class) {
                String name = field.getName();
                // Check that constant names follow UPPER_SNAKE_CASE convention
                assertTrue(name.matches("[A-Z_]+"), 
                    "Constant " + name + " should follow UPPER_SNAKE_CASE convention");
                // Check that all constants end with _SECURITY_INFO
                assertTrue(name.endsWith("_SECURITY_INFO"), 
                    "Constant " + name + " should end with _SECURITY_INFO");
            }
        }
    }

    @Test
    @DisplayName("Test SecurityInfo interface is public")
    void testInterfaceIsPublic() {
        int modifiers = SecurityInfo.class.getModifiers();
        assertTrue(Modifier.isPublic(modifiers), 
            "SecurityInfo interface should be public");
        assertTrue(Modifier.isInterface(modifiers), 
            "SecurityInfo should be an interface");
    }

    @Test
    @DisplayName("Test constant values range")
    void testConstantValuesRange() throws IllegalAccessException {
        Field[] fields = SecurityInfo.class.getDeclaredFields();
        
        for (Field field : fields) {
            if (field.getType() == int.class) {
                int value = field.getInt(null);
                // All values should be positive
                assertTrue(value > 0, 
                    "Constant " + field.getName() + " should have positive value");
                // Values should be within reasonable range for security flags
                assertTrue(value <= 0xFFFF, 
                    "Constant " + field.getName() + " value seems unusually large");
            }
        }
    }

    /**
     * Helper method to check if a number is a power of two
     */
    private boolean isPowerOfTwo(int n) {
        return n > 0 && (n & (n - 1)) == 0;
    }
}
