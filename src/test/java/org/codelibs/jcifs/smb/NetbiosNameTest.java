package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;

/**
 * Test class for NetbiosName interface functionality
 */
@DisplayName("NetbiosName Tests")
class NetbiosNameTest extends BaseTest {

    @Mock
    private NetbiosName mockNetbiosName;

    @Test
    @DisplayName("Should define interface methods")
    void testNetbiosNameInterface() {
        // Verify interface methods exist
        try {
            assertNotNull(NetbiosName.class.getMethod("getName"));
            assertNotNull(NetbiosName.class.getMethod("getScope"));
            assertNotNull(NetbiosName.class.getMethod("getNameType"));
        } catch (NoSuchMethodException e) {
            fail("Method not found: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("Should handle getName() method")
    void testGetName() {
        // Given
        String testName = "TESTSERVER";
        when(mockNetbiosName.getName()).thenReturn(testName);

        // When
        String name = mockNetbiosName.getName();

        // Then
        assertEquals(testName, name);
        verify(mockNetbiosName).getName();
    }

    @Test
    @DisplayName("Should handle getScope() method")
    void testGetScope() {
        // Given
        String testScope = "WORKGROUP";
        when(mockNetbiosName.getScope()).thenReturn(testScope);

        // When
        String scope = mockNetbiosName.getScope();

        // Then
        assertEquals(testScope, scope);
        verify(mockNetbiosName).getScope();
    }

    @Test
    @DisplayName("Should handle getNameType() method")
    void testGetNameType() {
        // Given
        int testType = 0x20; // Server service
        when(mockNetbiosName.getNameType()).thenReturn(testType);

        // When
        int nameType = mockNetbiosName.getNameType();

        // Then
        assertEquals(testType, nameType);
        verify(mockNetbiosName).getNameType();
    }

    @ParameterizedTest
    @ValueSource(ints = { 0x00, 0x03, 0x06, 0x1B, 0x1C, 0x1D, 0x1E, 0x20 })
    @DisplayName("Should handle various NetBIOS name types")
    void testVariousNameTypes(int nameType) {
        // Given
        when(mockNetbiosName.getNameType()).thenReturn(nameType);

        // When
        int result = mockNetbiosName.getNameType();

        // Then
        assertEquals(nameType, result);
    }

    @Test
    @DisplayName("Should handle null name")
    void testNullName() {
        // Given
        when(mockNetbiosName.getName()).thenReturn(null);

        // When
        String name = mockNetbiosName.getName();

        // Then
        assertNull(name);
    }

    @Test
    @DisplayName("Should handle empty name")
    void testEmptyName() {
        // Given
        when(mockNetbiosName.getName()).thenReturn("");

        // When
        String name = mockNetbiosName.getName();

        // Then
        assertEquals("", name);
    }

    @Test
    @DisplayName("Should handle null scope")
    void testNullScope() {
        // Given
        when(mockNetbiosName.getScope()).thenReturn(null);

        // When
        String scope = mockNetbiosName.getScope();

        // Then
        assertNull(scope);
    }

    @Test
    @DisplayName("Should handle various name lengths")
    void testVariousNameLengths() {
        // NetBIOS names can be up to 15 characters
        String[] testNames = { "A", "SERVER", "LONGSERVERNAME", "EXACTLY15CHARS1" };

        for (String testName : testNames) {
            when(mockNetbiosName.getName()).thenReturn(testName);
            assertEquals(testName, mockNetbiosName.getName());
        }
    }

    @Test
    @DisplayName("Should handle special characters in names")
    void testSpecialCharacters() {
        String[] testNames = { "SERVER-1", "SERVER_A", "SRV123", "MY-SRV" };

        for (String testName : testNames) {
            when(mockNetbiosName.getName()).thenReturn(testName);
            assertEquals(testName, mockNetbiosName.getName());
        }
    }

    @Test
    @DisplayName("Should handle case sensitivity")
    void testCaseSensitivity() {
        // Given
        String upperCase = "SERVER";
        String lowerCase = "server";
        String mixedCase = "Server";

        // Test different cases
        when(mockNetbiosName.getName()).thenReturn(upperCase);
        assertEquals(upperCase, mockNetbiosName.getName());

        when(mockNetbiosName.getName()).thenReturn(lowerCase);
        assertEquals(lowerCase, mockNetbiosName.getName());

        when(mockNetbiosName.getName()).thenReturn(mixedCase);
        assertEquals(mixedCase, mockNetbiosName.getName());
    }

    @Test
    @DisplayName("Should handle workstation service type")
    void testWorkstationServiceType() {
        // Given
        int workstationType = 0x00;
        when(mockNetbiosName.getNameType()).thenReturn(workstationType);

        // When
        int type = mockNetbiosName.getNameType();

        // Then
        assertEquals(workstationType, type);
    }

    @Test
    @DisplayName("Should handle server service type")
    void testServerServiceType() {
        // Given
        int serverType = 0x20;
        when(mockNetbiosName.getNameType()).thenReturn(serverType);

        // When
        int type = mockNetbiosName.getNameType();

        // Then
        assertEquals(serverType, type);
    }

    @Test
    @DisplayName("Should handle browser service type")
    void testBrowserServiceType() {
        // Given
        int browserType = 0x01;
        when(mockNetbiosName.getNameType()).thenReturn(browserType);

        // When
        int type = mockNetbiosName.getNameType();

        // Then
        assertEquals(browserType, type);
    }

    @Test
    @DisplayName("Should handle domain master browser")
    void testDomainMasterBrowser() {
        // Given
        int domainMasterType = 0x1B;
        when(mockNetbiosName.getNameType()).thenReturn(domainMasterType);

        // When
        int type = mockNetbiosName.getNameType();

        // Then
        assertEquals(domainMasterType, type);
    }

    @Test
    @DisplayName("Should be able to mock all interface methods")
    void testMockingAllMethods() {
        // Given
        String testName = "TESTNAME";
        String testScope = "TESTSCOPE";
        int testType = 0x20;

        when(mockNetbiosName.getName()).thenReturn(testName);
        when(mockNetbiosName.getScope()).thenReturn(testScope);
        when(mockNetbiosName.getNameType()).thenReturn(testType);

        // When/Then
        assertEquals(testName, mockNetbiosName.getName());
        assertEquals(testScope, mockNetbiosName.getScope());
        assertEquals(testType, mockNetbiosName.getNameType());

        // Verify all methods were called
        verify(mockNetbiosName).getName();
        verify(mockNetbiosName).getScope();
        verify(mockNetbiosName).getNameType();
    }

    @Test
    @DisplayName("Should handle interface method contracts")
    void testMethodContracts() {
        // The interface should allow for various implementations
        // Test that methods can return any valid values

        // Names can be any string
        when(mockNetbiosName.getName()).thenReturn("ANYNAME");
        assertNotNull(mockNetbiosName.getName());

        // Scope can be null or any string
        when(mockNetbiosName.getScope()).thenReturn(null);
        assertNull(mockNetbiosName.getScope());

        when(mockNetbiosName.getScope()).thenReturn("SCOPE");
        assertEquals("SCOPE", mockNetbiosName.getScope());

        // Name type can be any integer (typically 0-255 for NetBIOS)
        when(mockNetbiosName.getNameType()).thenReturn(255);
        assertEquals(255, mockNetbiosName.getNameType());
    }

}