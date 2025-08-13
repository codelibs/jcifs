package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.dcerpc.DcerpcConstants;
import jcifs.dcerpc.DcerpcMessage;

@DisplayName("MsrpcSamrConnect2 Tests")
public class MsrpcSamrConnect2Test {

    private SamrPolicyHandle mockPolicyHandle;
    private String testServer;
    private int testAccess;

    @BeforeEach
    void setUp() {
        mockPolicyHandle = mock(SamrPolicyHandle.class);
        testServer = "testServer";
        testAccess = 0x02000000; // SAM_SERVER_CONNECT access right
    }

    @Test
    @DisplayName("Should construct with correct parameters")
    void constructorShouldInitializeFieldsCorrectly() {
        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(testServer, testAccess, mockPolicyHandle);

        // Then
        assertNotNull(msrpcSamrConnect2, "MsrpcSamrConnect2 should be created successfully");
    }

    @Test
    @DisplayName("Should set ptype field to 0")
    void shouldSetPtypeToZero() throws NoSuchFieldException, IllegalAccessException {
        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(testServer, testAccess, mockPolicyHandle);

        // Then - Use reflection to verify protected field
        Field ptypeField = DcerpcMessage.class.getDeclaredField("ptype");
        ptypeField.setAccessible(true);
        int ptypeValue = (int) ptypeField.get(msrpcSamrConnect2);
        assertEquals(0, ptypeValue, "The 'ptype' field should be initialized to 0");
    }

    @Test
    @DisplayName("Should set flags to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG")
    void shouldSetFlagsCorrectly() throws NoSuchFieldException, IllegalAccessException {
        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(testServer, testAccess, mockPolicyHandle);

        // Then - Use reflection to verify protected field
        Field flagsField = DcerpcMessage.class.getDeclaredField("flags");
        flagsField.setAccessible(true);
        int flagsValue = (int) flagsField.get(msrpcSamrConnect2);
        int expectedFlags = DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG;
        assertEquals(expectedFlags, flagsValue, "The 'flags' field should be set to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG");
    }

    @Test
    @DisplayName("Should inherit from samr.SamrConnect2")
    void shouldInheritFromSamrConnect2() {
        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(testServer, testAccess, mockPolicyHandle);

        // Then
        assertTrue(msrpcSamrConnect2 instanceof samr.SamrConnect2, "Should be an instance of samr.SamrConnect2");
        assertTrue(msrpcSamrConnect2 instanceof DcerpcMessage, "Should be an instance of DcerpcMessage");
    }

    @Test
    @DisplayName("Should have correct opnum from parent class")
    void shouldHaveCorrectOpnum() {
        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(testServer, testAccess, mockPolicyHandle);

        // Then
        assertEquals(0x39, msrpcSamrConnect2.getOpnum(), "Should have opnum 0x39 from parent class");
    }

    @Test
    @DisplayName("Should work with null server name")
    void shouldHandleNullServerName() {
        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(null, testAccess, mockPolicyHandle);

        // Then
        assertNotNull(msrpcSamrConnect2, "Should handle null server name");
    }

    @Test
    @DisplayName("Should work with different access masks")
    void shouldWorkWithDifferentAccessMasks() {
        // Test with different access masks
        int[] accessMasks = {
            0x00000001, // SAM_SERVER_CONNECT
            0x00000002, // SAM_SERVER_SHUTDOWN
            0x00000004, // SAM_SERVER_INITIALIZE
            0x00000008, // SAM_SERVER_CREATE_DOMAIN
            0x00000010, // SAM_SERVER_ENUMERATE_DOMAINS
            0x00000020, // SAM_SERVER_LOOKUP_DOMAIN
            0x000F003F, // SAM_SERVER_ALL_ACCESS
            0x02000000  // MAXIMUM_ALLOWED
        };

        for (int accessMask : accessMasks) {
            // When
            MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(testServer, accessMask, mockPolicyHandle);
            
            // Then
            assertNotNull(msrpcSamrConnect2, "Should work with access mask: 0x" + Integer.toHexString(accessMask));
        }
    }

    @Test
    @DisplayName("Should use public methods from DcerpcMessage")
    void shouldUsePublicMethodsFromDcerpcMessage() {
        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(testServer, testAccess, mockPolicyHandle);

        // Then - Test public methods
        assertEquals(0, msrpcSamrConnect2.getPtype(), "getPtype() should return 0");
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, 
                    msrpcSamrConnect2.getFlags(), "getFlags() should return correct flags");
        assertTrue(msrpcSamrConnect2.isFlagSet(DcerpcConstants.DCERPC_FIRST_FRAG), 
                  "DCERPC_FIRST_FRAG should be set");
        assertTrue(msrpcSamrConnect2.isFlagSet(DcerpcConstants.DCERPC_LAST_FRAG), 
                  "DCERPC_LAST_FRAG should be set");
    }
}
