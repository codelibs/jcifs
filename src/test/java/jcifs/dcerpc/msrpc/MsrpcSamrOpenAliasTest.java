package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class MsrpcSamrOpenAliasTest {

    @Mock
    private SamrDomainHandle mockDomainHandle;
    @Mock
    private SamrAliasHandle mockAliasHandle;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Should correctly initialize MsrpcSamrOpenAlias with provided parameters")
    void testConstructorInitialization() {
        // Given
        int access = 0x01; // Example access value
        int rid = 123; // Example RID value

        // When
        MsrpcSamrOpenAlias msrpcSamrOpenAlias = new MsrpcSamrOpenAlias(mockDomainHandle, access, rid, mockAliasHandle);

        // Then
        assertNotNull(msrpcSamrOpenAlias, "MsrpcSamrOpenAlias object should not be null");

        // Verify that ptype and flags are set correctly using reflection
        try {
            java.lang.reflect.Field ptypeField = jcifs.dcerpc.DcerpcMessage.class.getDeclaredField("ptype");
            ptypeField.setAccessible(true);
            assertEquals(0, ptypeField.get(msrpcSamrOpenAlias), "ptype should be initialized to 0");

            java.lang.reflect.Field flagsField = jcifs.dcerpc.DcerpcMessage.class.getDeclaredField("flags");
            flagsField.setAccessible(true);
            assertEquals(0x01 | 0x02, flagsField.get(msrpcSamrOpenAlias),
                    "flags should be initialized to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG");
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Failed to access protected fields via reflection", e);
        }

        // Since SamrOpenAlias's constructor parameters are not directly exposed via getters in MsrpcSamrOpenAlias,
        // we cannot directly verify them here without reflection or extending SamrOpenAlias for testing.
        // However, the primary responsibility of MsrpcSamrOpenAlias's constructor is to call the super constructor
        // and set its own specific fields (ptype, flags).
        // The fact that the object is successfully created implies the super constructor was called.
    }

    // Additional tests could be added here if MsrpcSamrOpenAlias had more methods or complex logic.
    // For this specific class, the constructor is the main point of logic.
}
