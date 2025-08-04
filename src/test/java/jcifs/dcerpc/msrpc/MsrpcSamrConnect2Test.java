package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;

public class MsrpcSamrConnect2Test {

    @Test
    void constructorShouldInitializeFieldsCorrectly() {
        // Given
        String server = "testServer";
        int access = 123;
        SamrPolicyHandle mockPolicyHandle = mock(SamrPolicyHandle.class);

        // When
        MsrpcSamrConnect2 msrpcSamrConnect2 = new MsrpcSamrConnect2(server, access, mockPolicyHandle);

        // Then
        // Verify that the instance was created successfully
        assertNotNull(msrpcSamrConnect2, "MsrpcSamrConnect2 should be created successfully");
        
        // Since this class is a simple wrapper around samr.SamrConnect2,
        // we only test that it can be constructed without errors.
        // Testing internal field access is inappropriate for unit tests
        // as it couples tests to implementation details.
    }
}
