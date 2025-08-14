package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Unit tests for the {@link TransTransactNamedPipeResponse} class.
 */
class TransTransactNamedPipeResponseTest {

    @Mock
    private SmbNamedPipe mockPipe;

    @Mock
    private TransactNamedPipeInputStream mockPipeIn;

    @InjectMocks
    private TransTransactNamedPipeResponse response;

    @BeforeEach
    void setUp() {
        // Initialize mocks created above
        MockitoAnnotations.openMocks(this);
        // We need to manually inject the mock as we are not using @InjectMocks on the constructor
        response = new TransTransactNamedPipeResponse(mockPipe);
    }

    /**
     * Tests the constructor of {@link TransTransactNamedPipeResponse}.
     */
    @Test
    void testConstructor() {
        // The constructor is called in setUp(), so we just verify the result.
        assertNotNull(response, "The response object should not be null.");
    }

    /**
     * Tests the writeSetupWireFormat method.
     */
    @Test
    void testWriteSetupWireFormat() {
        byte[] dst = new byte[10];
        int result = response.writeSetupWireFormat(dst, 0);
        assertEquals(0, result, "writeSetupWireFormat should always return 0.");
    }

    /**
     * Tests the writeParametersWireFormat method.
     */
    @Test
    void testWriteParametersWireFormat() {
        byte[] dst = new byte[10];
        int result = response.writeParametersWireFormat(dst, 0);
        assertEquals(0, result, "writeParametersWireFormat should always return 0.");
    }

    /**
     * Tests the writeDataWireFormat method.
     */
    @Test
    void testWriteDataWireFormat() {
        byte[] dst = new byte[10];
        int result = response.writeDataWireFormat(dst, 0);
        assertEquals(0, result, "writeDataWireFormat should always return 0.");
    }

    /**
     * Tests the readSetupWireFormat method.
     */
    @Test
    void testReadSetupWireFormat() {
        byte[] buffer = new byte[10];
        int result = response.readSetupWireFormat(buffer, 0, 10);
        assertEquals(0, result, "readSetupWireFormat should always return 0.");
    }

    /**
     * Tests the readParametersWireFormat method.
     */
    @Test
    void testReadParametersWireFormat() {
        byte[] buffer = new byte[10];
        int result = response.readParametersWireFormat(buffer, 0, 10);
        assertEquals(0, result, "readParametersWireFormat should always return 0.");
    }

    /**
     * Tests the readDataWireFormat method when the pipe's input stream is null.
     */
    @Test
    void testReadDataWireFormat_withNullPipeIn() {
        mockPipe.pipeIn = null;
        byte[] buffer = new byte[10];
        int len = 10;
        int result = response.readDataWireFormat(buffer, 0, len);
        assertEquals(len, result, "readDataWireFormat should return the length when pipeIn is null.");
    }

    /**
     * Tests the readDataWireFormat method when the pipe has a valid input stream.
     */
    @Test
    void testReadDataWireFormat_withPipeIn() {
        // Setup the mock pipe and its input stream
        mockPipe.pipeIn = mockPipeIn;
        // The 'lock' field in TransactNamedPipeInputStream needs to be a real object for synchronization
        mockPipeIn.lock = new Object();

        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        int len = 10;

        // Call the method to be tested
        int result = response.readDataWireFormat(buffer, bufferIndex, len);

        // Verify the result
        assertEquals(len, result, "readDataWireFormat should return the length of data read.");

        // Verify that the receive method on the input stream was called exactly once
        verify(mockPipeIn, times(1)).receive(buffer, bufferIndex, len);
    }

    /**
     * Tests the toString method.
     */
    @Test
    void testToString() {
        String result = response.toString();
        assertNotNull(result, "toString() should not return null.");
    }

    // Helper method to access the super.toString() for verification,
    // as we cannot call it directly from the test.
    // This requires a package-private or public method in the class under test,
    // or we can just check for the prefix and suffix.
    // For this test, I'll add a helper in the response class to get super.toString()
    // Or, more simply, check the format of the string.
    @Test
    void testToStringFormat() {
        String str = response.toString();
        assert (str.startsWith("TransTransactNamedPipeResponse["));
        assert (str.endsWith("]"));
    }
}

// We need to add a helper method to TransTransactNamedPipeResponse to make the test more precise
// Or create a visible subclass for testing.
// For now, let's assume we can modify the original class slightly for testability,
// or we accept the less precise testToStringFormat test.

// Let's add a package-private helper to TransTransactNamedPipeResponse:
// String superToString() { return super.toString(); }
// And modify the test to use it.
// Since I cannot modify the original file, I will stick with the format test.
