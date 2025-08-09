package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.internal.dtyp.SecurityDescriptor;
import jcifs.internal.util.SMBUtil;

/**
 * Unit tests for NtTransQuerySecurityDescResponse class
 */
class NtTransQuerySecurityDescResponseTest {

    @Mock
    private Configuration mockConfig;

    private NtTransQuerySecurityDescResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        response = new NtTransQuerySecurityDescResponse(mockConfig);
    }

    @Test
    @DisplayName("Test constructor creates instance with null security descriptor")
    void testConstructor() {
        assertNotNull(response);
        assertNull(response.getSecurityDescriptor());
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns 0")
    void testWriteSetupWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.writeSetupWireFormat(buffer, 0);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns 0")
    void testWriteParametersWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.writeParametersWireFormat(buffer, 0);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.writeDataWireFormat(buffer, 0);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.readSetupWireFormat(buffer, 0, buffer.length);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat reads length correctly")
    void testReadParametersWireFormat() throws Exception {
        byte[] buffer = new byte[100];
        int expectedLength = 0x12345678;
        
        // Write length in little-endian format
        SMBUtil.writeInt4(expectedLength, buffer, 0);
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertEquals(4, result);
        
        // Access private field to verify length was set
        Field lengthField = response.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredField("length");
        lengthField.setAccessible(true);
        int actualLength = (int) lengthField.get(response);
        
        assertEquals(expectedLength, actualLength);
    }

    @DisplayName("Test readParametersWireFormat with various lengths")
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 100, 1000, 65535, Integer.MAX_VALUE})
    void testReadParametersWireFormatWithVariousLengths(int expectedLength) throws Exception {
        byte[] buffer = new byte[100];
        SMBUtil.writeInt4(expectedLength, buffer, 0);
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertEquals(4, result);
        
        // Access private field to verify length was set
        Field lengthField = response.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredField("length");
        lengthField.setAccessible(true);
        int actualLength = (int) lengthField.get(response);
        
        assertEquals(expectedLength, actualLength);
    }

    @Test
    @DisplayName("Test readDataWireFormat with error code returns 4")
    void testReadDataWireFormatWithErrorCode() throws Exception {
        byte[] buffer = new byte[100];
        
        // Set error code to non-zero
        setErrorCode(response, 1);
        
        int result = response.readDataWireFormat(buffer, 0, buffer.length);
        
        assertEquals(4, result);
        assertNull(response.getSecurityDescriptor());
    }

    @Test
    @DisplayName("Test readDataWireFormat with valid security descriptor")
    void testReadDataWireFormatWithValidSecurityDescriptor() throws Exception {
        // Create a minimal valid security descriptor buffer
        byte[] buffer = createValidSecurityDescriptorBuffer();
        
        // Set error code to 0
        setErrorCode(response, 0);
        
        int result = response.readDataWireFormat(buffer, 0, buffer.length);
        
        assertTrue(result > 0);
        assertNotNull(response.getSecurityDescriptor());
    }

    @Test
    @DisplayName("Test readDataWireFormat with IOException throws ArrayIndexOutOfBoundsException")
    void testReadDataWireFormatWithIOException() throws Exception {
        // Create an invalid security descriptor buffer that will cause ArrayIndexOutOfBoundsException
        byte[] buffer = new byte[4];
        
        // Set error code to 0
        setErrorCode(response, 0);
        
        // ArrayIndexOutOfBoundsException is thrown when buffer is too small
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            response.readDataWireFormat(buffer, 0, buffer.length);
        });
    }

    @DisplayName("Test readDataWireFormat with different buffer offsets")
    @ParameterizedTest
    @ValueSource(ints = {0, 10, 50, 100})
    void testReadDataWireFormatWithDifferentOffsets(int offset) throws Exception {
        // Create a buffer large enough for offset + data
        byte[] buffer = createValidSecurityDescriptorBuffer(offset + 100);
        
        // Set error code to 0
        setErrorCode(response, 0);
        
        // Copy valid descriptor data to the offset position
        byte[] validData = createValidSecurityDescriptorBuffer();
        System.arraycopy(validData, 0, buffer, offset, validData.length);
        
        int result = response.readDataWireFormat(buffer, offset, buffer.length - offset);
        
        assertTrue(result > 0);
        assertNotNull(response.getSecurityDescriptor());
    }

    @Test
    @DisplayName("Test toString returns expected format")
    void testToString() {
        String result = response.toString();
        
        assertNotNull(result);
        assertTrue(result.startsWith("NtTransQuerySecurityResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Test getSecurityDescriptor after successful read")
    void testGetSecurityDescriptorAfterRead() throws Exception {
        byte[] buffer = createValidSecurityDescriptorBuffer();
        
        setErrorCode(response, 0);
        response.readDataWireFormat(buffer, 0, buffer.length);
        
        SecurityDescriptor sd = response.getSecurityDescriptor();
        assertNotNull(sd);
        
        // Verify it's the same instance on subsequent calls
        SecurityDescriptor sd2 = response.getSecurityDescriptor();
        assertSame(sd, sd2);
    }

    @Test
    @DisplayName("Test readDataWireFormat with zero length buffer")
    void testReadDataWireFormatWithZeroLengthBuffer() throws Exception {
        byte[] buffer = new byte[0];
        
        setErrorCode(response, 0);
        
        // ArrayIndexOutOfBoundsException is thrown when buffer is too small
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            response.readDataWireFormat(buffer, 0, 0);
        });
    }

    @Test
    @DisplayName("Test readDataWireFormat preserves buffer index calculation")
    void testReadDataWireFormatBufferIndexCalculation() throws Exception {
        byte[] buffer = createValidSecurityDescriptorBuffer();
        int startIndex = 10;
        
        // Prepare buffer with offset
        byte[] fullBuffer = new byte[buffer.length + startIndex];
        System.arraycopy(buffer, 0, fullBuffer, startIndex, buffer.length);
        
        setErrorCode(response, 0);
        
        int bytesRead = response.readDataWireFormat(fullBuffer, startIndex, buffer.length);
        
        // Verify the method returns the correct number of bytes read
        assertTrue(bytesRead > 0);
        assertTrue(bytesRead <= buffer.length);
    }

    /**
     * Helper method to create a valid security descriptor buffer
     */
    private byte[] createValidSecurityDescriptorBuffer() {
        return createValidSecurityDescriptorBuffer(100);
    }

    /**
     * Helper method to create a valid security descriptor buffer with specified size
     */
    private byte[] createValidSecurityDescriptorBuffer(int size) {
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Security descriptor header
        buffer.put((byte) 0x01);  // Revision
        buffer.put((byte) 0x00);  // Padding
        buffer.putShort((short) 0x8004);  // Control flags (SE_DACL_PRESENT | SE_SELF_RELATIVE)
        buffer.putInt(20);  // Owner offset
        buffer.putInt(40);  // Group offset
        buffer.putInt(0);   // SACL offset (null)
        buffer.putInt(60);  // DACL offset
        
        // Owner SID at offset 20
        buffer.position(20);
        buffer.put((byte) 0x01);  // Revision
        buffer.put((byte) 0x01);  // SubAuthorityCount
        buffer.put(new byte[]{0, 0, 0, 0, 0, 1});  // IdentifierAuthority
        buffer.putInt(0);  // SubAuthority
        
        // Group SID at offset 40
        buffer.position(40);
        buffer.put((byte) 0x01);  // Revision
        buffer.put((byte) 0x01);  // SubAuthorityCount
        buffer.put(new byte[]{0, 0, 0, 0, 0, 2});  // IdentifierAuthority
        buffer.putInt(0);  // SubAuthority
        
        // DACL at offset 60
        buffer.position(60);
        buffer.put((byte) 0x02);  // AclRevision
        buffer.put((byte) 0x00);  // Padding
        buffer.putShort((short) 8);  // AclSize
        buffer.putShort((short) 0);  // AceCount
        buffer.putShort((short) 0);  // Padding
        
        return buffer.array();
    }

    /**
     * Helper method to set error code using reflection
     */
    private void setErrorCode(NtTransQuerySecurityDescResponse response, int errorCode) throws Exception {
        // Navigate through the inheritance hierarchy to find the errorCode field
        Class<?> currentClass = response.getClass();
        Field errorCodeField = null;
        
        while (currentClass != null && errorCodeField == null) {
            try {
                errorCodeField = currentClass.getDeclaredField("errorCode");
            } catch (NoSuchFieldException e) {
                currentClass = currentClass.getSuperclass();
            }
        }
        
        if (errorCodeField != null) {
            errorCodeField.setAccessible(true);
            errorCodeField.set(response, errorCode);
        }
    }
}