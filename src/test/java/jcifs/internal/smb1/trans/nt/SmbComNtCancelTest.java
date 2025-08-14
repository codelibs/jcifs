package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;

/**
 * Test class for SmbComNtCancel
 * 
 * Tests the SMB1 NT Cancel command implementation
 */
@DisplayName("SmbComNtCancel Tests")
class SmbComNtCancelTest {

    private static final byte SMB_COM_NT_CANCEL = (byte) 0xA4;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        private Configuration mockConfig;

        @BeforeEach
        void setUp() {
            mockConfig = mock(Configuration.class);
            when(mockConfig.getPid()).thenReturn(12345);
        }

        @Test
        @DisplayName("Should initialize with correct command and MID")
        void testConstructorInitialization() throws Exception {
            // Given
            int testMid = 42;

            // When
            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);
            SmbComNtCancel cancel = constructor.newInstance(mockConfig, testMid);

            // Then
            assertNotNull(cancel);
            assertEquals(testMid, cancel.getMid());

            // Verify command is set correctly
            Field commandField = ServerMessageBlock.class.getDeclaredField("command");
            commandField.setAccessible(true);
            assertEquals(SMB_COM_NT_CANCEL, commandField.getByte(cancel));
        }

        @ParameterizedTest
        @ValueSource(ints = { 0, 1, 100, 255, 65535 })
        @DisplayName("Should handle different MID values")
        void testConstructorWithVariousMids(int mid) throws Exception {
            // Given
            Configuration config = mock(Configuration.class);
            when(config.getPid()).thenReturn(12345);

            // When
            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);
            SmbComNtCancel cancel = constructor.newInstance(config, mid);

            // Then
            assertNotNull(cancel);
            assertEquals(mid, cancel.getMid());
        }

        @Test
        @DisplayName("Should throw NullPointerException when config is null")
        void testNullConfigurationThrowsException() throws Exception {
            // Given
            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);

            // When & Then
            InvocationTargetException exception = assertThrows(InvocationTargetException.class, () -> constructor.newInstance(null, 1));
            assertTrue(exception.getCause() instanceof NullPointerException);
        }

        @Test
        @DisplayName("Should work with different PID configuration")
        void testWithDifferentPidConfiguration() throws Exception {
            // Given
            Configuration config = mock(Configuration.class);
            when(config.getPid()).thenReturn(99999);
            int testMid = 10;

            // When
            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);
            SmbComNtCancel cancel = constructor.newInstance(config, testMid);

            // Then
            assertNotNull(cancel);
            assertEquals(testMid, cancel.getMid());
            assertTrue(cancel.isCancel());
        }
    }

    @Nested
    @DisplayName("Method Behavior Tests")
    class MethodBehaviorTests {

        private SmbComNtCancel cancel;
        private Configuration mockConfig;

        @BeforeEach
        void setUp() throws Exception {
            mockConfig = mock(Configuration.class);
            when(mockConfig.getPid()).thenReturn(12345);

            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);
            cancel = constructor.newInstance(mockConfig, 1);
        }

        @Test
        @DisplayName("isCancel should return true")
        void testIsCancelReturnsTrue() {
            assertTrue(cancel.isCancel());
        }

        @Test
        @DisplayName("writeParameterWordsWireFormat should return 0")
        void testWriteParameterWordsReturnsZero() throws Exception {
            // Given
            byte[] dst = new byte[100];
            int dstIndex = 10;

            // When
            Method method = SmbComNtCancel.class.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
            method.setAccessible(true);
            int result = (int) method.invoke(cancel, dst, dstIndex);

            // Then
            assertEquals(0, result);
        }

        @Test
        @DisplayName("writeBytesWireFormat should return 0")
        void testWriteBytesReturnsZero() throws Exception {
            // Given
            byte[] dst = new byte[100];
            int dstIndex = 10;

            // When
            Method method = SmbComNtCancel.class.getDeclaredMethod("writeBytesWireFormat", byte[].class, int.class);
            method.setAccessible(true);
            int result = (int) method.invoke(cancel, dst, dstIndex);

            // Then
            assertEquals(0, result);
        }

        @Test
        @DisplayName("readParameterWordsWireFormat should return 0")
        void testReadParameterWordsReturnsZero() throws Exception {
            // Given
            byte[] buffer = new byte[100];
            int bufferIndex = 10;

            // When
            Method method = SmbComNtCancel.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
            method.setAccessible(true);
            int result = (int) method.invoke(cancel, buffer, bufferIndex);

            // Then
            assertEquals(0, result);
        }

        @Test
        @DisplayName("readBytesWireFormat should return 0")
        void testReadBytesReturnsZero() throws Exception {
            // Given
            byte[] buffer = new byte[100];
            int bufferIndex = 10;

            // When
            Method method = SmbComNtCancel.class.getDeclaredMethod("readBytesWireFormat", byte[].class, int.class);
            method.setAccessible(true);
            int result = (int) method.invoke(cancel, buffer, bufferIndex);

            // Then
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("Wire Format Tests")
    class WireFormatTests {

        private SmbComNtCancel cancel;
        private Configuration mockConfig;

        @BeforeEach
        void setUp() throws Exception {
            mockConfig = mock(Configuration.class);
            when(mockConfig.getPid()).thenReturn(12345);

            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);
            cancel = constructor.newInstance(mockConfig, 1);
        }

        @Test
        @DisplayName("Write operations should not modify destination array")
        void testWriteOperationsDoNotModifyArray() throws Exception {
            // Given
            byte[] originalDst = new byte[100];
            byte[] dst = originalDst.clone();

            // When
            Method writeParams = SmbComNtCancel.class.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
            writeParams.setAccessible(true);
            writeParams.invoke(cancel, dst, 0);

            Method writeBytes = SmbComNtCancel.class.getDeclaredMethod("writeBytesWireFormat", byte[].class, int.class);
            writeBytes.setAccessible(true);
            writeBytes.invoke(cancel, dst, 0);

            // Then - array should remain unchanged
            assertArrayEquals(originalDst, dst);
        }

        @Test
        @DisplayName("Read operations should not modify buffer array")
        void testReadOperationsDoNotModifyArray() throws Exception {
            // Given
            byte[] originalBuffer = new byte[100];
            for (int i = 0; i < originalBuffer.length; i++) {
                originalBuffer[i] = (byte) i;
            }
            byte[] buffer = originalBuffer.clone();

            // When
            Method readParams = SmbComNtCancel.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
            readParams.setAccessible(true);
            readParams.invoke(cancel, buffer, 0);

            Method readBytes = SmbComNtCancel.class.getDeclaredMethod("readBytesWireFormat", byte[].class, int.class);
            readBytes.setAccessible(true);
            readBytes.invoke(cancel, buffer, 0);

            // Then - buffer should remain unchanged
            assertArrayEquals(originalBuffer, buffer);
        }

        @ParameterizedTest
        @ValueSource(ints = { 0, 50, 99 })
        @DisplayName("Should handle various buffer positions correctly")
        void testWireFormatMethodsWithDifferentPositions(int position) throws Exception {
            // Given
            byte[] buffer = new byte[100];

            // Test write parameter words
            Method writeParams = SmbComNtCancel.class.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
            writeParams.setAccessible(true);
            assertEquals(0, writeParams.invoke(cancel, buffer, position));

            // Test write bytes
            Method writeBytes = SmbComNtCancel.class.getDeclaredMethod("writeBytesWireFormat", byte[].class, int.class);
            writeBytes.setAccessible(true);
            assertEquals(0, writeBytes.invoke(cancel, buffer, position));

            // Test read parameter words
            Method readParams = SmbComNtCancel.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
            readParams.setAccessible(true);
            assertEquals(0, readParams.invoke(cancel, buffer, position));

            // Test read bytes
            Method readBytes = SmbComNtCancel.class.getDeclaredMethod("readBytesWireFormat", byte[].class, int.class);
            readBytes.setAccessible(true);
            assertEquals(0, readBytes.invoke(cancel, buffer, position));
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle empty byte arrays")
        void testWithEmptyArrays() throws Exception {
            // Given
            Configuration config = mock(Configuration.class);
            when(config.getPid()).thenReturn(12345);

            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);
            SmbComNtCancel cancel = constructor.newInstance(config, 1);

            byte[] emptyArray = new byte[0];

            // When & Then - should handle gracefully
            Method writeParams = SmbComNtCancel.class.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
            writeParams.setAccessible(true);
            assertEquals(0, writeParams.invoke(cancel, emptyArray, 0));

            Method readParams = SmbComNtCancel.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
            readParams.setAccessible(true);
            assertEquals(0, readParams.invoke(cancel, emptyArray, 0));
        }

        @Test
        @DisplayName("Should handle negative MID values")
        void testWithNegativeMid() throws Exception {
            // Given
            Configuration config = mock(Configuration.class);
            when(config.getPid()).thenReturn(12345);
            int negativeMid = -1;

            // When
            Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
            constructor.setAccessible(true);
            SmbComNtCancel cancel = constructor.newInstance(config, negativeMid);

            // Then
            assertNotNull(cancel);
            assertEquals(negativeMid, cancel.getMid());
        }
    }
}
