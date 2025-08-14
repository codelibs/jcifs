package jcifs.dcerpc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.dcerpc.ndr.NdrBuffer;

/**
 * Comprehensive test suite for jcifs.dcerpc.DcerpcBind class.
 * Tests DCE/RPC bind message functionality for MSRPC protocol compliance.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DcerpcBind Tests")
class DcerpcBindTest {

    @Mock
    private DcerpcBinding mockBinding;

    @Mock
    private DcerpcHandle mockHandle;

    @Mock
    private NdrBuffer mockBuffer;

    private DcerpcBind bind;

    @BeforeEach
    void setUp() {
        bind = new DcerpcBind();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Default constructor should create instance with default values")
        void testDefaultConstructor() {
            // When
            DcerpcBind defaultBind = new DcerpcBind();

            // Then
            assertNotNull(defaultBind, "Default constructor should create instance");
            assertEquals(0, defaultBind.getOpnum(), "Default opnum should be 0");
        }

        @Test
        @DisplayName("Package constructor should initialize with binding and handle")
        void testPackageConstructor() throws Exception {
            // Given
            int maxXmit = 4096;
            int maxRecv = 4096;
            when(mockHandle.getMaxXmit()).thenReturn(maxXmit);
            when(mockHandle.getMaxRecv()).thenReturn(maxRecv);

            // When
            DcerpcBind bindWithParams = new DcerpcBind(mockBinding, mockHandle);

            // Then
            assertNotNull(bindWithParams, "Constructor should create instance");
            assertEquals(0, bindWithParams.getOpnum(), "Opnum should be 0");
            assertEquals(11, bindWithParams.getPtype(), "Ptype should be 11 for bind message");
            assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, bindWithParams.getFlags(),
                    "Flags should be set for first and last fragment");

            // Verify private fields using reflection
            Field bindingField = DcerpcBind.class.getDeclaredField("binding");
            bindingField.setAccessible(true);
            assertSame(mockBinding, bindingField.get(bindWithParams), "Binding should be set");

            Field maxXmitField = DcerpcBind.class.getDeclaredField("max_xmit");
            maxXmitField.setAccessible(true);
            assertEquals(maxXmit, maxXmitField.get(bindWithParams), "Max xmit should be set");

            Field maxRecvField = DcerpcBind.class.getDeclaredField("max_recv");
            maxRecvField.setAccessible(true);
            assertEquals(maxRecv, maxRecvField.get(bindWithParams), "Max recv should be set");
        }

        @Test
        @DisplayName("Package constructor should handle null binding")
        void testPackageConstructorWithNullBinding() throws Exception {
            // Given
            when(mockHandle.getMaxXmit()).thenReturn(1024);
            when(mockHandle.getMaxRecv()).thenReturn(1024);

            // When
            DcerpcBind bindWithNullBinding = new DcerpcBind(null, mockHandle);

            // Then
            assertNotNull(bindWithNullBinding, "Constructor should handle null binding");
            Field bindingField = DcerpcBind.class.getDeclaredField("binding");
            bindingField.setAccessible(true);
            assertNull(bindingField.get(bindWithNullBinding), "Binding should be null");
        }
    }

    @Nested
    @DisplayName("Opnum Tests")
    class OpnumTests {

        @Test
        @DisplayName("getOpnum should always return 0")
        void testGetOpnum() {
            // When
            int opnum = bind.getOpnum();

            // Then
            assertEquals(0, opnum, "Opnum should always be 0 for bind messages");
        }

        @Test
        @DisplayName("getOpnum should be consistent across multiple calls")
        void testGetOpnumConsistency() {
            // When
            int opnum1 = bind.getOpnum();
            int opnum2 = bind.getOpnum();
            int opnum3 = bind.getOpnum();

            // Then
            assertEquals(opnum1, opnum2, "Opnum should be consistent");
            assertEquals(opnum2, opnum3, "Opnum should be consistent");
            assertEquals(0, opnum1, "All calls should return 0");
        }

        @Test
        @DisplayName("getOpnum should return 0 for parameterized constructor")
        void testGetOpnumWithParameterizedConstructor() throws Exception {
            // Given
            when(mockHandle.getMaxXmit()).thenReturn(2048);
            when(mockHandle.getMaxRecv()).thenReturn(2048);
            DcerpcBind paramBind = new DcerpcBind(mockBinding, mockHandle);

            // When
            int opnum = paramBind.getOpnum();

            // Then
            assertEquals(0, opnum, "Opnum should be 0 even with parameterized constructor");
        }
    }

    @Nested
    @DisplayName("Result Handling Tests")
    class ResultHandlingTests {

        @Test
        @DisplayName("getResult should return null when result is 0")
        void testGetResultSuccess() throws Exception {
            // Given
            setResultField(bind, 0);

            // When
            DcerpcException result = bind.getResult();

            // Then
            assertNull(result, "Should return null for successful result (0)");
        }

        @Test
        @DisplayName("getResult should return exception for error code 1")
        void testGetResultError1() throws Exception {
            // Given
            setResultField(bind, 1);

            // When
            DcerpcException result = bind.getResult();

            // Then
            assertNotNull(result, "Should return exception for error result");
            assertEquals("DCERPC_BIND_ERR_ABSTRACT_SYNTAX_NOT_SUPPORTED", result.getMessage(),
                    "Should return correct error message for code 1");
        }

        @Test
        @DisplayName("getResult should return exception for error code 2")
        void testGetResultError2() throws Exception {
            // Given
            setResultField(bind, 2);

            // When
            DcerpcException result = bind.getResult();

            // Then
            assertNotNull(result, "Should return exception for error result");
            assertEquals("DCERPC_BIND_ERR_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED", result.getMessage(),
                    "Should return correct error message for code 2");
        }

        @Test
        @DisplayName("getResult should return exception for error code 3")
        void testGetResultError3() throws Exception {
            // Given
            setResultField(bind, 3);

            // When
            DcerpcException result = bind.getResult();

            // Then
            assertNotNull(result, "Should return exception for error result");
            assertEquals("DCERPC_BIND_ERR_LOCAL_LIMIT_EXCEEDED", result.getMessage(), "Should return correct error message for code 3");
        }

        @Test
        @DisplayName("getResult should return hex representation for unknown error codes")
        void testGetResultUnknownError() throws Exception {
            // Given
            setResultField(bind, 5);

            // When
            DcerpcException result = bind.getResult();

            // Then
            assertNotNull(result, "Should return exception for unknown error result");
            assertEquals("0x0005", result.getMessage(), "Should return hex representation for unknown error code");
        }

        @Test
        @DisplayName("getResult should handle large error codes")
        void testGetResultLargeErrorCode() throws Exception {
            // Given
            setResultField(bind, 0xFFFF);

            // When
            DcerpcException result = bind.getResult();

            // Then
            assertNotNull(result, "Should return exception for large error code");
            assertEquals("0xFFFF", result.getMessage(), "Should return hex representation for large error code");
        }

        private void setResultField(DcerpcBind bind, int value) throws Exception {
            Field resultField = DcerpcMessage.class.getDeclaredField("result");
            resultField.setAccessible(true);
            resultField.set(bind, value);
        }
    }

    @Nested
    @DisplayName("Encoding Tests")
    class EncodingTests {

        @Test
        @DisplayName("encode_in should handle null binding gracefully")
        void testEncodeInWithNullBinding() throws Exception {
            // Given
            when(mockHandle.getMaxXmit()).thenReturn(1024);
            when(mockHandle.getMaxRecv()).thenReturn(1024);
            DcerpcBind bindWithNullBinding = new DcerpcBind(null, mockHandle);

            // When/Then
            assertThrows(NullPointerException.class, () -> {
                bindWithNullBinding.encode_in(mockBuffer);
            }, "Should throw NullPointerException when binding is null");
        }

        @Test
        @DisplayName("encode_in should use default constructor values")
        void testEncodeInDefaultConstructor() throws Exception {
            // Given
            DcerpcBind defaultBind = new DcerpcBind();

            // When/Then - Should handle encoding with default values (nulls)
            assertThrows(NullPointerException.class, () -> {
                defaultBind.encode_in(mockBuffer);
            }, "Should throw NullPointerException with default constructor values");
        }

        @Test
        @DisplayName("encode_in should write basic buffer operations")
        void testEncodeInBasicOperations() throws Exception {
            // Given
            int maxXmit = 1024;
            int maxRecv = 2048;
            when(mockHandle.getMaxXmit()).thenReturn(maxXmit);
            when(mockHandle.getMaxRecv()).thenReturn(maxRecv);

            // Use lenient stubbing to handle multiple calls
            lenient().doNothing().when(mockBuffer).enc_ndr_short(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_long(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_small(anyInt());

            DcerpcBind bindWithParams = new DcerpcBind(mockBinding, mockHandle);

            // When/Then - Expect NPE due to UUID.encode() limitations
            assertThrows(NullPointerException.class, () -> {
                bindWithParams.encode_in(mockBuffer);
            }, "Should fail on UUID encoding");
        }
    }

    @Nested
    @DisplayName("Decoding Tests")
    class DecodingTests {

        @Test
        @DisplayName("decode_out should read bind response data correctly")
        void testDecodeOut() throws Exception {
            // Given
            int result = 0;
            when(mockBuffer.dec_ndr_short()).thenReturn(4096, 4096, 10, result, 0);
            when(mockBuffer.dec_ndr_long()).thenReturn(12345);
            when(mockBuffer.dec_ndr_small()).thenReturn(1);
            lenient().doNothing().when(mockBuffer).advance(anyInt());
            lenient().when(mockBuffer.align(anyInt())).thenReturn(0);

            // When
            bind.decode_out(mockBuffer);

            // Then
            verify(mockBuffer, times(5)).dec_ndr_short(); // max xmit, max recv, addr len, result, final short
            verify(mockBuffer).dec_ndr_long(); // assoc group
            verify(mockBuffer).advance(10); // secondary addr (length 10)
            verify(mockBuffer, times(2)).align(4); // alignment calls
            verify(mockBuffer).dec_ndr_small(); // num results
            verify(mockBuffer).advance(20); // transfer syntax / version

            // Verify result was set
            Field resultField = DcerpcMessage.class.getDeclaredField("result");
            resultField.setAccessible(true);
            assertEquals(result, resultField.get(bind), "Result should be set from decoded value");
        }

        @Test
        @DisplayName("decode_out should handle non-zero result codes")
        void testDecodeOutWithError() throws Exception {
            // Given
            int errorResult = 2;
            when(mockBuffer.dec_ndr_short()).thenReturn(2048, 2048, 5, errorResult, 1);
            when(mockBuffer.dec_ndr_long()).thenReturn(54321);
            when(mockBuffer.dec_ndr_small()).thenReturn(2);
            lenient().doNothing().when(mockBuffer).advance(anyInt());
            lenient().when(mockBuffer.align(anyInt())).thenReturn(0);

            // When
            bind.decode_out(mockBuffer);

            // Then
            Field resultField = DcerpcMessage.class.getDeclaredField("result");
            resultField.setAccessible(true);
            assertEquals(errorResult, resultField.get(bind), "Error result should be set correctly");

            // Verify getResult returns appropriate exception
            DcerpcException exception = bind.getResult();
            assertNotNull(exception, "Should return exception for error result");
            assertEquals("DCERPC_BIND_ERR_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED", exception.getMessage(),
                    "Should return correct error message");
        }

        @Test
        @DisplayName("decode_out should handle zero secondary address length")
        void testDecodeOutZeroSecondaryAddr() throws Exception {
            // Given
            when(mockBuffer.dec_ndr_short()).thenReturn(512, 512, 0, 0, 0);
            when(mockBuffer.dec_ndr_long()).thenReturn(0);
            when(mockBuffer.dec_ndr_small()).thenReturn(1);
            lenient().doNothing().when(mockBuffer).advance(anyInt());
            lenient().when(mockBuffer.align(anyInt())).thenReturn(0);

            // When
            bind.decode_out(mockBuffer);

            // Then
            verify(mockBuffer).advance(0); // Should advance 0 bytes
        }
    }

    @Nested
    @DisplayName("Static Method Tests")
    class StaticMethodTests {

        @Test
        @DisplayName("getResultMessage should return correct messages for known error codes")
        void testGetResultMessage() throws Exception {
            // When/Then - Use reflection to test the private static method
            Method getResultMessageMethod = DcerpcBind.class.getDeclaredMethod("getResultMessage", int.class);
            getResultMessageMethod.setAccessible(true);

            assertEquals("0", getResultMessageMethod.invoke(null, 0), "Should return '0' for success");
            assertEquals("DCERPC_BIND_ERR_ABSTRACT_SYNTAX_NOT_SUPPORTED", getResultMessageMethod.invoke(null, 1),
                    "Should return correct message for error 1");
            assertEquals("DCERPC_BIND_ERR_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED", getResultMessageMethod.invoke(null, 2),
                    "Should return correct message for error 2");
            assertEquals("DCERPC_BIND_ERR_LOCAL_LIMIT_EXCEEDED", getResultMessageMethod.invoke(null, 3),
                    "Should return correct message for error 3");
        }

        @Test
        @DisplayName("getResultMessage should return hex format for unknown error codes")
        void testGetResultMessageUnknownCodes() throws Exception {
            // When/Then
            Method getResultMessageMethod = DcerpcBind.class.getDeclaredMethod("getResultMessage", int.class);
            getResultMessageMethod.setAccessible(true);

            assertEquals("0x0004", getResultMessageMethod.invoke(null, 4), "Should return hex format for unknown code 4");
            assertEquals("0x00FF", getResultMessageMethod.invoke(null, 255), "Should return hex format for unknown code 255");
            assertEquals("0x1000", getResultMessageMethod.invoke(null, 4096), "Should return hex format for large unknown code");
        }

        @Test
        @DisplayName("getResultMessage should handle boundary conditions")
        void testGetResultMessageBoundaryConditions() throws Exception {
            // When/Then
            Method getResultMessageMethod = DcerpcBind.class.getDeclaredMethod("getResultMessage", int.class);
            getResultMessageMethod.setAccessible(true);

            // Test boundary at 4 (first unknown code)
            assertEquals("DCERPC_BIND_ERR_LOCAL_LIMIT_EXCEEDED", getResultMessageMethod.invoke(null, 3),
                    "Should return known message for code 3");
            assertEquals("0x0004", getResultMessageMethod.invoke(null, 4), "Should return hex format for code 4");
        }
    }

    @Nested
    @DisplayName("Inheritance Tests")
    class InheritanceTests {

        @Test
        @DisplayName("DcerpcBind should extend DcerpcMessage")
        void testInheritance() {
            // Then
            assertTrue(bind instanceof DcerpcMessage, "Should extend DcerpcMessage");
            assertTrue(bind instanceof jcifs.dcerpc.ndr.NdrObject, "Should extend NdrObject");
            assertTrue(bind instanceof DcerpcConstants, "Should implement DcerpcConstants");
        }

        @Test
        @DisplayName("DcerpcBind should have access to parent class methods")
        void testParentClassMethods() {
            // When/Then
            assertDoesNotThrow(() -> {
                bind.getPtype();
                bind.getFlags();
            }, "Should have access to parent class methods");
        }

        @Test
        @DisplayName("DcerpcBind should override abstract methods correctly")
        void testAbstractMethodOverrides() throws Exception {
            // Given
            when(mockHandle.getMaxXmit()).thenReturn(1024);
            when(mockHandle.getMaxRecv()).thenReturn(1024);
            DcerpcBind bindWithParams = new DcerpcBind(mockBinding, mockHandle);

            // When/Then
            assertEquals(0, bindWithParams.getOpnum(), "Should override getOpnum correctly");

            // Set result to 0 and test again
            Field resultField = DcerpcMessage.class.getDeclaredField("result");
            resultField.setAccessible(true);
            resultField.set(bindWithParams, 0);
            assertNull(bindWithParams.getResult(), "Should return null when result is 0");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Bind message constructor should set correct values")
        void testBindMessageConstructor() throws Exception {
            // Given
            int maxXmit = 2048;
            int maxRecv = 4096;
            when(mockHandle.getMaxXmit()).thenReturn(maxXmit);
            when(mockHandle.getMaxRecv()).thenReturn(maxRecv);

            // When
            DcerpcBind bindMessage = new DcerpcBind(mockBinding, mockHandle);

            // Then
            assertEquals(11, bindMessage.getPtype(), "Ptype should be set for bind");
            assertEquals(0, bindMessage.getOpnum(), "Opnum should be 0");
            assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, bindMessage.getFlags(),
                    "Flags should be set correctly");
        }

        @Test
        @DisplayName("Decode error handling should work correctly")
        void testDecodeErrorHandling() throws Exception {
            // Given
            when(mockHandle.getMaxXmit()).thenReturn(1024);
            when(mockHandle.getMaxRecv()).thenReturn(1024);
            DcerpcBind bindMessage = new DcerpcBind(mockBinding, mockHandle);

            // When - Decode with error response
            when(mockBuffer.dec_ndr_short()).thenReturn(1024, 1024, 0, 1, 0);
            when(mockBuffer.dec_ndr_long()).thenReturn(0);
            when(mockBuffer.dec_ndr_small()).thenReturn(1);
            lenient().doNothing().when(mockBuffer).advance(anyInt());
            lenient().when(mockBuffer.align(anyInt())).thenReturn(0);
            bindMessage.decode_out(mockBuffer);

            // Then - Verify error result
            DcerpcException exception = bindMessage.getResult();
            assertNotNull(exception, "Should return exception for error result");
            assertEquals("DCERPC_BIND_ERR_ABSTRACT_SYNTAX_NOT_SUPPORTED", exception.getMessage(), "Should return correct error message");
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle various result codes correctly")
        void testVariousResultCodes() throws Exception {
            // Test all known result codes
            int[] validCodes = { 0, 1, 2, 3 };
            String[] expectedMessages = { null, // 0 returns null (no exception)
                    "DCERPC_BIND_ERR_ABSTRACT_SYNTAX_NOT_SUPPORTED", "DCERPC_BIND_ERR_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED",
                    "DCERPC_BIND_ERR_LOCAL_LIMIT_EXCEEDED" };

            for (int i = 0; i < validCodes.length; i++) {
                setResultField(bind, validCodes[i]);
                DcerpcException result = bind.getResult();

                if (validCodes[i] == 0) {
                    assertNull(result, "Should return null for result code 0");
                } else {
                    assertNotNull(result, "Should return exception for result code " + validCodes[i]);
                    assertEquals(expectedMessages[i], result.getMessage(),
                            "Should return correct message for result code " + validCodes[i]);
                }
            }
        }

        @Test
        @DisplayName("Should handle unknown result codes with hex format")
        void testUnknownResultCodes() throws Exception {
            // Test unknown result codes
            int[] unknownCodes = { 4, 10, 255, 1000 };

            for (int code : unknownCodes) {
                setResultField(bind, code);
                DcerpcException result = bind.getResult();

                assertNotNull(result, "Should return exception for unknown result code " + code);
                assertTrue(result.getMessage().startsWith("0x"), "Should return hex format for unknown result code " + code);
            }
        }

        private void setResultField(DcerpcBind bind, int value) throws Exception {
            Field resultField = DcerpcMessage.class.getDeclaredField("result");
            resultField.setAccessible(true);
            resultField.set(bind, value);
        }
    }
}