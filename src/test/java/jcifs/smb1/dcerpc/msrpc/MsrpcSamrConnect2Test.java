package jcifs.smb1.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.smb1.dcerpc.DcerpcMessage;
import jcifs.smb1.dcerpc.ndr.NdrObject;

/**
 * Tests for {@link jcifs.smb1.dcerpc.msrpc.MsrpcSamrConnect2} constructor.
 * <p>
 * The class under test is a simple wrapper around the base class that
 * sets internal fields in its constructor.
 * These tests verify that the constructor accepts various parameters
 * without throwing exceptions.
 */
@ExtendWith(MockitoExtension.class)
class MsrpcSamrConnect2Test {

    // Helper method to create a minimal SamrPolicyHandle instance.
    private static SamrPolicyHandle createMockPolicyHandle() {
        return mock(SamrPolicyHandle.class);
    }

    @Nested
    @DisplayName("Constructor parameter handling")
    class ConstructorParameterHandling {

        static Stream<Arguments> provideParameters() {
            return Stream.of(Arguments.of("\\\\example\\\\server", 0x000F0000), Arguments.of(null, 0), Arguments.of("\\\\localhost", -1),
                    Arguments.of("\\\\127.0.0.1", Integer.MAX_VALUE), Arguments.of("", 0x00020000),
                    Arguments.of("\\\\server.domain.com", 0));
        }

        @ParameterizedTest
        @MethodSource("provideParameters")
        @DisplayName("should accept various parameter combinations")
        void testConstructorSucceeds(String systemName, int accessMask) {
            // Arrange
            SamrPolicyHandle ph = createMockPolicyHandle();

            // Act & Assert - constructor should not throw
            assertDoesNotThrow(() -> new MsrpcSamrConnect2(systemName, accessMask, ph));
        }

        @Test
        @DisplayName("should create instance with valid parameters")
        void testConstructorCreatesInstance() {
            // Arrange
            String systemName = "\\\\server";
            int accessMask = 0x000F0000;
            SamrPolicyHandle ph = createMockPolicyHandle();

            // Act
            MsrpcSamrConnect2 msg = new MsrpcSamrConnect2(systemName, accessMask, ph);

            // Assert - instance should be created and extend proper class
            assertNotNull(msg);
            assertTrue(msg instanceof samr.SamrConnect2);
            assertTrue(msg instanceof DcerpcMessage);
        }
    }

    @Nested
    @DisplayName("Edge case handling")
    class EdgeCases {

        @Test
        @DisplayName("should handle null system name")
        void testNullSystemNameDoesNotThrow() {
            // Arrange
            SamrPolicyHandle ph = createMockPolicyHandle();

            // Act & Assert
            assertDoesNotThrow(() -> new MsrpcSamrConnect2(null, 0, ph));
        }

        @Test
        @DisplayName("should accept negative access mask values")
        void testNegativeAccessMaskAccepted() {
            // Arrange
            SamrPolicyHandle ph = createMockPolicyHandle();

            // Act & Assert
            assertDoesNotThrow(() -> new MsrpcSamrConnect2("\\\\srv", -42, ph));
        }

        @Test
        @DisplayName("should handle null policy handle")
        void testNullPolicyHandleHandled() {
            // Act & Assert - The constructor accepts null policy handle without throwing
            assertDoesNotThrow(() -> new MsrpcSamrConnect2("\\\\srv", 0, null));
        }

        @Test
        @DisplayName("should handle empty string as system name")
        void testEmptySystemName() {
            // Arrange
            SamrPolicyHandle ph = createMockPolicyHandle();

            // Act & Assert
            assertDoesNotThrow(() -> new MsrpcSamrConnect2("", 0x000F0000, ph));
        }

        @Test
        @DisplayName("should handle all null parameters")
        void testAllNullParameters() {
            // Act & Assert
            assertDoesNotThrow(() -> new MsrpcSamrConnect2(null, 0, null));
        }
    }

    @Nested
    @DisplayName("Inheritance verification")
    class InheritanceVerification {

        @Test
        @DisplayName("should properly extend base classes")
        void testInheritance() {
            // Arrange
            SamrPolicyHandle ph = createMockPolicyHandle();

            // Act
            MsrpcSamrConnect2 msg = new MsrpcSamrConnect2("\\\\server", 0x000F0000, ph);

            // Assert - verify inheritance chain
            assertTrue(msg instanceof samr.SamrConnect2, "Should extend SamrConnect2");
            assertTrue(msg instanceof DcerpcMessage, "Should extend DcerpcMessage");
            assertTrue(msg instanceof NdrObject, "Should extend NdrObject");
        }

        @Test
        @DisplayName("should inherit getOpnum method")
        void testGetOpnumMethod() {
            // Arrange
            SamrPolicyHandle ph = createMockPolicyHandle();
            MsrpcSamrConnect2 msg = new MsrpcSamrConnect2("\\\\server", 0x000F0000, ph);

            // Act & Assert - getOpnum is inherited from SamrConnect2
            assertDoesNotThrow(() -> msg.getOpnum());
            assertEquals(0x39, msg.getOpnum(), "getOpnum should return 0x39 as defined in SamrConnect2");
        }
    }
}
