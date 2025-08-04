package jcifs.https;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.http.NtlmHttpURLConnection;

/**
 * Comprehensive test suite for jcifs.https.Handler class.
 * Tests HTTPS URL stream handler functionality with NTLM authentication support.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("HTTPS Handler Tests")
class HandlerTest {

    @Mock
    private CIFSContext mockContext;

    private Handler handler;

    /**
     * Helper method to create a fully configured Handler instance
     */
    private Handler createHandler() {
        return new Handler(mockContext);
    }

    @BeforeEach
    void setUp() {
        handler = createHandler();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor should accept CIFSContext parameter")
        void testConstructor_WithCIFSContext() {
            // Given
            CIFSContext context = mock(CIFSContext.class);

            // When
            Handler handler = new Handler(context);

            // Then
            assertNotNull(handler, "Handler should be created successfully");
        }

        @Test
        @DisplayName("Constructor should accept null CIFSContext")
        void testConstructor_WithNullContext() {
            // When
            Handler handler = new Handler(null);

            // Then
            assertNotNull(handler, "Handler should be created even with null context");
        }

        @Test
        @DisplayName("Constructor should properly initialize inherited properties")
        void testConstructor_InheritanceInitialization() {
            // Given
            CIFSContext context = mock(CIFSContext.class);

            // When
            Handler handler = new Handler(context);

            // Then
            assertNotNull(handler, "Handler should inherit from parent class");
            assertTrue(handler instanceof jcifs.http.Handler, "Handler should extend http.Handler");
        }
    }

    @Nested
    @DisplayName("Default Port Tests")
    class DefaultPortTests {

        @Test
        @DisplayName("getDefaultPort should return HTTPS port 443")
        void testGetDefaultPort_ReturnsHTTPSPort() {
            // When
            int port = handler.getDefaultPort();

            // Then
            assertEquals(443, port, "Default HTTPS port should be 443");
            assertEquals(Handler.DEFAULT_HTTPS_PORT, port, "Should match constant value");
        }

        @Test
        @DisplayName("getDefaultPort should override parent HTTP port")
        void testGetDefaultPort_OverridesParentPort() {
            // When
            int httpsPort = handler.getDefaultPort();
            int httpPort = jcifs.http.Handler.DEFAULT_HTTP_PORT;

            // Then
            assertNotEquals(httpPort, httpsPort, "HTTPS port should differ from HTTP port");
            assertEquals(80, httpPort, "HTTP port should be 80");
            assertEquals(443, httpsPort, "HTTPS port should be 443");
        }

        @Test
        @DisplayName("getDefaultPort should be consistent across multiple calls")
        void testGetDefaultPort_ConsistentResults() {
            // When
            int port1 = handler.getDefaultPort();
            int port2 = handler.getDefaultPort();
            int port3 = handler.getDefaultPort();

            // Then
            assertEquals(port1, port2, "Port should be consistent");
            assertEquals(port2, port3, "Port should be consistent");
            assertEquals(443, port1, "Port should always be 443");
        }
    }

    @Nested
    @DisplayName("Constants Tests")
    class ConstantsTests {

        @Test
        @DisplayName("DEFAULT_HTTPS_PORT should have correct value")
        void testDefaultHTTPSPortConstant() {
            // Then
            assertEquals(443, Handler.DEFAULT_HTTPS_PORT, "DEFAULT_HTTPS_PORT should be 443");
        }

        @Test
        @DisplayName("DEFAULT_HTTPS_PORT should be public static final")
        void testDefaultHTTPSPortAccessibility() throws NoSuchFieldException {
            // When
            var field = Handler.class.getField("DEFAULT_HTTPS_PORT");

            // Then
            assertTrue(java.lang.reflect.Modifier.isPublic(field.getModifiers()), "Field should be public");
            assertTrue(java.lang.reflect.Modifier.isStatic(field.getModifiers()), "Field should be static");
            assertTrue(java.lang.reflect.Modifier.isFinal(field.getModifiers()), "Field should be final");
            assertEquals(int.class, field.getType(), "Field should be int type");
        }
    }

    @Nested
    @DisplayName("Inheritance Tests")
    class InheritanceTests {

        @Test
        @DisplayName("Handler should extend jcifs.http.Handler")
        void testInheritance_ExtendsHttpHandler() {
            // Then
            assertTrue(handler instanceof jcifs.http.Handler, "Should extend http.Handler");
            assertTrue(handler instanceof java.net.URLStreamHandler, "Should extend URLStreamHandler");
        }

        @Test
        @DisplayName("Handler should inherit openConnection method")
        void testInheritance_InheritsOpenConnection() throws NoSuchMethodException {
            // Given
            Handler httpsHandler = new Handler(mockContext);

            // When - Verify inheritance through class hierarchy
            Class<?> parentClass = httpsHandler.getClass().getSuperclass();
            var method = parentClass.getDeclaredMethod("openConnection", URL.class);

            // Then
            assertNotNull(method, "Should inherit openConnection method from parent");
            assertEquals(URLConnection.class, method.getReturnType(), "Should return URLConnection");
            assertEquals(jcifs.http.Handler.class, parentClass, "Parent should be http.Handler");
        }

        @Test
        @DisplayName("Handler should have deprecation annotation")
        void testDeprecationAnnotation() {
            // When
            boolean isDeprecated = Handler.class.isAnnotationPresent(Deprecated.class);

            // Then
            assertTrue(isDeprecated, "Handler class should be marked as @Deprecated");
        }
    }

    @Nested
    @DisplayName("Method Availability Tests")
    class MethodAvailabilityTests {

        @Test
        @DisplayName("Handler should inherit openConnection method")
        void testOpenConnectionMethodExists() throws NoSuchMethodException {
            // When - Check the parent class for the method since https.Handler doesn't override it
            var method = jcifs.http.Handler.class.getDeclaredMethod("openConnection", URL.class);

            // Then
            assertNotNull(method, "openConnection method should exist in parent class");
            assertEquals(URLConnection.class, method.getReturnType(), "Should return URLConnection");
            // Note: Method is protected in parent class
            assertTrue(java.lang.reflect.Modifier.isProtected(method.getModifiers()), 
                      "openConnection should be protected");
            
            // Verify https.Handler can access this inherited method
            assertTrue(jcifs.http.Handler.class.isAssignableFrom(Handler.class),
                      "Handler should inherit from http.Handler and have access to openConnection");
        }

        @Test
        @DisplayName("Handler should have accessible public methods")
        void testPublicMethodsAvailable() throws NoSuchMethodException {
            // Given
            var clazz = Handler.class;

            // When/Then - Verify constructor is public
            var constructor = clazz.getConstructor(CIFSContext.class);
            assertNotNull(constructor, "Public constructor should exist");
            assertTrue(java.lang.reflect.Modifier.isPublic(constructor.getModifiers()), 
                      "Constructor should be public");
        }

        @Test
        @DisplayName("Handler should inherit proper method signatures")
        void testInheritedMethodSignatures() {
            // Given
            var clazz = Handler.class;

            // When/Then
            // Verify it properly extends the parent class
            assertEquals(jcifs.http.Handler.class, clazz.getSuperclass(), 
                        "Should extend jcifs.http.Handler");
            
            // Verify it's a URLStreamHandler
            assertTrue(java.net.URLStreamHandler.class.isAssignableFrom(clazz), 
                      "Should be assignable to URLStreamHandler");
        }
    }

    @Nested
    @DisplayName("JCIFS Specification Compliance Tests")
    class JCIFSComplianceTests {

        @Test
        @DisplayName("Handler should support SMB over HTTPS functionality")
        void testSMBOverHTTPSSupport() {
            // Given
            Handler httpsHandler = new Handler(mockContext);
            
            // When
            int port = httpsHandler.getDefaultPort();
            
            // Then
            assertEquals(443, port, "Should use standard HTTPS port for SMB over HTTPS");
            assertNotNull(httpsHandler, "Handler should be ready for SMB HTTPS operations");
        }

        @Test
        @DisplayName("Handler should maintain CIFSContext for authentication")
        void testCIFSContextIntegration() {
            // Given
            CIFSContext context = mock(CIFSContext.class);
            
            // When
            Handler handler = new Handler(context);
            
            // Then
            assertNotNull(handler, "Handler should properly integrate with CIFSContext");
            // The context is used internally by the parent class for NTLM authentication
        }

        @Test
        @DisplayName("Handler should properly extend HTTP handler for HTTPS")
        void testHTTPSExtension() {
            // Given
            Handler httpsHandler = new Handler(mockContext);
            
            // When
            int httpsPort = httpsHandler.getDefaultPort();
            int httpPort = jcifs.http.Handler.DEFAULT_HTTP_PORT;
            
            // Then
            assertEquals(443, httpsPort, "HTTPS should use port 443");
            assertEquals(80, httpPort, "HTTP should use port 80");
            assertNotEquals(httpsPort, httpPort, "HTTPS and HTTP should use different ports");
        }

        @Test
        @DisplayName("Handler should support NTLM authentication over HTTPS")
        void testNTLMOverHTTPS() {
            // Given
            CIFSContext context = mock(CIFSContext.class);
            Handler handler = new Handler(context);
            
            // When/Then
            // Verify that the handler is properly configured for NTLM over HTTPS
            assertTrue(handler instanceof jcifs.http.Handler, "Should extend HTTP handler with NTLM support");
            assertEquals(443, handler.getDefaultPort(), "Should use HTTPS port for secure NTLM");
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Handler should work with different CIFSContext implementations")
        void testDifferentContextImplementations() {
            // Given
            CIFSContext context1 = mock(CIFSContext.class);
            CIFSContext context2 = mock(CIFSContext.class);
            
            // When
            Handler handler1 = new Handler(context1);
            Handler handler2 = new Handler(context2);
            
            // Then
            assertEquals(handler1.getDefaultPort(), handler2.getDefaultPort(), 
                        "Port should be same regardless of context");
            assertEquals(443, handler1.getDefaultPort(), "Both should use HTTPS port");
            assertEquals(443, handler2.getDefaultPort(), "Both should use HTTPS port");
        }

        @Test
        @DisplayName("Handler should be thread-safe for port operations")
        void testThreadSafety() throws InterruptedException {
            // Given
            Handler handler = new Handler(mockContext);
            int[] results = new int[10];
            Thread[] threads = new Thread[10];
            
            // When
            for (int i = 0; i < 10; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    results[index] = handler.getDefaultPort();
                });
                threads[i].start();
            }
            
            for (Thread thread : threads) {
                thread.join();
            }
            
            // Then
            for (int result : results) {
                assertEquals(443, result, "All threads should get consistent port value");
            }
        }

        @Test
        @DisplayName("Handler should maintain contract after multiple instantiations")
        void testMultipleInstantiations() {
            // When
            Handler[] handlers = new Handler[5];
            for (int i = 0; i < 5; i++) {
                handlers[i] = new Handler(mock(CIFSContext.class));
            }
            
            // Then
            for (Handler h : handlers) {
                assertEquals(443, h.getDefaultPort(), "All instances should return same port");
                assertTrue(h instanceof jcifs.http.Handler, "All should be proper subclasses");
            }
        }
    }
}