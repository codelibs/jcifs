package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.lang.reflect.Modifier;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SessionSetupHandlerTest {

    // Provide two implementations: an anonymous class and a Mockito mock
    static Stream<Arguments> implementations() {
        SessionSetupHandler anon = new SessionSetupHandler() {
            // no methods to implement (marker interface)
        };
        SessionSetupHandler mock = mock(SessionSetupHandler.class);
        return Stream.of(Arguments.of(anon), Arguments.of(mock));
    }

    @Test
    @DisplayName("Class is a public interface in expected package")
    void testPublicInterfaceAndPackage() {
        // Arrange & Act
        Class<SessionSetupHandler> clazz = SessionSetupHandler.class;

        // Assert
        assertTrue(clazz.isInterface(), "Should be an interface");
        assertTrue(Modifier.isPublic(clazz.getModifiers()), "Interface should be public");
        assertEquals("org.codelibs.jcifs.smb.impl", clazz.getPackageName(), "Package must match source");
        assertEquals("SessionSetupHandler", clazz.getSimpleName(), "Simple name must match source");
    }

    @Test
    @DisplayName("Interface declares no methods or fields")
    void testNoMembers() {
        // Assert
        assertEquals(0, SessionSetupHandler.class.getDeclaredMethods().length, "No methods expected");
        assertEquals(0, SessionSetupHandler.class.getDeclaredFields().length, "No fields expected");
        assertEquals(0, SessionSetupHandler.class.getDeclaredClasses().length, "No nested types expected");
    }

    @ParameterizedTest(name = "Implementation is instance: {0}")
    @MethodSource("implementations")
    @DisplayName("Happy path: can create implementations and use type checks")
    void testImplementationsAreUsable(SessionSetupHandler impl) {
        // Arrange is provided by method source

        // Act & Assert
        assertNotNull(impl, "Implementation instance should not be null");
        assertTrue(SessionSetupHandler.class.isInstance(impl), "Instance should be assignable to interface");
        assertTrue(SessionSetupHandler.class.isAssignableFrom(impl.getClass()), "Type should be assignable");
    }

    @Test
    @DisplayName("Edge: null is not an instance of the interface")
    void testNullIsNotInstance() {
        // Assert
        assertFalse(SessionSetupHandler.class.isInstance(null));
    }

    @Test
    @DisplayName("Invalid: looking up constructor on interface fails")
    void testNoConstructorLookup() {
        // Act & Assert: interfaces have no constructors
        assertThrows(NoSuchMethodException.class, () -> SessionSetupHandler.class.getDeclaredConstructor());
    }

    @Test
    @DisplayName("Invalid: resolving class by null name throws NPE")
    void testClassForNameWithNull() {
        // Intent: demonstrate defensive behavior with null when resolving this type by name
        assertThrows(NullPointerException.class, () -> Class.forName(null));
    }

    @Test
    @DisplayName("Happy path: class is loadable via fully qualified name")
    void testClassForName() throws Exception {
        // Act
        Class<?> c = Class.forName("org.codelibs.jcifs.smb.impl.SessionSetupHandler");

        // Assert
        assertEquals(SessionSetupHandler.class, c);
        assertTrue(c.isInterface());
    }

    @Mock
    SessionSetupHandler mocked;

    @Test
    @DisplayName("Interactions: Mockito mock has no interactions by default")
    void testMockitoNoInteractions() {
        // Intent: ensure we can mock the interface and verify no unexpected calls
        // Act & Assert
        assertNotNull(mocked);
        verifyNoInteractions(mocked);
    }
}
