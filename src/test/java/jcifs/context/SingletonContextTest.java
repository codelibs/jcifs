package jcifs.context;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;

class SingletonContextTest {

    private static final Logger log = LoggerFactory.getLogger(SingletonContextTest.class);

    // Use reflection to reset the singleton instance between tests
    @BeforeEach
    @AfterEach
    void resetSingleton() {
        try {
            Field instance = SingletonContext.class.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            instance.set(null, null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            log.error("Failed to reset SingletonContext instance", e);
            fail("Failed to reset SingletonContext instance: " + e.getMessage());
        }
        // Clear system properties that might affect the test
        System.clearProperty("jcifs.properties");
        System.clearProperty("java.protocol.handler.pkgs");
    }

    @Test
    void testInitWithNullProperties() throws CIFSException {
        // Test successful initialization with null properties
        assertDoesNotThrow(() -> SingletonContext.init(null));
        assertNotNull(SingletonContext.getInstance());
    }

    @Test
    void testInitWithCustomProperties() throws CIFSException {
        // Test successful initialization with custom properties
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.nativeOs", "CustomOS");
        props.setProperty("jcifs.smb.client.nativeLanMan", "CustomLanman");
        assertDoesNotThrow(() -> SingletonContext.init(props));
        CIFSContext context = SingletonContext.getInstance();
        assertNotNull(context);
        assertEquals("CustomOS", context.getConfig().getNativeOs());
        assertEquals("CustomLanman", context.getConfig().getNativeLanman());
    }

    @Test
    void testInitAlreadyInitializedThrowsException() throws CIFSException {
        // Test attempting to initialize when already initialized
        SingletonContext.init(null);
        CIFSException e = assertThrows(CIFSException.class, () -> SingletonContext.init(null));
        assertEquals("Singleton context is already initialized", e.getMessage());
    }

    @Test
    void testInitLoadsJcifsPropertiesFile(@TempDir Path tempDir) throws IOException, CIFSException {
        // Test that jcifs.properties file is loaded
        Path jcifsPropertiesPath = tempDir.resolve("jcifs.properties");
        Files.writeString(jcifsPropertiesPath, "jcifs.smb.client.nativeOs=FileOS");
        System.setProperty("jcifs.properties", jcifsPropertiesPath.toString());

        SingletonContext.init(null);
        CIFSContext context = SingletonContext.getInstance();
        assertNotNull(context);
        assertEquals("FileOS", context.getConfig().getNativeOs());
    }

    @Test
    void testInitLoadsSystemProperties() throws CIFSException {
        // Test that system properties are loaded
        System.setProperty("jcifs.smb.client.nativeOs", "SystemOS");
        SingletonContext.init(null);
        CIFSContext context = SingletonContext.getInstance();
        assertNotNull(context);
        assertEquals("SystemOS", context.getConfig().getNativeOs());
    }

    @Test
    void testInitPropertyPrecedence(@TempDir Path tempDir) throws IOException, CIFSException {
        // Test property precedence: custom > system > jcifs.properties
        Path jcifsPropertiesPath = tempDir.resolve("jcifs.properties");
        Files.writeString(jcifsPropertiesPath, "jcifs.smb.client.nativeOs=FileOS");
        System.setProperty("jcifs.properties", jcifsPropertiesPath.toString());

        System.setProperty("jcifs.smb.client.nativeOs", "SystemOS");

        Properties customProps = new Properties();
        customProps.setProperty("jcifs.smb.client.nativeOs", "CustomOS");

        SingletonContext.init(customProps);
        CIFSContext context = SingletonContext.getInstance();
        assertNotNull(context);
        assertEquals("CustomOS", context.getConfig().getNativeOs());
    }

    @Test
    void testInitIOExceptionHandling(@TempDir Path tempDir) {
        // Test handling IOException when loading jcifs.properties
        Path nonExistentPath = tempDir.resolve("nonexistent.properties");
        System.setProperty("jcifs.properties", nonExistentPath.toString());

        // Expect no exception to be thrown, but an error logged (which we can't directly assert here)
        assertDoesNotThrow(() -> SingletonContext.init(null));
        assertNotNull(SingletonContext.getInstance()); // Should still initialize
    }

    @Test
    void testGetInstanceInitializesIfNull() {
        // Test getInstance initializes the context if it's null
        assertNull(getSingletonInstanceViaReflection()); // Ensure it's null initially
        CIFSContext context = SingletonContext.getInstance();
        assertNotNull(context);
        assertNotNull(getSingletonInstanceViaReflection()); // Should be initialized now
    }

    @Test
    void testGetInstanceReturnsExistingInstance() throws CIFSException {
        // Test getInstance returns the existing instance
        SingletonContext.init(null);
        CIFSContext firstInstance = SingletonContext.getInstance();
        CIFSContext secondInstance = SingletonContext.getInstance();
        assertSame(firstInstance, secondInstance);
    }

    @Test
    void testRegisterSmbURLHandlerWhenPkgsIsNull() {
        // Test registerSmbURLHandler when java.protocol.handler.pkgs is null
        System.clearProperty("java.protocol.handler.pkgs");
        SingletonContext.registerSmbURLHandler();
        assertEquals("jcifs", System.getProperty("java.protocol.handler.pkgs"));
    }

    @Test
    void testRegisterSmbURLHandlerWhenPkgsDoesNotContainJcifs() {
        // Test registerSmbURLHandler when java.protocol.handler.pkgs does not contain "jcifs"
        System.setProperty("java.protocol.handler.pkgs", "com.example");
        SingletonContext.registerSmbURLHandler();
        assertEquals("com.example|jcifs", System.getProperty("java.protocol.handler.pkgs"));
    }

    @Test
    void testRegisterSmbURLHandlerWhenPkgsAlreadyContainsJcifs() {
        // Test registerSmbURLHandler when java.protocol.handler.pkgs already contains "jcifs"
        System.setProperty("java.protocol.handler.pkgs", "com.example|jcifs|org.test");
        SingletonContext.registerSmbURLHandler();
        assertEquals("com.example|jcifs|org.test", System.getProperty("java.protocol.handler.pkgs"));
    }

    // Helper method to get the singleton instance via reflection for assertion
    private Object getSingletonInstanceViaReflection() {
        try {
            Field instance = SingletonContext.class.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            return instance.get(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            log.error("Failed to get SingletonContext instance via reflection", e);
            fail("Failed to get SingletonContext instance via reflection: " + e.getMessage());
            return null; // Should not reach here
        }
    }
}
