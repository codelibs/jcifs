package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests for {@link LogStream}.  The class is minimal so the tests focus on
 * static state handling, constructor behaviour and null‑safety.
 */
public class LogStreamTest {

    private PrintStream testPrintStream;
    private ByteArrayOutputStream baos;

    @BeforeEach
    void setUp() {
        // Create a real PrintStream backed by ByteArrayOutputStream for testing
        baos = new ByteArrayOutputStream();
        testPrintStream = new PrintStream(baos);
    }

    @AfterEach
    void resetStaticState() {
        LogStream.setLevel(1);
        // Reset the singleton instance to null to ensure clean state
        LogStream.setInstance(System.err);
    }

    @Test
    void defaultGetInstanceCreatesSingleton() {
        LogStream first = LogStream.getInstance();
        LogStream second = LogStream.getInstance();
        assertSame(first, second, "Repeated calls should return the same instance");
    }

    @Test
    void setInstanceReplacesExistingInstance() {
        LogStream oldInstance = LogStream.getInstance();
        LogStream.setInstance(testPrintStream);
        LogStream newInstance = LogStream.getInstance();
        assertNotSame(oldInstance, newInstance, "Instance should be replaced after setInstance");
    }

    @Test
    void setInstanceWithNullThrowsNPE() {
        assertThrows(NullPointerException.class, () -> LogStream.setInstance(null),
                "setInstance(null) must throw NPE");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 5, -1, 100})
    void setLevelUpdatesStaticField(int level) {
        LogStream.setLevel(level);
        assertEquals(level, LogStream.level, "Static level should reflect the new value");
    }

    @Test
    void setLevelBeforeInstanceCreationIsIndependent() {
        LogStream.setLevel(6);
        assertEquals(6, LogStream.level, "Level must persist after setLevel");
        LogStream.setInstance(testPrintStream);
        assertEquals(6, LogStream.level, "Level should be unaffected by setInstance");
    }

    @Test
    void logStreamWritesToUnderlyingStream() {
        // Test that LogStream properly delegates to the underlying PrintStream
        LogStream.setInstance(testPrintStream);
        LogStream logStream = LogStream.getInstance();
        
        String testMessage = "Test message";
        logStream.println(testMessage);
        logStream.flush();
        
        String output = baos.toString();
        assertTrue(output.contains(testMessage), "LogStream should write to underlying stream");
    }

    @Test
    void constructorRequiresNonNullStream() {
        // Test that the LogStream constructor properly handles null
        assertThrows(NullPointerException.class, () -> new LogStream(null),
                "LogStream constructor should throw NPE for null stream");
    }
}