package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LogStreamTest {

    private PrintStream originalErr;
    private ByteArrayOutputStream testOutput;
    private PrintStream testStream;
    private int originalLevel;

    @BeforeEach
    void setUp() throws Exception {
        // Save original state
        originalErr = System.err;
        originalLevel = LogStream.level;
        
        // Create test stream
        testOutput = new ByteArrayOutputStream();
        testStream = new PrintStream(testOutput);
        
        // Reset LogStream instance using reflection
        resetLogStreamInstance();
    }

    @AfterEach
    void tearDown() throws Exception {
        // Restore original state
        System.setErr(originalErr);
        LogStream.level = originalLevel;
        // Reset instance using reflection
        resetLogStreamInstance();
    }

    private void resetLogStreamInstance() throws Exception {
        // Use reflection to reset the static instance field to null
        Field instanceField = LogStream.class.getDeclaredField("inst");
        instanceField.setAccessible(true);
        instanceField.set(null, null);
    }

    @Test
    void testConstructor() {
        // Test constructor creates a LogStream that extends PrintStream
        LogStream logStream = new LogStream(testStream);
        assertNotNull(logStream);
        assertTrue(logStream instanceof PrintStream);
    }

    @Test
    void testSetLevel() {
        // Test setting log level
        LogStream.setLevel(0);
        assertEquals(0, LogStream.level);
        
        LogStream.setLevel(1);
        assertEquals(1, LogStream.level);
        
        LogStream.setLevel(3);
        assertEquals(3, LogStream.level);
        
        LogStream.setLevel(10);
        assertEquals(10, LogStream.level);
        
        // Test negative level
        LogStream.setLevel(-1);
        assertEquals(-1, LogStream.level);
    }

    @Test
    void testGetInstanceWithoutSetInstance() {
        // Test getInstance when no instance has been set
        // Should default to System.err
        LogStream instance = LogStream.getInstance();
        assertNotNull(instance);
        
        // Getting instance again should return the same instance
        LogStream instance2 = LogStream.getInstance();
        assertSame(instance, instance2);
    }

    @Test
    void testSetInstanceAndGetInstance() {
        // Test setting a custom instance
        LogStream.setInstance(testStream);
        LogStream instance = LogStream.getInstance();
        assertNotNull(instance);
        
        // Write something to verify it uses our test stream
        instance.println("test message");
        instance.flush();
        String output = testOutput.toString();
        assertTrue(output.contains("test message"));
    }

    @Test
    void testSetInstanceMultipleTimes() {
        // Test setting instance multiple times
        PrintStream stream1 = new PrintStream(new ByteArrayOutputStream());
        PrintStream stream2 = new PrintStream(new ByteArrayOutputStream());
        
        LogStream.setInstance(stream1);
        LogStream instance1 = LogStream.getInstance();
        
        LogStream.setInstance(stream2);
        LogStream instance2 = LogStream.getInstance();
        
        // Each setInstance should create a new LogStream
        assertNotNull(instance1);
        assertNotNull(instance2);
        // The second setInstance replaces the first, so they should not be the same
        assertNotSame(instance1, instance2);
        // Getting instance again should return the same as instance2
        assertSame(instance2, LogStream.getInstance());
    }

    @Test
    void testLogStreamInheritsFromPrintStream() {
        // Test that LogStream properly inherits PrintStream functionality
        LogStream.setInstance(testStream);
        LogStream logStream = LogStream.getInstance();
        
        // Test various PrintStream methods
        logStream.print("test");
        logStream.print(123);
        logStream.print(true);
        logStream.println();
        logStream.println("line");
        logStream.printf("formatted %d%n", 42);
        logStream.flush();
        
        String output = testOutput.toString();
        assertTrue(output.contains("test"));
        assertTrue(output.contains("123"));
        assertTrue(output.contains("true"));
        assertTrue(output.contains("line"));
        assertTrue(output.contains("formatted 42"));
    }

    @Test
    void testDefaultLevel() {
        // Test that default level is 1
        assertEquals(1, LogStream.level);
    }

    @Test
    void testLevelValuesDocumentation() {
        // Test various level values as documented
        // 0 - nothing
        LogStream.setLevel(0);
        assertEquals(0, LogStream.level);
        
        // 1 - critical [default]
        LogStream.setLevel(1);
        assertEquals(1, LogStream.level);
        
        // 2 - basic info can be logged under load
        LogStream.setLevel(2);
        assertEquals(2, LogStream.level);
        
        // 3 - almost everything
        LogStream.setLevel(3);
        assertEquals(3, LogStream.level);
        
        // N - debugging (higher values)
        LogStream.setLevel(10);
        assertEquals(10, LogStream.level);
    }

    @Test
    void testSetInstanceAfterGetInstance() {
        // Test that setInstance after getInstance has been called
        // getInstance first (creates default instance with System.err)
        LogStream instance1 = LogStream.getInstance();
        assertNotNull(instance1);
        
        // Now set a new instance
        LogStream.setInstance(testStream);
        LogStream instance2 = LogStream.getInstance();
        assertNotNull(instance2);
        
        // Should be different instances since setInstance replaces the previous one
        assertNotSame(instance1, instance2);
        // Getting instance again should return the same as instance2
        assertSame(instance2, LogStream.getInstance());
    }

    @Test
    void testNullStreamHandling() {
        // Test that passing null to setInstance throws NullPointerException
        // This is expected behavior as PrintStream doesn't accept null
        assertThrows(NullPointerException.class, () -> {
            LogStream.setInstance(null);
        });
    }

    @Test
    void testPrintStreamDelegation() {
        // Test that LogStream properly delegates to underlying PrintStream
        // Use a real PrintStream with ByteArrayOutputStream to test delegation
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream realStream = new PrintStream(baos);
        LogStream logStream = new LogStream(realStream);
        
        // Test delegation of various methods
        logStream.println("test");
        logStream.print(42);
        logStream.print(" ");
        logStream.print(true);
        logStream.flush();
        
        String output = baos.toString();
        assertTrue(output.contains("test"));
        assertTrue(output.contains("42"));
        assertTrue(output.contains("true"));
        
        // Test close
        logStream.close();
        // After close, the stream should not accept more writes
        // but PrintStream doesn't throw exceptions on write after close
    }

    @Test
    void testConcurrentAccess() throws InterruptedException {
        // Test thread safety of getInstance
        LogStream.setInstance(testStream);
        
        final LogStream[] instances = new LogStream[10];
        Thread[] threads = new Thread[10];
        
        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                instances[index] = LogStream.getInstance();
            });
            threads[i].start();
        }
        
        for (Thread thread : threads) {
            thread.join();
        }
        
        // All threads should get the same instance
        LogStream expected = instances[0];
        for (LogStream instance : instances) {
            assertSame(expected, instance);
        }
    }
}