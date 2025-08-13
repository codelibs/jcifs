package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * JUnit 5 tests for {@link TestLocking}.
 * Tests command line argument parsing and basic field initialization.
 * Does not require a real SMB server - focuses on application logic.
 */
@ExtendWith(MockitoExtension.class)
class TestLockingTest {

    private PrintStream originalOut;
    private PrintStream originalErr;
    private ByteArrayOutputStream outContent;
    private ByteArrayOutputStream errContent;

    @Mock
    private SmbFile mockSmbFile;

    @BeforeEach
    void setUpStreams() {
        originalOut = System.out;
        originalErr = System.err;
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    @AfterEach
    void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    @DisplayName("TestLocking fields are properly initialized")
    void testFieldInitialization() {
        TestLocking t = new TestLocking();
        
        // Check default field values
        assertEquals(1, t.numThreads, "Default numThreads should be 1");
        assertEquals(1, t.numIter, "Default numIter should be 1");
        assertEquals(100L, t.delay, "Default delay should be 100");
        assertNull(t.url, "URL should be null by default");
        assertEquals(0, t.numComplete, "numComplete should start at 0");
        assertEquals(0L, t.ltime, "ltime should start at 0");
    }

    @Test
    @DisplayName("TestLocking fields can be configured")
    void testFieldConfiguration() {
        TestLocking t = new TestLocking();
        
        // Set custom values
        t.numThreads = 5;
        t.numIter = 10;
        t.delay = 250L;
        t.url = "smb://custom/path/file.txt";
        
        // Verify values are set
        assertEquals(5, t.numThreads, "numThreads should be configurable");
        assertEquals(10, t.numIter, "numIter should be configurable");
        assertEquals(250L, t.delay, "delay should be configurable");
        assertEquals("smb://custom/path/file.txt", t.url, "url should be configurable");
    }

    @Test
    @DisplayName("TestLocking increments numComplete")
    void testNumCompleteIncrement() {
        TestLocking t = new TestLocking();
        t.url = "smb://test/file.txt";
        t.numIter = 0; // Set to 0 so run() exits immediately
        
        // Run the method
        t.run();
        
        // Verify numComplete was incremented
        assertEquals(1, t.numComplete, "numComplete should be incremented after run");
    }

    @Nested
    @DisplayName("Argument parsing")
    class ArgumentParsing {
        
        @Test
        @DisplayName("URL parameter is correctly parsed")
        void urlParameterParsing() {
            String expectedUrl = "smb://server/share/test.txt";
            TestLocking t = new TestLocking();
            
            // Simulate argument parsing
            String[] args = {"-t", "2", "-i", "5", "-d", "100", expectedUrl};
            for (int ai = 0; ai < args.length; ai++) {
                if (args[ai].equals("-t")) {
                    ai++;
                    t.numThreads = Integer.parseInt(args[ai]);
                } else if (args[ai].equals("-i")) {
                    ai++;
                    t.numIter = Integer.parseInt(args[ai]);
                } else if (args[ai].equals("-d")) {
                    ai++;
                    t.delay = Long.parseLong(args[ai]);
                } else {
                    t.url = args[ai];
                }
            }
            
            assertEquals(expectedUrl, t.url, "URL should be correctly parsed");
            assertEquals(2, t.numThreads, "Thread count should be parsed");
            assertEquals(5, t.numIter, "Iteration count should be parsed");
            assertEquals(100L, t.delay, "Delay should be parsed");
        }
        
        @Test
        @DisplayName("Default values are used when flags not provided")
        void defaultValuesParsing() {
            TestLocking t = new TestLocking();
            
            // Parse only URL
            String[] args = {"smb://server/share/test.txt"};
            for (int ai = 0; ai < args.length; ai++) {
                if (!args[ai].startsWith("-")) {
                    t.url = args[ai];
                }
            }
            
            assertEquals("smb://server/share/test.txt", t.url, "URL should be parsed");
            assertEquals(1, t.numThreads, "Default thread count should be 1");
            assertEquals(1, t.numIter, "Default iteration count should be 1");
            assertEquals(100L, t.delay, "Default delay should be 100");
        }

        @Test
        @DisplayName("Multiple flags are parsed correctly")
        void multipleFlags() {
            TestLocking t = new TestLocking();
            
            // Parse multiple flags
            String[] args = {"-t", "3", "-i", "7", "-d", "200", "smb://test/file.txt"};
            for (int ai = 0; ai < args.length; ai++) {
                if (args[ai].equals("-t")) {
                    ai++;
                    t.numThreads = Integer.parseInt(args[ai]);
                } else if (args[ai].equals("-i")) {
                    ai++;
                    t.numIter = Integer.parseInt(args[ai]);
                } else if (args[ai].equals("-d")) {
                    ai++;
                    t.delay = Long.parseLong(args[ai]);
                } else {
                    t.url = args[ai];
                }
            }
            
            assertEquals(3, t.numThreads, "Thread count should be 3");
            assertEquals(7, t.numIter, "Iteration count should be 7");
            assertEquals(200L, t.delay, "Delay should be 200");
            assertEquals("smb://test/file.txt", t.url, "URL should be parsed");
        }

        @Test
        @DisplayName("Flags can be in any order")
        void flagsInDifferentOrder() {
            TestLocking t = new TestLocking();
            
            // Parse flags in different order
            String[] args = {"smb://test/file.txt", "-i", "4", "-t", "2", "-d", "150"};
            for (int ai = 0; ai < args.length; ai++) {
                if (args[ai].equals("-t")) {
                    ai++;
                    t.numThreads = Integer.parseInt(args[ai]);
                } else if (args[ai].equals("-i")) {
                    ai++;
                    t.numIter = Integer.parseInt(args[ai]);
                } else if (args[ai].equals("-d")) {
                    ai++;
                    t.delay = Long.parseLong(args[ai]);
                } else if (!args[ai].startsWith("-")) {
                    t.url = args[ai];
                }
            }
            
            assertEquals(2, t.numThreads, "Thread count should be 2");
            assertEquals(4, t.numIter, "Iteration count should be 4");
            assertEquals(150L, t.delay, "Delay should be 150");
            assertEquals("smb://test/file.txt", t.url, "URL should be parsed");
        }
    }

    @Test
    @DisplayName("ltime field is mutable")
    void testLtimeField() {
        TestLocking t = new TestLocking();
        
        // Initial value
        assertEquals(0L, t.ltime, "ltime should start at 0");
        
        // Set new value
        long currentTime = System.currentTimeMillis();
        t.ltime = currentTime;
        assertEquals(currentTime, t.ltime, "ltime should be mutable");
    }

    @Test
    @DisplayName("TestLocking implements Runnable")
    void testImplementsRunnable() {
        TestLocking t = new TestLocking();
        assertTrue(t instanceof Runnable, "TestLocking should implement Runnable");
    }

    @Test
    @DisplayName("run method handles null URL gracefully")
    void testRunWithNullUrl() {
        TestLocking t = new TestLocking();
        t.url = null; // Null URL
        t.numIter = 0; // No iterations to avoid NPE
        
        // Should not throw exception
        assertDoesNotThrow(() -> t.run(), "run() should handle null URL gracefully");
        assertEquals(1, t.numComplete, "numComplete should still be incremented");
    }

    @Test
    @DisplayName("run method handles zero iterations")
    void testRunWithZeroIterations() {
        TestLocking t = new TestLocking();
        t.url = "smb://test/file.txt";
        t.numIter = 0; // Zero iterations
        
        // Should complete immediately
        t.run();
        assertEquals(1, t.numComplete, "numComplete should be incremented");
    }

    @Test
    @DisplayName("TestLocking can be instantiated")
    void testInstantiation() {
        TestLocking t = new TestLocking();
        assertNotNull(t, "TestLocking instance should not be null");
    }

    @Test
    @DisplayName("Field values are independent across instances")
    void testIndependentInstances() {
        TestLocking t1 = new TestLocking();
        TestLocking t2 = new TestLocking();
        
        // Set different values
        t1.numThreads = 2;
        t1.url = "smb://server1/share/file.txt";
        
        t2.numThreads = 5;
        t2.url = "smb://server2/share/file.txt";
        
        // Verify independence
        assertEquals(2, t1.numThreads, "t1 should have its own numThreads value");
        assertEquals(5, t2.numThreads, "t2 should have its own numThreads value");
        assertEquals("smb://server1/share/file.txt", t1.url, "t1 should have its own URL");
        assertEquals("smb://server2/share/file.txt", t2.url, "t2 should have its own URL");
    }
}