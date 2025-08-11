package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.PrintStream;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Tests for {@link LogStream}.  The class is minimal so the tests focus on
 * static state handling, constructor behaviour and null‑safety.
 */
@ExtendWith(MockitoExtension.class)
public class LogStreamTest {

    @Mock
    private PrintStream mockPrintStream;

    @AfterEach
    void resetStaticState() {
        LogStream.setLevel(1);
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
        LogStream.setInstance(mockPrintStream);
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
        LogStream.setInstance(mockPrintStream);
        assertEquals(6, LogStream.level, "Level should be unaffected by setInstance");
    }
}
