package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;

import jcifs.Configuration;
import jcifs.CIFSContext;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.SmbConstants;
import jcifs.internal.util.SMBUtil;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Unit tests for {@link SmbComNTCreateAndX}.  The tests exercise the
 * constructor’s flag handling, response creation and simple accessors.
 *
 * <p>All tests run in the same package as the class under test so that
 * package‑private members are visible if required.
 */
@ExtendWith(MockitoExtension.class)
class SmbComNTCreateAndXTest {
    @Mock Configuration mockConfig;
    @Mock ServerMessageBlock mockAndX;
    @Mock CIFSContext mockContext;

    /**
     * Helper that creates a request instance with the supplied flags.
     * The other arguments are simple constants.
     */
    private SmbComNTCreateAndX createRequest(int flags, int createOptions) {
        return new SmbComNTCreateAndX(
                mockConfig,
                "test.txt",
                flags,
                SmbConstants.FILE_READ_EA, // desired access
                0, // shareAccess
                0, // extFileAttributes
                createOptions,
                mockAndX
        );
    }

    @Nested
    @DisplayName("Constructor createDisposition calculation")
    class CreateDispositionTests {
        static java.util.stream.Stream<Arguments> flagsProvider() {
            return java.util.stream.Stream.of(
                    Arguments.of(SmbConstants.O_TRUNC | SmbConstants.O_CREAT, SmbComNTCreateAndX.FILE_OVERWRITE_IF),
                    Arguments.of(SmbConstants.O_TRUNC, SmbComNTCreateAndX.FILE_OVERWRITE),
                    Arguments.of(SmbConstants.O_CREAT | SmbConstants.O_EXCL, SmbComNTCreateAndX.FILE_CREATE),
                    Arguments.of(SmbConstants.O_CREAT, SmbComNTCreateAndX.FILE_OPEN_IF),
                    Arguments.of(0, SmbComNTCreateAndX.FILE_OPEN)
            );
        }

        @ParameterizedTest
        @MethodSource("flagsProvider")
        void verifiesCreateDisposition(int flags, int expected) {
            SmbComNTCreateAndX req = createRequest(flags, 0);
            // Use reflection to read the private field createDisposition
            int actual = (int) getPrivateField(req, "createDisposition");
            assertEquals(expected, actual, "createDisposition should match" );
        }
    }

    @Test
    @DisplayName("CreateOptions default padding" )
    void createOptionsAddedWhenLow() {
        // createOptions less than 0x0001 (i.e., 0) should be padded with 0x0040
        SmbComNTCreateAndX req = createRequest(0, 0);
        int actual = (int) getPrivateField(req, "createOptions");
        assertEquals(0x0040, actual, "createOptions should be padded with 0x0040");
    }

    @Test
    @DisplayName("addFlags0 combines flags correctly")
    void addFlags0() {
        SmbComNTCreateAndX req = createRequest(0, 0);
        req.addFlags0(0x10);
        int flags0 = (int) getPrivateField(req, "flags0");
        assertTrue((flags0 & 0x10) != 0, "flag should be set after addFlags0");
        // Calling again should combine rather than overwrite
        req.addFlags0(0x20);
        flags0 = (int) getPrivateField(req, "flags0");
        assertTrue((flags0 & 0x20) != 0, "flag should accumulate" );
    }

    @Test
    @DisplayName("initResponse prepares a response instance")
    void initResponseCreatesResponse() {
        SmbComNTCreateAndX req = createRequest(0, 0);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        SmbComNTCreateAndXResponse resp = req.initResponse(mockContext);
        assertNotNull(resp, "Response should not be null after init");
        // getResponse should now return the same instance
        assertSame(resp, req.getResponse(), "getResponse should expose the initialized response");
    }

    @Test
    @DisplayName("getResponse before initResponse returns null")
    void getResponseInitiallyNull() {
        SmbComNTCreateAndX req = createRequest(0, 0);
        assertNull(req.getResponse(), "Before init, response is null");
    }

    @Test
    @DisplayName("toString representation contains expected fields")
    void toStringContainsKeyData() {
        SmbComNTCreateAndX req = createRequest(0, 0);
        String str = req.toString();
        assertTrue(str.startsWith("SmbComNTCreateAndX["), "toString should start with class name");
        assertTrue(str.contains("name=test.txt"), "The file name should appear");
        // securityFlags are set to 0x03 – verify hex sequence
        assertTrue(str.contains("securityFlags=0x03"), "securityFlags should be present");
    }

    /**
     * Fetch a private field value via reflection.  This helper keeps the
     * test code tidy and is used where unit‑testing logic relies on
     * internally stored data.
     */
    private static Object getPrivateField(Object target, String name) {
        try {
            java.lang.reflect.Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

