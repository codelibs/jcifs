package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.net.MalformedURLException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.SmbConstants;
import jcifs.SmbPipeHandle;
import jcifs.SmbPipeResource;
import jcifs.context.SingletonContext;
import jcifs.internal.smb1.com.SmbComNTCreateAndX;
import jcifs.internal.smb1.com.SmbComNTCreateAndXResponse;

@ExtendWith(MockitoExtension.class)
class SmbNamedPipeTest {

    // Creates a minimal valid CIFS context that does not perform I/O by itself
    private CIFSContext ctx() {
        return SingletonContext.getInstance();
    }

    @Nested
    @DisplayName("Constructor behavior")
    class ConstructorTests {

        @ParameterizedTest
        @DisplayName("Accepts IPC$ URLs (happy path)")
        @ValueSource(strings = { "smb://server/IPC$/foo", "smb://server/IPC$/PIPE/foo" })
        void constructsWithIpcShare(String url) throws Exception {
            // Arrange & Act
            SmbNamedPipe pipe = new SmbNamedPipe(url, SmbPipeResource.PIPE_TYPE_RDWR, ctx());

            // Assert: type is named pipe and pipe type preserved
            assertEquals(SmbConstants.TYPE_NAMED_PIPE, pipe.getType(), "Type should be TYPE_NAMED_PIPE");
            assertEquals(SmbPipeResource.PIPE_TYPE_RDWR, pipe.getPipeType(), "Pipe type should match constructor");
        }

        @ParameterizedTest
        @DisplayName("Rejects non-IPC$ URLs")
        @ValueSource(strings = { "smb://server/C$/foo", "smb://server/public/foo", "smb://server/share/path" })
        void rejectsNonIpcShare(String url) {
            // Arrange & Act & Assert
            MalformedURLException ex =
                    assertThrows(MalformedURLException.class, () -> new SmbNamedPipe(url, SmbPipeResource.PIPE_TYPE_RDWR, ctx()));
            assertEquals("Named pipes are only valid on IPC$", ex.getMessage());
        }

        @Test
        @DisplayName("Null context throws NPE (invalid input)")
        void nullContextThrows() {
            assertThrows(NullPointerException.class, () -> new SmbNamedPipe("smb://server/IPC$/foo", 0, null));
        }

        @Test
        @DisplayName("Second constructor sets unshared based on flags")
        void secondCtorUnsharedFlagPath() throws Exception {
            // Arrange: include UNSHARED flag to exercise that branch
            int flags = SmbPipeResource.PIPE_TYPE_RDWR | SmbPipeResource.PIPE_TYPE_UNSHARED;

            // Act
            SmbNamedPipe pipe = new SmbNamedPipe("smb://server/IPC$/foo", flags, ctx());

            // Assert: observable properties still correct
            assertEquals(flags, pipe.getPipeType());
            assertEquals(SmbConstants.TYPE_NAMED_PIPE, pipe.getType());
        }
    }

    @Test
    @DisplayName("customizeCreate sets required flags and extended mode")
    void customizeCreateSetsFlagsAndExtended() throws Exception {
        // Arrange: real instance to call protected method; collaborators mocked for interaction verification
        SmbNamedPipe pipe = new SmbNamedPipe("smb://server/IPC$/foo", SmbPipeResource.PIPE_TYPE_RDWR, ctx());
        SmbComNTCreateAndX req = mock(SmbComNTCreateAndX.class);
        SmbComNTCreateAndXResponse resp = mock(SmbComNTCreateAndXResponse.class);

        // Act
        pipe.customizeCreate(req, resp);

        // Assert: verify interactions with dependencies
        verify(req, times(1)).addFlags0(0x16);
        verify(resp, times(1)).setExtended(true);
        verify(resp, never()).setExtended(false);
    }

    @Test
    @DisplayName("openPipe returns a handle bound to this pipe")
    void openPipeReturnsHandleBoundToPipe() throws Exception {
        // Arrange
        SmbNamedPipe pipe = new SmbNamedPipe("smb://server/IPC$/foo", SmbPipeResource.PIPE_TYPE_RDWR, ctx());

        // Act
        SmbPipeHandle handle = pipe.openPipe();

        // Assert: observable handle behavior without network I/O
        assertNotNull(handle, "Handle must not be null");
        assertSame(pipe, handle.getPipe(), "Handle should reference originating pipe");
        assertSame(handle, handle.unwrap(SmbPipeHandle.class), "unwrap should return same instance for interface type");
    }

    @ParameterizedTest
    @DisplayName("getPipeType echoes constructor input (edge values)")
    @ValueSource(ints = { 0, SmbPipeResource.PIPE_TYPE_RDONLY, SmbPipeResource.PIPE_TYPE_WRONLY, SmbPipeResource.PIPE_TYPE_DCE_TRANSACT })
    void getPipeTypeEchoesInput(int pipeType) throws Exception {
        // Arrange & Act
        SmbNamedPipe pipe = new SmbNamedPipe("smb://server/IPC$/foo", pipeType, ctx());

        // Assert
        assertEquals(pipeType, pipe.getPipeType());
    }
}
