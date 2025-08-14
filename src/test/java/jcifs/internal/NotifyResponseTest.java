package jcifs.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.FileNotifyInformation;
import jcifs.internal.smb1.trans.nt.NtTransNotifyChangeResponse;
import jcifs.internal.smb2.notify.Smb2ChangeNotifyResponse;

/**
 * Test class for NotifyResponse interface and its implementations
 */
class NotifyResponseTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private FileNotifyInformation mockNotifyInfo1;

    @Mock
    private FileNotifyInformation mockNotifyInfo2;

    @Mock
    private CommonServerMessageBlockRequest mockRequest;

    /**
     * Mock implementation of NotifyResponse for testing interface behavior
     */
    private static class MockNotifyResponse implements NotifyResponse {

        private List<FileNotifyInformation> notifyInformation;
        private boolean async = false;
        private CommonServerMessageBlockResponse nextResponse = null;
        private SMBSigningDigest digest;
        private CommonServerMessageBlockResponse response;
        private long mid;
        private int command;
        private int uid;
        private boolean extendedSecurity;
        private long sessionId;
        private boolean retainPayload;
        private byte[] rawPayload;

        // Response interface fields
        private boolean received = false;
        private int grantedCredits = 0;
        private int errorCode = 0;
        private boolean verifyFailed = false;
        private boolean error = false;
        private Exception exception;
        private Long expiration;

        public MockNotifyResponse(List<FileNotifyInformation> notifyInfo) {
            this.notifyInformation = notifyInfo != null ? new ArrayList<>(notifyInfo) : new ArrayList<>();
        }

        @Override
        public List<FileNotifyInformation> getNotifyInformation() {
            return this.notifyInformation;
        }

        @Override
        public boolean isAsync() {
            return this.async;
        }

        public void setAsync(boolean async) {
            this.async = async;
        }

        @Override
        public CommonServerMessageBlockResponse getNextResponse() {
            return this.nextResponse;
        }

        public void setNextResponse(CommonServerMessageBlockResponse nextResponse) {
            this.nextResponse = nextResponse;
        }

        @Override
        public void prepare(CommonServerMessageBlockRequest next) {
            // Mock implementation - do nothing
        }

        @Override
        public void reset() {
            // Mock implementation - reset state
            this.async = false;
            this.nextResponse = null;
        }

        // CommonServerMessageBlock interface methods
        @Override
        public int decode(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
            // Mock implementation
            return 0;
        }

        @Override
        public int encode(byte[] dst, int dstIndex) {
            // Mock implementation
            return 0;
        }

        @Override
        public void setDigest(SMBSigningDigest digest) {
            this.digest = digest;
        }

        @Override
        public SMBSigningDigest getDigest() {
            return this.digest;
        }

        @Override
        public CommonServerMessageBlockResponse getResponse() {
            return this.response;
        }

        @Override
        public void setResponse(CommonServerMessageBlockResponse msg) {
            this.response = msg;
        }

        @Override
        public long getMid() {
            return this.mid;
        }

        @Override
        public void setMid(long mid) {
            this.mid = mid;
        }

        @Override
        public int getCommand() {
            return this.command;
        }

        @Override
        public void setCommand(int command) {
            this.command = command;
        }

        @Override
        public void setUid(int uid) {
            this.uid = uid;
        }

        @Override
        public void setExtendedSecurity(boolean extendedSecurity) {
            this.extendedSecurity = extendedSecurity;
        }

        @Override
        public void setSessionId(long sessionId) {
            this.sessionId = sessionId;
        }

        // Message interface methods
        @Override
        public boolean isRetainPayload() {
            return this.retainPayload;
        }

        @Override
        public void setRawPayload(byte[] rawPayload) {
            this.rawPayload = rawPayload;
        }

        @Override
        public boolean verifySignature(byte[] buffer, int i, int size) {
            // Mock implementation
            return true;
        }

        @Override
        public byte[] getRawPayload() {
            return this.rawPayload;
        }

        @Override
        public void retainPayload() {
            // Mock implementation - do nothing
        }

        @Override
        public void exception(Exception e) {
            this.exception = e;
        }

        @Override
        public Exception getException() {
            return this.exception;
        }

        @Override
        public void setExpiration(Long expiration) {
            this.expiration = expiration;
        }

        @Override
        public Long getExpiration() {
            return this.expiration;
        }

        // Additional Response interface methods
        @Override
        public boolean isReceived() {
            return this.received;
        }

        @Override
        public void received() {
            this.received = true;
        }

        @Override
        public void clearReceived() {
            this.received = false;
        }

        @Override
        public int getGrantedCredits() {
            return this.grantedCredits;
        }

        @Override
        public int getErrorCode() {
            return this.errorCode;
        }

        @Override
        public boolean isVerifyFailed() {
            return this.verifyFailed;
        }

        @Override
        public boolean isError() {
            return this.error;
        }

        @Override
        public void error() {
            this.error = true;
        }

        // Setter methods for testing
        public void setGrantedCredits(int grantedCredits) {
            this.grantedCredits = grantedCredits;
        }

        public void setErrorCode(int errorCode) {
            this.errorCode = errorCode;
        }

        public void setVerifyFailed(boolean verifyFailed) {
            this.verifyFailed = verifyFailed;
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup mock notify information
        when(mockNotifyInfo1.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_ADDED);
        when(mockNotifyInfo1.getFileName()).thenReturn("test1.txt");

        when(mockNotifyInfo2.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_MODIFIED);
        when(mockNotifyInfo2.getFileName()).thenReturn("test2.txt");
    }

    @Test
    @DisplayName("Test NotifyResponse interface with empty notification list")
    void testNotifyResponseWithEmptyList() {
        MockNotifyResponse response = new MockNotifyResponse(Collections.emptyList());

        List<FileNotifyInformation> notifications = response.getNotifyInformation();

        assertNotNull(notifications);
        assertTrue(notifications.isEmpty());
        assertEquals(0, notifications.size());
    }

    @Test
    @DisplayName("Test NotifyResponse interface with single notification")
    void testNotifyResponseWithSingleNotification() {
        List<FileNotifyInformation> inputList = Collections.singletonList(mockNotifyInfo1);
        MockNotifyResponse response = new MockNotifyResponse(inputList);

        List<FileNotifyInformation> notifications = response.getNotifyInformation();

        assertNotNull(notifications);
        assertEquals(1, notifications.size());
        assertEquals(mockNotifyInfo1, notifications.get(0));

        // Verify the notification content
        FileNotifyInformation info = notifications.get(0);
        assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, info.getAction());
        assertEquals("test1.txt", info.getFileName());
    }

    @Test
    @DisplayName("Test NotifyResponse interface with multiple notifications")
    void testNotifyResponseWithMultipleNotifications() {
        List<FileNotifyInformation> inputList = Arrays.asList(mockNotifyInfo1, mockNotifyInfo2);
        MockNotifyResponse response = new MockNotifyResponse(inputList);

        List<FileNotifyInformation> notifications = response.getNotifyInformation();

        assertNotNull(notifications);
        assertEquals(2, notifications.size());
        assertEquals(mockNotifyInfo1, notifications.get(0));
        assertEquals(mockNotifyInfo2, notifications.get(1));

        // Verify first notification
        FileNotifyInformation info1 = notifications.get(0);
        assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, info1.getAction());
        assertEquals("test1.txt", info1.getFileName());

        // Verify second notification
        FileNotifyInformation info2 = notifications.get(1);
        assertEquals(FileNotifyInformation.FILE_ACTION_MODIFIED, info2.getAction());
        assertEquals("test2.txt", info2.getFileName());
    }

    @Test
    @DisplayName("Test NotifyResponse interface with null notification list")
    void testNotifyResponseWithNullList() {
        MockNotifyResponse response = new MockNotifyResponse(null);

        List<FileNotifyInformation> notifications = response.getNotifyInformation();

        assertNotNull(notifications);
        assertTrue(notifications.isEmpty());
    }

    @Test
    @DisplayName("Test CommonServerMessageBlockResponse methods")
    void testCommonServerMessageBlockResponseMethods() {
        MockNotifyResponse response = new MockNotifyResponse(Collections.emptyList());

        // Test async property
        assertFalse(response.isAsync());
        response.setAsync(true);
        assertTrue(response.isAsync());

        // Test next response property
        assertNull(response.getNextResponse());
        MockNotifyResponse nextResponse = new MockNotifyResponse(Collections.emptyList());
        response.setNextResponse(nextResponse);
        assertEquals(nextResponse, response.getNextResponse());

        // Test prepare method (should not throw exception)
        assertDoesNotThrow(() -> response.prepare(mockRequest));
    }

    @Test
    @DisplayName("Test NotifyResponse returned list immutability")
    void testNotifyResponseListImmutability() {
        List<FileNotifyInformation> inputList = new ArrayList<>(Arrays.asList(mockNotifyInfo1, mockNotifyInfo2));
        MockNotifyResponse response = new MockNotifyResponse(inputList);

        List<FileNotifyInformation> notifications = response.getNotifyInformation();

        // Verify initial state
        assertEquals(2, notifications.size());

        // Modify input list - should not affect returned list
        inputList.clear();
        assertEquals(2, notifications.size());

        // Try to modify returned list - behavior depends on implementation
        // This tests that the implementation properly handles list modifications
        try {
            notifications.clear();
            // If this succeeds, the implementation allows modification
            assertTrue(notifications.isEmpty());
        } catch (UnsupportedOperationException e) {
            // If this throws, the implementation returned an immutable list
            assertEquals(2, notifications.size());
        }
    }

    @Test
    @DisplayName("Test NtTransNotifyChangeResponse concrete implementation")
    void testNtTransNotifyChangeResponse() {
        NtTransNotifyChangeResponse response = new NtTransNotifyChangeResponse(mockConfig);

        // Test interface implementation
        assertTrue(response instanceof NotifyResponse);
        assertTrue(response instanceof CommonServerMessageBlockResponse);

        // Test initial state
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertNotNull(notifications);
        assertTrue(notifications.isEmpty());
    }

    @Test
    @DisplayName("Test Smb2ChangeNotifyResponse concrete implementation")
    void testSmb2ChangeNotifyResponse() {
        Smb2ChangeNotifyResponse response = new Smb2ChangeNotifyResponse(mockConfig);

        // Test interface implementation
        assertTrue(response instanceof NotifyResponse);
        assertTrue(response instanceof CommonServerMessageBlockResponse);

        // Test initial state
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertNotNull(notifications);
        assertTrue(notifications.isEmpty());
    }

    @Test
    @DisplayName("Test NotifyResponse with different file actions")
    void testNotifyResponseWithDifferentFileActions() {
        // Create mock notifications for different actions
        FileNotifyInformation addedFile = mock(FileNotifyInformation.class);
        when(addedFile.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_ADDED);
        when(addedFile.getFileName()).thenReturn("added.txt");

        FileNotifyInformation removedFile = mock(FileNotifyInformation.class);
        when(removedFile.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_REMOVED);
        when(removedFile.getFileName()).thenReturn("removed.txt");

        FileNotifyInformation modifiedFile = mock(FileNotifyInformation.class);
        when(modifiedFile.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_MODIFIED);
        when(modifiedFile.getFileName()).thenReturn("modified.txt");

        FileNotifyInformation renamedOld = mock(FileNotifyInformation.class);
        when(renamedOld.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_RENAMED_OLD_NAME);
        when(renamedOld.getFileName()).thenReturn("oldname.txt");

        FileNotifyInformation renamedNew = mock(FileNotifyInformation.class);
        when(renamedNew.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_RENAMED_NEW_NAME);
        when(renamedNew.getFileName()).thenReturn("newname.txt");

        List<FileNotifyInformation> notifications = Arrays.asList(addedFile, removedFile, modifiedFile, renamedOld, renamedNew);

        MockNotifyResponse response = new MockNotifyResponse(notifications);
        List<FileNotifyInformation> result = response.getNotifyInformation();

        assertEquals(5, result.size());

        // Verify all actions are preserved
        assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, result.get(0).getAction());
        assertEquals(FileNotifyInformation.FILE_ACTION_REMOVED, result.get(1).getAction());
        assertEquals(FileNotifyInformation.FILE_ACTION_MODIFIED, result.get(2).getAction());
        assertEquals(FileNotifyInformation.FILE_ACTION_RENAMED_OLD_NAME, result.get(3).getAction());
        assertEquals(FileNotifyInformation.FILE_ACTION_RENAMED_NEW_NAME, result.get(4).getAction());

        // Verify all filenames are preserved
        assertEquals("added.txt", result.get(0).getFileName());
        assertEquals("removed.txt", result.get(1).getFileName());
        assertEquals("modified.txt", result.get(2).getFileName());
        assertEquals("oldname.txt", result.get(3).getFileName());
        assertEquals("newname.txt", result.get(4).getFileName());
    }

    @Test
    @DisplayName("Test NotifyResponse with stream actions")
    void testNotifyResponseWithStreamActions() {
        // Create mock notifications for stream actions
        FileNotifyInformation addedStream = mock(FileNotifyInformation.class);
        when(addedStream.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_ADDED_STREAM);
        when(addedStream.getFileName()).thenReturn("file.txt:stream");

        FileNotifyInformation removedStream = mock(FileNotifyInformation.class);
        when(removedStream.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_REMOVED_STREAM);
        when(removedStream.getFileName()).thenReturn("file.txt:removedstream");

        FileNotifyInformation modifiedStream = mock(FileNotifyInformation.class);
        when(modifiedStream.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_MODIFIED_STREAM);
        when(modifiedStream.getFileName()).thenReturn("file.txt:modifiedstream");

        List<FileNotifyInformation> notifications = Arrays.asList(addedStream, removedStream, modifiedStream);

        MockNotifyResponse response = new MockNotifyResponse(notifications);
        List<FileNotifyInformation> result = response.getNotifyInformation();

        assertEquals(3, result.size());

        // Verify stream actions
        assertEquals(FileNotifyInformation.FILE_ACTION_ADDED_STREAM, result.get(0).getAction());
        assertEquals(FileNotifyInformation.FILE_ACTION_REMOVED_STREAM, result.get(1).getAction());
        assertEquals(FileNotifyInformation.FILE_ACTION_MODIFIED_STREAM, result.get(2).getAction());

        // Verify stream filenames
        assertEquals("file.txt:stream", result.get(0).getFileName());
        assertEquals("file.txt:removedstream", result.get(1).getFileName());
        assertEquals("file.txt:modifiedstream", result.get(2).getFileName());
    }

    @Test
    @DisplayName("Test NotifyResponse chaining with multiple responses")
    void testNotifyResponseChaining() {
        MockNotifyResponse response1 = new MockNotifyResponse(Collections.singletonList(mockNotifyInfo1));
        MockNotifyResponse response2 = new MockNotifyResponse(Collections.singletonList(mockNotifyInfo2));

        // Setup chaining
        response1.setNextResponse(response2);

        // Verify chaining
        assertEquals(response2, response1.getNextResponse());
        assertNull(response2.getNextResponse());

        // Verify each response maintains its own notifications
        assertEquals(1, response1.getNotifyInformation().size());
        assertEquals(mockNotifyInfo1, response1.getNotifyInformation().get(0));

        assertEquals(1, response2.getNotifyInformation().size());
        assertEquals(mockNotifyInfo2, response2.getNotifyInformation().get(0));
    }

    @Test
    @DisplayName("Test NotifyResponse with special characters in filenames")
    void testNotifyResponseWithSpecialCharactersInFilenames() {
        // Create notifications with special characters
        FileNotifyInformation unicodeFile = mock(FileNotifyInformation.class);
        when(unicodeFile.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_ADDED);
        when(unicodeFile.getFileName()).thenReturn("файл.txt"); // Cyrillic characters

        FileNotifyInformation spaceFile = mock(FileNotifyInformation.class);
        when(spaceFile.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_MODIFIED);
        when(spaceFile.getFileName()).thenReturn("file with spaces.txt");

        FileNotifyInformation symbolFile = mock(FileNotifyInformation.class);
        when(symbolFile.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_REMOVED);
        when(symbolFile.getFileName()).thenReturn("file@#$%.txt");

        List<FileNotifyInformation> notifications = Arrays.asList(unicodeFile, spaceFile, symbolFile);

        MockNotifyResponse response = new MockNotifyResponse(notifications);
        List<FileNotifyInformation> result = response.getNotifyInformation();

        assertEquals(3, result.size());

        // Verify special character filenames are preserved
        assertEquals("файл.txt", result.get(0).getFileName());
        assertEquals("file with spaces.txt", result.get(1).getFileName());
        assertEquals("file@#$%.txt", result.get(2).getFileName());
    }

    @Test
    @DisplayName("Test NotifyResponse consistency across multiple calls")
    void testNotifyResponseConsistency() {
        List<FileNotifyInformation> notifications = Arrays.asList(mockNotifyInfo1, mockNotifyInfo2);
        MockNotifyResponse response = new MockNotifyResponse(notifications);

        // Call getNotifyInformation multiple times
        List<FileNotifyInformation> result1 = response.getNotifyInformation();
        List<FileNotifyInformation> result2 = response.getNotifyInformation();
        List<FileNotifyInformation> result3 = response.getNotifyInformation();

        // Verify all calls return the same content
        assertEquals(result1.size(), result2.size());
        assertEquals(result2.size(), result3.size());

        for (int i = 0; i < result1.size(); i++) {
            assertEquals(result1.get(i), result2.get(i));
            assertEquals(result2.get(i), result3.get(i));
        }

        // Verify content is correct
        assertEquals(2, result1.size());
        assertEquals(mockNotifyInfo1, result1.get(0));
        assertEquals(mockNotifyInfo2, result1.get(1));
    }
}
