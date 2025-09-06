package org.codelibs.jcifs.smb.internal.smb2;

import static org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2.SMB2_CANCEL;
import static org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2.SMB2_FLAGS_ASYNC_COMMAND;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for Smb2CancelRequest
 */
class Smb2CancelRequestTest {

    @Mock
    private Configuration mockConfig;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Test constructor with non-zero asyncId sets async flag")
    void testConstructorWithNonZeroAsyncId() {
        // Given
        long mid = 12345L;
        long asyncId = 67890L;

        // When
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, mid, asyncId);

        // Then
        assertEquals(SMB2_CANCEL, request.getCommand());
        assertEquals(mid, request.getMid());
        assertEquals(asyncId, request.getAsyncId());
        assertTrue((request.getFlags() & SMB2_FLAGS_ASYNC_COMMAND) != 0, "Async flag should be set when asyncId is non-zero");
    }

    @Test
    @DisplayName("Test constructor with zero asyncId does not set async flag")
    void testConstructorWithZeroAsyncId() {
        // Given
        long mid = 12345L;
        long asyncId = 0L;

        // When
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, mid, asyncId);

        // Then
        assertEquals(SMB2_CANCEL, request.getCommand());
        assertEquals(mid, request.getMid());
        assertEquals(asyncId, request.getAsyncId());
        assertFalse((request.getFlags() & SMB2_FLAGS_ASYNC_COMMAND) != 0, "Async flag should not be set when asyncId is zero");
    }

    @Test
    @DisplayName("Test getCreditCost returns 1")
    void testGetCreditCost() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        int creditCost = request.getCreditCost();

        // Then
        assertEquals(1, creditCost, "Credit cost should always be 1 for cancel requests");
    }

    @Test
    @DisplayName("Test isResponseAsync returns false")
    void testIsResponseAsync() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        boolean isAsync = request.isResponseAsync();

        // Then
        assertFalse(isAsync, "Cancel requests should not expect async responses");
    }

    @Test
    @DisplayName("Test getNext returns null")
    void testGetNext() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        ServerMessageBlock2Request<?> next = request.getNext();

        // Then
        assertNull(next, "Cancel requests should not have next requests in chain");
    }

    @Test
    @DisplayName("Test getOverrideTimeout returns null")
    void testGetOverrideTimeout() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        Integer timeout = request.getOverrideTimeout();

        // Then
        assertNull(timeout, "Cancel requests should not override timeout");
    }

    @Test
    @DisplayName("Test allowChain returns false")
    void testAllowChain() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);
        CommonServerMessageBlockRequest nextRequest = mock(CommonServerMessageBlockRequest.class);

        // When
        boolean allowChain = request.allowChain(nextRequest);

        // Then
        assertFalse(allowChain, "Cancel requests should not allow chaining");
    }

    @Test
    @DisplayName("Test split returns null")
    void testSplit() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        CommonServerMessageBlockRequest splitRequest = request.split();

        // Then
        assertNull(splitRequest, "Cancel requests cannot be split");
    }

    @Test
    @DisplayName("Test createCancel returns null")
    void testCreateCancel() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        CommonServerMessageBlockRequest cancelRequest = request.createCancel();

        // Then
        assertNull(cancelRequest, "Cancel requests cannot create another cancel");
    }

    @Test
    @DisplayName("Test setRequestCredits sets credit value")
    void testSetRequestCredits() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);
        int credits = 10;

        // When
        request.setRequestCredits(credits);

        // Then
        assertEquals(credits, request.getCredit(), "Credits should be set correctly");
    }

    @Test
    @DisplayName("Test setTid sets tree ID")
    void testSetTid() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);
        int treeId = 42;

        // When
        request.setTid(treeId);

        // Then
        assertEquals(treeId, request.getTreeId(), "Tree ID should be set correctly");
    }

    @Test
    @DisplayName("Test isCancel returns true")
    void testIsCancel() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        boolean isCancel = request.isCancel();

        // Then
        assertTrue(isCancel, "Should identify itself as a cancel request");
    }

    @Test
    @DisplayName("Test size calculation")
    void testSize() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);

        // When
        int size = request.size();

        // Then
        // Size should be aligned to 8 bytes: SMB2_HEADER_LENGTH + 4 bytes for cancel structure
        int expectedSize = ((Smb2Constants.SMB2_HEADER_LENGTH + 4 + 7) / 8) * 8;
        assertEquals(expectedSize, size, "Size calculation should be correct and 8-byte aligned");
    }

    @Test
    @DisplayName("Test writeBytesWireFormat writes correct bytes")
    void testWriteBytesWireFormat() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);
        byte[] buffer = new byte[100];
        int offset = 10;

        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(4, bytesWritten, "Should write 4 bytes");
        // Check that structure size (4) is written as 2-byte little-endian
        assertEquals(4, buffer[offset] | (buffer[offset + 1] << 8), "Structure size should be 4");
        assertEquals(0, buffer[offset + 2], "Reserved bytes should be 0");
        assertEquals(0, buffer[offset + 3], "Reserved bytes should be 0");
    }

    @Test
    @DisplayName("Test readBytesWireFormat returns 0")
    void testReadBytesWireFormat() {
        // Given
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, 1L, 0L);
        byte[] buffer = new byte[100];
        int offset = 10;

        // When
        int bytesRead = request.readBytesWireFormat(buffer, offset);

        // Then
        assertEquals(0, bytesRead, "Cancel requests do not read response data");
    }

    @Test
    @DisplayName("Test multiple property settings")
    void testMultiplePropertySettings() {
        // Given
        long mid = 99999L;
        long asyncId = 88888L;
        int credits = 5;
        int treeId = 77;

        // When
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, mid, asyncId);
        request.setRequestCredits(credits);
        request.setTid(treeId);

        // Then
        assertEquals(mid, request.getMid(), "MID should be set correctly");
        assertEquals(asyncId, request.getAsyncId(), "AsyncId should be set correctly");
        assertEquals(credits, request.getCredit(), "Credits should be set correctly");
        assertEquals(treeId, request.getTreeId(), "Tree ID should be set correctly");
        assertTrue((request.getFlags() & SMB2_FLAGS_ASYNC_COMMAND) != 0, "Async flag should be set for non-zero asyncId");
    }

    @Test
    @DisplayName("Test edge case with maximum values")
    void testMaximumValues() {
        // Given
        long maxMid = Long.MAX_VALUE;
        long maxAsyncId = Long.MAX_VALUE;
        int maxCredits = Integer.MAX_VALUE;
        int maxTreeId = Integer.MAX_VALUE;

        // When
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, maxMid, maxAsyncId);
        request.setRequestCredits(maxCredits);
        request.setTid(maxTreeId);

        // Then
        assertEquals(maxMid, request.getMid(), "Should handle maximum MID");
        assertEquals(maxAsyncId, request.getAsyncId(), "Should handle maximum AsyncId");
        assertEquals(maxCredits, request.getCredit(), "Should handle maximum credits");
        assertEquals(maxTreeId, request.getTreeId(), "Should handle maximum tree ID");
    }

    @Test
    @DisplayName("Test edge case with minimum/negative values")
    void testMinimumValues() {
        // Given
        long negativeMid = -1L;
        long negativeAsyncId = -1L;

        // When
        Smb2CancelRequest request = new Smb2CancelRequest(mockConfig, negativeMid, negativeAsyncId);

        // Then
        assertEquals(negativeMid, request.getMid(), "Should handle negative MID");
        assertEquals(negativeAsyncId, request.getAsyncId(), "Should handle negative AsyncId");
        assertTrue((request.getFlags() & SMB2_FLAGS_ASYNC_COMMAND) != 0, "Async flag should be set for non-zero (negative) asyncId");
    }
}
