package jcifs.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.smb.NtStatus;

class ServerMessageBlock2ResponseTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private Smb2SigningDigest mockDigest;

    @Mock
    private CommonServerMessageBlockRequest mockRequest;

    @Mock
    private CommonServerMessageBlockResponse mockNextResponse;

    private TestServerMessageBlock2Response response;

    // Test implementation of abstract ServerMessageBlock2Response
    private static class TestServerMessageBlock2Response extends ServerMessageBlock2Response {

        private ServerMessageBlock2 nextBlock;
        private boolean async = false;
        private boolean retainPayload = false;
        private byte[] rawPayload;
        private Smb2SigningDigest digest;

        public TestServerMessageBlock2Response(Configuration config) {
            super(config);
        }

        public TestServerMessageBlock2Response(Configuration config, int command) {
            super(config, command);
        }

        @Override
        public ServerMessageBlock2 getNext() {
            return nextBlock;
        }

        @Override
        public void setNext(ServerMessageBlock2 next) {
            this.nextBlock = next;
        }

        // Helper methods to manipulate parent's private fields via reflection or protected methods
        public void setStatusForTest(int status) {
            // Workaround: Use reflection to set private status field
            try {
                java.lang.reflect.Field statusField = ServerMessageBlock2.class.getDeclaredField("status");
                statusField.setAccessible(true);
                statusField.set(this, status);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public void setFlagsForTest(int flags) {
            // Workaround: Use reflection to set private flags field
            try {
                java.lang.reflect.Field flagsField = ServerMessageBlock2.class.getDeclaredField("flags");
                flagsField.setAccessible(true);
                flagsField.set(this, flags);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public boolean isAsync() {
            return async;
        }

        public void setAsync(boolean async) {
            this.async = async;
        }

        @Override
        public boolean isRetainPayload() {
            return retainPayload;
        }

        public void setRetainPayload(boolean retainPayload) {
            this.retainPayload = retainPayload;
        }

        @Override
        public void setRawPayload(byte[] payload) {
            this.rawPayload = payload;
        }

        public byte[] getRawPayload() {
            return rawPayload;
        }

        // Helper method to set credit since parent's setter is final
        public void setCreditForTest(int credit) {
            setCredit(credit);
        }

        @Override
        public Smb2SigningDigest getDigest() {
            return digest;
        }

        public void setDigest(Smb2SigningDigest digest) {
            this.digest = digest;
        }

        @Override
        protected int readBytesWireFormat(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
            // Simple implementation for testing
            return 0;
        }

        @Override
        protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
            // Simple implementation for testing
            return 0;
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.isRequireSecureNegotiate()).thenReturn(false);
        response = new TestServerMessageBlock2Response(mockConfig);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should construct with config only")
        void testConstructorWithConfig() {
            TestServerMessageBlock2Response resp = new TestServerMessageBlock2Response(mockConfig);
            assertNotNull(resp);
            assertSame(mockConfig, resp.getConfig());
        }

        @Test
        @DisplayName("Should construct with config and command")
        void testConstructorWithConfigAndCommand() {
            int command = 0x01;
            TestServerMessageBlock2Response resp = new TestServerMessageBlock2Response(mockConfig, command);
            assertNotNull(resp);
            assertSame(mockConfig, resp.getConfig());
        }
    }

    @Nested
    @DisplayName("Response Chaining Tests")
    class ResponseChainingTests {

        @Test
        @DisplayName("Should return next response")
        void testGetNextResponse() {
            TestServerMessageBlock2Response nextResponse = new TestServerMessageBlock2Response(mockConfig);
            response.setNext(nextResponse);

            CommonServerMessageBlockResponse result = response.getNextResponse();

            assertSame(nextResponse, result);
        }

        @Test
        @DisplayName("Should return null when no next response")
        void testGetNextResponseNull() {
            CommonServerMessageBlockResponse result = response.getNextResponse();

            assertNull(result);
        }

        @Test
        @DisplayName("Should prepare next response")
        void testPrepare() {
            TestServerMessageBlock2Response nextResponse = mock(TestServerMessageBlock2Response.class);
            response.setNext(nextResponse);

            response.prepare(mockRequest);

            verify(nextResponse).prepare(mockRequest);
        }

        @Test
        @DisplayName("Should not throw when preparing with null next response")
        void testPrepareWithNullNext() {
            assertDoesNotThrow(() -> response.prepare(mockRequest));
        }
    }

    @Nested
    @DisplayName("State Management Tests")
    class StateManagementTests {

        @Test
        @DisplayName("Should reset state correctly")
        void testReset() {
            // Set initial state
            response.received();
            assertTrue(response.isReceived());

            // Reset
            response.reset();

            assertFalse(response.isReceived());
        }

        @Test
        @DisplayName("Should handle received notification")
        void testReceived() throws InterruptedException {
            CountDownLatch latch = new CountDownLatch(1);

            Thread waiter = new Thread(() -> {
                synchronized (response) {
                    try {
                        if (!response.isReceived()) {
                            response.wait(1000);
                        }
                        latch.countDown();
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            });

            waiter.start();
            Thread.sleep(50); // Give waiter time to start

            response.received();

            assertTrue(latch.await(500, TimeUnit.MILLISECONDS));
            assertTrue(response.isReceived());
        }

        @Test
        @DisplayName("Should handle async pending status")
        void testReceivedAsyncPending() throws InterruptedException {
            response.setAsync(true);
            response.setStatusForTest(NtStatus.NT_STATUS_PENDING);

            CountDownLatch latch = new CountDownLatch(1);

            Thread waiter = new Thread(() -> {
                synchronized (response) {
                    try {
                        response.wait(100);
                        latch.countDown();
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            });

            waiter.start();
            Thread.sleep(50);

            response.received();

            assertTrue(latch.await(500, TimeUnit.MILLISECONDS));
            assertFalse(response.isReceived()); // Should not be marked as received
        }

        @Test
        @DisplayName("Should handle exception")
        void testException() {
            Exception testException = new Exception("Test exception");

            response.exception(testException);

            assertTrue(response.isError());
            assertTrue(response.isReceived());
            assertSame(testException, response.getException());
        }

        @Test
        @DisplayName("Should handle error")
        void testError() throws InterruptedException {
            CountDownLatch latch = new CountDownLatch(1);

            Thread waiter = new Thread(() -> {
                synchronized (response) {
                    try {
                        if (!response.isError()) {
                            response.wait(1000);
                        }
                        latch.countDown();
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            });

            waiter.start();
            Thread.sleep(50);

            response.error();

            assertTrue(latch.await(500, TimeUnit.MILLISECONDS));
            assertTrue(response.isError());
        }

        @Test
        @DisplayName("Should clear received state")
        void testClearReceived() {
            response.received();
            assertTrue(response.isReceived());

            response.clearReceived();

            assertFalse(response.isReceived());
        }
    }

    @Nested
    @DisplayName("Signature Tests")
    class SignatureTests {

        @Test
        @DisplayName("Should detect signed packet")
        void testIsSigned() {
            response.setFlagsForTest(ServerMessageBlock2.SMB2_FLAGS_SIGNED);

            assertTrue(response.isSigned());
        }

        @Test
        @DisplayName("Should detect unsigned packet")
        void testIsNotSigned() {
            response.setFlagsForTest(0);

            assertFalse(response.isSigned());
        }

        @Test
        @DisplayName("Should verify signature successfully")
        void testVerifySignatureSuccess() {
            byte[] buffer = new byte[100];
            response.setDigest(mockDigest);
            when(mockDigest.verify(buffer, 0, 100, 0, response)).thenReturn(false);

            boolean result = response.verifySignature(buffer, 0, 100);

            assertTrue(result);
            assertFalse(response.isVerifyFailed());
        }

        @Test
        @DisplayName("Should handle signature verification failure")
        void testVerifySignatureFailure() {
            byte[] buffer = new byte[100];
            response.setDigest(mockDigest);
            when(mockDigest.verify(buffer, 0, 100, 0, response)).thenReturn(true);

            boolean result = response.verifySignature(buffer, 0, 100);

            assertFalse(result);
            assertTrue(response.isVerifyFailed());
        }

        @Test
        @DisplayName("Should skip verification for async responses")
        void testVerifySignatureAsyncSkip() {
            byte[] buffer = new byte[100];
            response.setDigest(mockDigest);
            response.setAsync(true);

            boolean result = response.verifySignature(buffer, 0, 100);

            assertTrue(result);
            verify(mockDigest, never()).verify(any(), anyInt(), anyInt(), anyInt(), any());
        }

        @Test
        @DisplayName("Should skip verification when digest is null")
        void testVerifySignatureNoDigest() {
            byte[] buffer = new byte[100];

            boolean result = response.verifySignature(buffer, 0, 100);

            assertTrue(result);
        }

        @Test
        @DisplayName("Should verify signature on error when secure negotiate required")
        void testVerifySignatureErrorWithSecureNegotiate() {
            byte[] buffer = new byte[100];
            response.setDigest(mockDigest);
            response.setStatusForTest(NtStatus.NT_STATUS_ACCESS_DENIED);
            when(mockConfig.isRequireSecureNegotiate()).thenReturn(true);
            when(mockDigest.verify(buffer, 0, 100, 0, response)).thenReturn(false);

            boolean result = response.verifySignature(buffer, 0, 100);

            assertTrue(result);
            verify(mockDigest).verify(buffer, 0, 100, 0, response);
        }
    }

    @Nested
    @DisplayName("Expiration Tests")
    class ExpirationTests {

        @Test
        @DisplayName("Should get and set expiration")
        void testExpiration() {
            Long expiration = 1000L;

            response.setExpiration(expiration);

            assertEquals(expiration, response.getExpiration());
        }

        @Test
        @DisplayName("Should handle null expiration")
        void testNullExpiration() {
            response.setExpiration(null);

            assertNull(response.getExpiration());
        }
    }

    @Nested
    @DisplayName("Async Handling Tests")
    class AsyncHandlingTests {

        @Test
        @DisplayName("Should get and set async handled")
        void testAsyncHandled() {
            assertFalse(response.isAsyncHandled());

            response.setAsyncHandled(true);

            assertTrue(response.isAsyncHandled());
        }
    }

    @Nested
    @DisplayName("Error Code Tests")
    class ErrorCodeTests {

        @Test
        @DisplayName("Should return status as error code")
        void testGetErrorCode() {
            int status = NtStatus.NT_STATUS_ACCESS_DENIED;
            response.setStatusForTest(status);

            assertEquals(status, response.getErrorCode());
        }
    }

    @Nested
    @DisplayName("Credit Tests")
    class CreditTests {

        @Test
        @DisplayName("Should return credit as granted credits")
        void testGetGrantedCredits() {
            int credits = 10;
            response.setCreditForTest(credits);

            assertEquals(credits, response.getGrantedCredits());
        }
    }

    @Nested
    @DisplayName("Payload Handling Tests")
    class PayloadHandlingTests {

        @Test
        @DisplayName("Should handle response with retained payload")
        void testHaveResponseWithRetainedPayload() throws SMBProtocolDecodingException {
            byte[] buffer = { 1, 2, 3, 4, 5 };
            response.setRetainPayload(true);
            response.setDigest(null);

            response.haveResponse(buffer, 1, 3);

            byte[] payload = response.getRawPayload();
            assertNotNull(payload);
            assertEquals(3, payload.length);
            assertArrayEquals(new byte[] { 2, 3, 4 }, payload);
            assertTrue(response.isReceived());
            assertFalse(response.isAsyncHandled());
        }

        @Test
        @DisplayName("Should handle response without retained payload")
        void testHaveResponseWithoutRetainedPayload() throws SMBProtocolDecodingException {
            byte[] buffer = { 1, 2, 3, 4, 5 };
            response.setRetainPayload(false);
            response.setDigest(null);

            response.haveResponse(buffer, 1, 3);

            assertNull(response.getRawPayload());
            assertTrue(response.isReceived());
        }

        @Test
        @DisplayName("Should throw exception on signature verification failure")
        void testHaveResponseSignatureFailure() {
            byte[] buffer = new byte[100];
            response.setDigest(mockDigest);
            when(mockDigest.verify(buffer, 0, 100, 0, response)).thenReturn(true);

            SMBProtocolDecodingException exception =
                    assertThrows(SMBProtocolDecodingException.class, () -> response.haveResponse(buffer, 0, 100));

            assertTrue(exception.getMessage().contains("Signature verification failed"));
        }
    }

    @Nested
    @DisplayName("Concurrency Tests")
    class ConcurrencyTests {

        @Test
        @DisplayName("Should handle concurrent received notifications")
        void testConcurrentReceived() throws InterruptedException {
            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch endLatch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                new Thread(() -> {
                    try {
                        startLatch.await();
                        response.received();
                        endLatch.countDown();
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }).start();
            }

            startLatch.countDown();
            assertTrue(endLatch.await(1, TimeUnit.SECONDS));
            assertTrue(response.isReceived());
        }

        @Test
        @DisplayName("Should handle concurrent error notifications")
        void testConcurrentError() throws InterruptedException {
            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch endLatch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                new Thread(() -> {
                    try {
                        startLatch.await();
                        response.error();
                        endLatch.countDown();
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }).start();
            }

            startLatch.countDown();
            assertTrue(endLatch.await(1, TimeUnit.SECONDS));
            assertTrue(response.isError());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = { NtStatus.NT_STATUS_SUCCESS, NtStatus.NT_STATUS_PENDING, NtStatus.NT_STATUS_ACCESS_DENIED,
            NtStatus.NT_STATUS_INVALID_PARAMETER })
    @DisplayName("Should handle various status codes")
    void testVariousStatusCodes(int status) {
        response.setStatusForTest(status);
        assertEquals(status, response.getErrorCode());
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 10, 100, 255 })
    @DisplayName("Should handle various credit values")
    void testVariousCreditValues(int credits) {
        response.setCreditForTest(credits);
        assertEquals(credits, response.getGrantedCredits());
    }
}
