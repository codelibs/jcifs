package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.codelibs.jcifs.smb.CIFSException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SSPContextTest {

    // Simple, deterministic test double covering all methods of SSPContext.
    private static class DummySSPContext implements SSPContext {
        private byte[] signingKey;
        private boolean established;
        private String nbName;
        private ASN1ObjectIdentifier[] supportedMechs;
        private int flags;
        private boolean integrity;
        private boolean disposed;

        DummySSPContext(byte[] signingKey, boolean established, String nbName, ASN1ObjectIdentifier[] supportedMechs, int flags,
                boolean integrity) {
            this.signingKey = signingKey;
            this.established = established;
            this.nbName = nbName;
            this.supportedMechs = supportedMechs != null ? supportedMechs.clone() : new ASN1ObjectIdentifier[0];
            this.flags = flags;
            this.integrity = integrity;
        }

        @Override
        public byte[] getSigningKey() throws CIFSException {
            if (this.signingKey == null) {
                throw new CIFSException("signing key not available");
            }
            return this.signingKey.clone();
        }

        @Override
        public boolean isEstablished() {
            return this.established;
        }

        @Override
        public byte[] initSecContext(byte[] token, int off, int len) throws CIFSException {
            if (token == null) {
                if (len == 0) {
                    return new byte[0];
                }
                throw new CIFSException("token is null but len > 0");
            }
            if (off < 0 || len < 0 || off > token.length || off + len > token.length) {
                throw new CIFSException("invalid offset/length");
            }
            return Arrays.copyOfRange(token, off, off + len);
        }

        @Override
        public String getNetbiosName() {
            return this.nbName;
        }

        @Override
        public void dispose() throws CIFSException {
            if (this.disposed) {
                throw new CIFSException("already disposed");
            }
            this.disposed = true;
            this.established = false;
        }

        @Override
        public boolean isSupported(ASN1ObjectIdentifier mechanism) {
            if (mechanism == null) {
                return false;
            }
            for (ASN1ObjectIdentifier m : this.supportedMechs) {
                if (mechanism.equals(m)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public boolean isPreferredMech(ASN1ObjectIdentifier selectedMech) {
            return this.supportedMechs.length > 0 && Objects.equals(this.supportedMechs[0], selectedMech);
        }

        @Override
        public int getFlags() {
            return this.flags;
        }

        @Override
        public ASN1ObjectIdentifier[] getSupportedMechs() {
            return this.supportedMechs.clone();
        }

        @Override
        public boolean supportsIntegrity() {
            return this.integrity;
        }

        @Override
        public byte[] calculateMIC(byte[] data) throws CIFSException {
            if (data == null) {
                throw new CIFSException("data is null");
            }
            // Trivial MIC: 1-byte sum of all unsigned bytes
            int sum = 0;
            for (byte b : data) {
                sum = (sum + (b & 0xFF)) & 0xFF;
            }
            return new byte[] { (byte) sum };
        }

        @Override
        public void verifyMIC(byte[] data, byte[] mic) throws CIFSException {
            if (data == null || mic == null) {
                throw new CIFSException("data/mic is null");
            }
            byte[] expected = calculateMIC(data);
            if (mic.length != expected.length || mic[0] != expected[0]) {
                throw new CIFSException("MIC mismatch");
            }
        }

        @Override
        public boolean isMICAvailable() {
            // Available if context is established and integrity is supported
            return this.established && this.integrity;
        }
    }

    @Nested
    @DisplayName("Happy path behavior")
    class HappyPath {
        @Test
        @DisplayName("All getters return configured values and MIC roundtrips")
        void testAllMethodsHappyPath() throws Exception {
            // Arrange
            ASN1ObjectIdentifier mech1 = new ASN1ObjectIdentifier("1.2.840.113554.1.2.2"); // Kerberos V5
            ASN1ObjectIdentifier mech2 = new ASN1ObjectIdentifier("1.3.6.1.5.5.2"); // SPNEGO
            DummySSPContext ctx =
                    new DummySSPContext(new byte[] { 1, 2, 3 }, true, "NBHOST", new ASN1ObjectIdentifier[] { mech1, mech2 }, 0xA5, true);

            // Act & Assert
            assertArrayEquals(new byte[] { 1, 2, 3 }, ctx.getSigningKey(), "signing key");
            assertTrue(ctx.isEstablished(), "should be established");

            byte[] in = new byte[] { 9, 8, 7, 6 };
            assertArrayEquals(new byte[] { 8, 7 }, ctx.initSecContext(in, 1, 2), "slice should match");

            assertEquals("NBHOST", ctx.getNetbiosName(), "NetBIOS name");

            assertEquals(0xA5, ctx.getFlags(), "flags");
            assertTrue(ctx.supportsIntegrity(), "integrity supported");
            assertTrue(ctx.isMICAvailable(), "MIC available when established + integrity");

            assertTrue(ctx.isSupported(mech1), "mech1 supported");
            assertTrue(ctx.isPreferredMech(mech1), "first supported is preferred");
            assertArrayEquals(new ASN1ObjectIdentifier[] { mech1, mech2 }, ctx.getSupportedMechs(), "supported mechs");

            // MIC roundtrip: calculate then verify
            byte[] data = new byte[] { 10, 20, 30 };
            byte[] mic = ctx.calculateMIC(data);
            assertNotNull(mic);
            ctx.verifyMIC(data, mic); // should not throw
        }
    }

    @Nested
    @DisplayName("Invalid and null inputs")
    class InvalidInputs {
        @Test
        @DisplayName("getSigningKey throws when unavailable")
        void testGetSigningKeyThrows() {
            DummySSPContext ctx = new DummySSPContext(null, false, null, null, 0, false);
            CIFSException ex = assertThrows(CIFSException.class, ctx::getSigningKey);
            assertTrue(ex.getMessage().contains("signing key"));
        }

        @Test
        @DisplayName("initSecContext throws on invalid ranges")
        void testInitSecContextInvalidRanges() {
            DummySSPContext ctx = new DummySSPContext(new byte[] { 1 }, false, null, null, 0, false);
            byte[] buf = new byte[] { 1, 2, 3 };
            assertThrows(CIFSException.class, () -> ctx.initSecContext(buf, -1, 1));
            assertThrows(CIFSException.class, () -> ctx.initSecContext(buf, 0, -1));
            assertThrows(CIFSException.class, () -> ctx.initSecContext(buf, 3, 1));
            assertThrows(CIFSException.class, () -> ctx.initSecContext(buf, 2, 2));
        }

        @Test
        @DisplayName("initSecContext null token edge cases")
        void testInitSecContextNullToken() throws Exception {
            DummySSPContext ctx = new DummySSPContext(new byte[] { 1 }, false, null, null, 0, false);
            // len == 0 is allowed and returns empty token
            assertArrayEquals(new byte[0], ctx.initSecContext(null, 0, 0));
            // len > 0 is invalid
            assertThrows(CIFSException.class, () -> ctx.initSecContext(null, 0, 1));
        }

        @Test
        @DisplayName("verifyMIC throws on mismatch and nulls")
        void testVerifyMICThrows() throws Exception {
            DummySSPContext ctx = new DummySSPContext(new byte[] { 1 }, true, null, null, 0, true);
            byte[] data = new byte[] { 1, 2, 3 };
            byte[] wrongMic = new byte[] { 0 };
            assertThrows(CIFSException.class, () -> ctx.verifyMIC(data, wrongMic));
            assertThrows(CIFSException.class, () -> ctx.verifyMIC(null, new byte[] { 0 }));
            assertThrows(CIFSException.class, () -> ctx.verifyMIC(data, null));
        }

        @Test
        @DisplayName("dispose toggles state and is not idempotent")
        void testDisposeBehavior() throws Exception {
            DummySSPContext ctx = new DummySSPContext(new byte[] { 1 }, true, null, null, 0, false);
            ctx.dispose();
            assertFalse(ctx.isEstablished(), "disposed context should not be established");
            CIFSException ex = assertThrows(CIFSException.class, ctx::dispose);
            assertTrue(ex.getMessage().contains("disposed"));
        }

        @Test
        @DisplayName("Supported/preferred mech edge cases (null, empty, unknown)")
        void testMechanismEdges() {
            DummySSPContext empty = new DummySSPContext(new byte[] { 1 }, false, "", new ASN1ObjectIdentifier[0], 0, false);
            assertFalse(empty.isSupported(new ASN1ObjectIdentifier("1.2.3")));
            assertFalse(empty.isPreferredMech(new ASN1ObjectIdentifier("1.2.3")));
            assertFalse(empty.isPreferredMech(null));
            assertFalse(empty.isSupported(null));
            assertEquals("", empty.getNetbiosName(), "supports empty NetBIOS name");
        }
    }

    @Nested
    @DisplayName("Parameterized initSecContext slices")
    class ParameterizedInit {
        static Stream<Arguments> validRanges() {
            byte[] src = new byte[] { 0, 1, 2, 3 };
            return Stream.of(Arguments.of(src, 0, 0, new byte[] {}), Arguments.of(src, 0, 4, new byte[] { 0, 1, 2, 3 }),
                    Arguments.of(src, 1, 2, new byte[] { 1, 2 }), Arguments.of(src, 3, 1, new byte[] { 3 }));
        }

        @ParameterizedTest(name = "slice off={1}, len={2}")
        @MethodSource("validRanges")
        void testSlices(byte[] src, int off, int len, byte[] expected) throws Exception {
            DummySSPContext ctx = new DummySSPContext(new byte[] { 9 }, false, null, null, 0, false);
            assertArrayEquals(expected, ctx.initSecContext(src, off, len));
        }
    }

    @Nested
    @DisplayName("Mockito interactions")
    class MockitoInteractions {

        @Mock
        SSPContext mockCtx;

        // Helper exercising all SSPContext methods to verify call interactions.
        private void useContext(SSPContext ctx) throws Exception {
            ctx.getSigningKey();
            ctx.isEstablished();
            ctx.initSecContext(new byte[] { 1, 2, 3 }, 1, 1);
            ctx.getNetbiosName();
            ctx.isSupported(new ASN1ObjectIdentifier("1.2.3"));
            ctx.isPreferredMech(new ASN1ObjectIdentifier("1.2.3"));
            ctx.getFlags();
            ctx.getSupportedMechs();
            ctx.supportsIntegrity();
            byte[] mic = ctx.calculateMIC(new byte[] { 5 });
            ctx.verifyMIC(new byte[] { 5 }, mic);
            ctx.isMICAvailable();
            ctx.dispose();
        }

        @Test
        @DisplayName("Verifies calls and argument flow across methods")
        void testInteractions() throws Exception {
            // Arrange
            when(mockCtx.getSigningKey()).thenReturn(new byte[] { 7 });
            when(mockCtx.isEstablished()).thenReturn(true);
            when(mockCtx.initSecContext(any(byte[].class), anyInt(), anyInt())).thenReturn(new byte[] { 9 });
            when(mockCtx.getNetbiosName()).thenReturn("NB");
            when(mockCtx.isSupported(any())).thenReturn(true);
            when(mockCtx.isPreferredMech(any())).thenReturn(false);
            when(mockCtx.getFlags()).thenReturn(123);
            when(mockCtx.getSupportedMechs()).thenReturn(new ASN1ObjectIdentifier[] { new ASN1ObjectIdentifier("1.2.3") });
            when(mockCtx.supportsIntegrity()).thenReturn(true);
            when(mockCtx.calculateMIC(any(byte[].class))).thenReturn(new byte[] { 42 });
            // verifyMIC returns void; no stubbing needed
            when(mockCtx.isMICAvailable()).thenReturn(true);

            // Act
            useContext(mockCtx);

            // Assert: verify key interactions and ordering where meaningful
            InOrder inOrder = inOrder(mockCtx);
            inOrder.verify(mockCtx).getSigningKey();
            inOrder.verify(mockCtx).isEstablished();
            inOrder.verify(mockCtx).initSecContext(any(byte[].class), eq(1), eq(1));
            inOrder.verify(mockCtx).getNetbiosName();
            inOrder.verify(mockCtx).isSupported(any());
            inOrder.verify(mockCtx).isPreferredMech(any());
            inOrder.verify(mockCtx).getFlags();
            inOrder.verify(mockCtx).getSupportedMechs();
            inOrder.verify(mockCtx).supportsIntegrity();
            inOrder.verify(mockCtx).calculateMIC(any(byte[].class));
            inOrder.verify(mockCtx).verifyMIC(any(byte[].class), any(byte[].class));
            inOrder.verify(mockCtx).isMICAvailable();
            inOrder.verify(mockCtx).dispose();

            // Also ensure no unexpected calls
            verifyNoMoreInteractions(mockCtx);
        }

        @Test
        @DisplayName("Never calculates MIC when integrity unsupported")
        void testNoMicCalculationWhenIntegrityUnsupported() throws Exception {
            // Only stub supportsIntegrity - isEstablished won't be called due to short-circuit
            when(mockCtx.supportsIntegrity()).thenReturn(false);

            // A small consumer that only uses MIC if advertised as available
            byte[] data = new byte[] { 1, 2 };
            if (mockCtx.supportsIntegrity() && mockCtx.isEstablished()) {
                mockCtx.calculateMIC(data);
            }

            // Verify that calculateMIC was never called
            verify(mockCtx, never()).calculateMIC(any());
            // Verify that supportsIntegrity was checked once
            verify(mockCtx, times(1)).supportsIntegrity();
            // Due to short-circuit evaluation, isEstablished should never be called
            // when supportsIntegrity returns false
            verify(mockCtx, never()).isEstablished();
        }
    }
}
