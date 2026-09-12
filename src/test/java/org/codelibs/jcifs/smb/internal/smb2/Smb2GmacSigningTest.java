/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb2.nego.SigningNegotiateContext;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * AES-128-GMAC signing, which SMB 3.1.1 negotiates in a SIGNING_CAPABILITIES context.
 *
 * <p>
 * GMAC differs from CMAC in a way that matters structurally: its MAC object cannot be reset and reused, because
 * every message needs a fresh nonce. BouncyCastle enforces that - a second doFinal on a GMAC Mac without
 * re-initialising throws {@code IllegalStateException: GCM cipher cannot be reused for encryption} - so signing
 * two messages in a row is the case that would break a digest written the way the CMAC one is.
 * </p>
 */
class Smb2GmacSigningTest {

    private static final int SIGNATURE_OFFSET = 48;
    private static final int SIGNATURE_LENGTH = 16;
    private static final int FLAGS_OFFSET = 16;
    private static final int MID_OFFSET = 24;

    private byte[] sessionKey;
    private byte[] preauthIntegrityHash;
    private CommonServerMessageBlock request;
    private CommonServerMessageBlock response;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setup() {
        this.sessionKey = new byte[16];
        Arrays.fill(this.sessionKey, (byte) 0xAA);
        this.preauthIntegrityHash = new byte[64];
        Arrays.fill(this.preauthIntegrityHash, (byte) 0xBB);
        this.request = mock(CommonServerMessageBlock.class);
        this.response = mock(CommonServerMessageBlock.class);
    }

    private static byte[] message(final long mid) {
        final byte[] data = new byte[128];
        SMBUtil.writeInt8(mid, data, MID_OFFSET);
        return data;
    }

    private static byte[] signatureOf(final byte[] data) {
        return Arrays.copyOfRange(data, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);
    }

    @Test
    @DisplayName("a GMAC digest signs, and signs a second message without being re-created")
    void gmacSignsRepeatedly() throws GeneralSecurityException {
        final Smb2SigningDigest digest = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311, this.preauthIntegrityHash,
                SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC);

        final byte[] first = message(1L);
        digest.sign(first, 0, first.length, this.request, this.response);
        assertFalse(Arrays.equals(new byte[SIGNATURE_LENGTH], signatureOf(first)), "the first message must be signed");

        // The point of this test. A Mac initialised once and merely reset cannot do this - BouncyCastle throws
        // rather than producing a wrong tag - so a digest that signs one message proves nothing about the second.
        final byte[] second = message(2L);
        assertDoesNotThrow(() -> digest.sign(second, 0, second.length, this.request, this.response),
                "signing a second message must not require a new digest");
        assertFalse(Arrays.equals(new byte[SIGNATURE_LENGTH], signatureOf(second)), "the second message must be signed");
    }

    @Test
    @DisplayName("the signature depends on the message id, because the nonce does")
    void signatureDependsOnMessageId() throws GeneralSecurityException {
        final Smb2SigningDigest digest = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311, this.preauthIntegrityHash,
                SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC);

        final byte[] one = message(1L);
        final byte[] two = message(2L);
        digest.sign(one, 0, one.length, this.request, this.response);
        digest.sign(two, 0, two.length, this.request, this.response);

        // Two messages identical but for the id must get different tags. Were the nonce fixed - or derived from
        // something constant - they would match, and every message on the connection would reuse one nonce, which
        // is the failure GMAC is least forgiving of.
        assertFalse(Arrays.equals(signatureOf(one), signatureOf(two)), "different message ids must produce different signatures");
    }

    @Test
    @DisplayName("GMAC and CMAC produce different signatures over the same bytes")
    void gmacDiffersFromCmac() throws GeneralSecurityException {
        final Smb2SigningDigest gmac = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311, this.preauthIntegrityHash,
                SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC);
        final Smb2SigningDigest cmac = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311, this.preauthIntegrityHash,
                SigningNegotiateContext.SIGNING_ALGO_AES128_CMAC);

        final byte[] viaGmac = message(7L);
        final byte[] viaCmac = message(7L);
        gmac.sign(viaGmac, 0, viaGmac.length, this.request, this.response);
        cmac.sign(viaCmac, 0, viaCmac.length, this.request, this.response);

        // If the algorithm argument were ignored, both would be CMAC and these would match - so this is what
        // catches the negotiated algorithm never actually reaching the Mac.
        assertFalse(Arrays.equals(signatureOf(viaGmac), signatureOf(viaCmac)), "GMAC and CMAC must not agree on a signature");
    }

    @Test
    @DisplayName("an unset algorithm still signs with AES-CMAC, exactly as before")
    void unsetAlgorithmFallsBackToCmac() throws GeneralSecurityException {
        // A 3.1.1 server may return no SIGNING_CAPABILITIES context, in which case MS-SMB2 3.3.5.4 says AES-CMAC.
        // The three-argument constructor is the pre-existing behaviour and must stay byte-identical to passing the
        // CMAC id explicitly, or every existing deployment's signatures change.
        final Smb2SigningDigest legacy = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311, this.preauthIntegrityHash);
        final Smb2SigningDigest explicitCmac = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311,
                this.preauthIntegrityHash, SigningNegotiateContext.SIGNING_ALGO_AES128_CMAC);

        final byte[] viaLegacy = message(11L);
        final byte[] viaExplicit = message(11L);
        legacy.sign(viaLegacy, 0, viaLegacy.length, this.request, this.response);
        explicitCmac.sign(viaExplicit, 0, viaExplicit.length, this.request, this.response);

        assertArrayEquals(signatureOf(viaLegacy), signatureOf(viaExplicit), "the default must remain AES-CMAC, bit for bit");
    }

    @Test
    @DisplayName("a GMAC signature verifies, and a tampered one does not")
    void gmacVerifies() throws GeneralSecurityException {
        final Smb2SigningDigest signer = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311, this.preauthIntegrityHash,
                SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC);
        final Smb2SigningDigest verifier = new Smb2SigningDigest(this.sessionKey, Smb2Constants.SMB2_DIALECT_0311,
                this.preauthIntegrityHash, SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC);

        // Signed as a response, because that is the direction a client verifies, and the nonce's direction bit is
        // read from the message itself - so a verifier that rebuilt the nonce as if it were a request would fail.
        final byte[] data = message(21L);
        SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SERVER_TO_REDIR, data, FLAGS_OFFSET);
        signer.sign(data, 0, data.length, this.request, this.response);

        // verify() reports trouble by returning true, which reads backwards but is the existing contract.
        assertFalse(verifier.verify(data, 0, data.length, 0, this.response), "a correctly signed message must verify");

        data[100] ^= 0x01;
        assertTrue(verifier.verify(data, 0, data.length, 0, this.response), "a tampered message must not verify");
    }
}
