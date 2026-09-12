/*
 * © 2017 AgNO3 Gmbh & Co. KG
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.internal.smb2;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.codelibs.jcifs.smb.internal.SMBSigningDigest;
import org.codelibs.jcifs.smb.internal.smb2.nego.SigningNegotiateContext;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Crypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMB2/SMB3 message signing digest implementation.
 *
 * This class handles cryptographic signing of SMB2/SMB3 messages to ensure
 * message integrity and authenticity. It supports different signing algorithms
 * used in various SMB2/SMB3 dialect versions.
 *
 * @author mbechler
 */
public class Smb2SigningDigest implements SMBSigningDigest {

    private static final Logger log = LoggerFactory.getLogger(Smb2SigningDigest.class);

    /**
     *
     */
    private static final int SIGNATURE_OFFSET = 48;
    private static final int SIGNATURE_LENGTH = 16;

    /** Offsets within the SMB2 header, matching ServerMessageBlock2.writeHeaderWireFormat. */
    private static final int COMMAND_OFFSET = 12;
    private static final int FLAGS_OFFSET = 16;
    private static final int MID_OFFSET = 24;

    /** AES-GMAC takes a 12-byte nonce (MS-SMB2 3.1.4.1, [RFC4543]). */
    private static final int GMAC_NONCE_LENGTH = 12;

    /** No SIGNING_CAPABILITIES context was negotiated, so AES-128-CMAC applies. */
    public static final int SIGNING_ALGO_UNSET = -1;

    /** Set in the nonce when the message was sent by the server rather than the client. */
    private static final int NONCE_FLAG_RESPONSE = 0x01;

    /** Set in the nonce when the message is an SMB2 CANCEL request. */
    private static final int NONCE_FLAG_CANCEL = 0x02;

    private final Mac digest;

    /**
     * The signing key, kept because a GMAC Mac has to be re-initialised for every message and initialising needs
     * the key again. Null unless GMAC was negotiated.
     */
    private final byte[] gmacKey;

    /**
     * Constructs a SMB2 signing digest with the specified session key and dialect
     *
     * @param sessionKey
     *            the session key for signing
     * @param dialect
     *            the SMB2 dialect version
     * @param preauthIntegrityHash
     *            the pre-authentication integrity hash (for SMB 3.1.1)
     * @throws GeneralSecurityException
     *             if the signing algorithm cannot be initialized
     *
     */
    public Smb2SigningDigest(final byte[] sessionKey, final int dialect, final byte[] preauthIntegrityHash)
            throws GeneralSecurityException {
        this(sessionKey, dialect, preauthIntegrityHash, SIGNING_ALGO_UNSET);
    }

    /**
     * Constructs a SMB2 signing digest for a negotiated signing algorithm.
     *
     * @param sessionKey
     *            the session key for signing
     * @param dialect
     *            the SMB2 dialect version
     * @param preauthIntegrityHash
     *            the pre-authentication integrity hash (for SMB 3.1.1)
     * @param signingAlgorithm
     *            the algorithm from the SIGNING_CAPABILITIES negotiate context, or {@code -1} when the server
     *            returned none - which means AES-128-CMAC (MS-SMB2 3.3.5.4)
     * @throws GeneralSecurityException
     *             if the signing algorithm cannot be initialized
     */
    public Smb2SigningDigest(final byte[] sessionKey, final int dialect, final byte[] preauthIntegrityHash, final int signingAlgorithm)
            throws GeneralSecurityException {
        Mac m;
        byte[] signingKey;
        boolean gmac = false;
        switch (dialect) {
        case Smb2Constants.SMB2_DIALECT_0202:
        case Smb2Constants.SMB2_DIALECT_0210:
            m = Mac.getInstance("HmacSHA256");
            signingKey = sessionKey;
            break;
        case Smb2Constants.SMB2_DIALECT_0300:
        case Smb2Constants.SMB2_DIALECT_0302:
            signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, new byte[0] /* unimplemented */);
            m = Mac.getInstance("AESCMAC", Crypto.getProvider());
            break;
        case Smb2Constants.SMB2_DIALECT_0311:
            if (preauthIntegrityHash == null) {
                throw new IllegalArgumentException("Missing preauthIntegrityHash for SMB 3.1");
            }
            signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrityHash);
            // Only 3.1.1 negotiates the algorithm. Anything else, including an unset selection, is AES-CMAC -
            // which is what this client used before the context was offered, so the default is unchanged.
            if (signingAlgorithm == SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC) {
                m = Mac.getInstance("AES-GMAC", Crypto.getProvider());
                gmac = true;
            } else {
                m = Mac.getInstance("AESCMAC", Crypto.getProvider());
            }
            break;
        default:
            throw new IllegalArgumentException("Unknown dialect");
        }

        if (gmac) {
            // Deliberately not initialised here. GMAC needs a per-message nonce, and BouncyCastle refuses to
            // reuse an initialised GCM cipher - a second doFinal throws "GCM cipher cannot be reused for
            // encryption" - so the key is kept and init happens per message instead.
            this.gmacKey = signingKey;
        } else {
            m.init(new SecretKeySpec(signingKey, "HMAC"));
            this.gmacKey = null;
        }
        this.digest = m;
    }

    /**
     * Returns the MAC to use for one message, initialised for it.
     *
     * <p>
     * For CMAC and HMAC this is the single instance built in the constructor, reset. For GMAC it is a <em>new</em>
     * instance every time, because the nonce is per message and BouncyCastle tracks key/nonce pairs on the
     * instance: re-initialising one with a nonce it has already seen fails with "cannot reuse nonce for GCM
     * encryption". That guard is right for encryption and wrong for a MAC, where recomputing the same tag over
     * the same message is exactly what verifying does - so one digest would refuse to verify a response it had
     * just signed, and any retried or replayed message would fail on the second look. A fresh instance costs a
     * cipher construction, which is nothing beside the round trip that carried the message.
     * </p>
     *
     * <p>
     * Called with the monitor already held by {@link #sign} or {@link #verify}, so the initialisation and the
     * update that follows are one atomic step even when a digest is shared between threads.
     * </p>
     */
    private Mac prepare(final byte[] data, final int offset) {
        if (this.gmacKey == null) {
            this.digest.reset();
            return this.digest;
        }
        try {
            final Mac gmac = Mac.getInstance("AES-GMAC", Crypto.getProvider());
            gmac.init(new SecretKeySpec(this.gmacKey, "AES"), new IvParameterSpec(gmacNonce(data, offset)));
            return gmac;
        } catch (final NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Failed to initialise GMAC for signing", e);
        }
    }

    /**
     * Builds the AES-GMAC nonce for the message whose header starts at {@code offset}.
     *
     * <p>
     * MS-SMB2 3.1.4.1: 12 bytes, the first 8 set to the MessageId, then four bytes whose least significant bit is
     * zero if the sender is a client and one otherwise, whose penultimate bit is set for an SMB2 CANCEL request,
     * and whose remaining 30 bits are zero. Section 3.1.5.1 has verification use the same syntax.
     * </p>
     *
     * <p>
     * Everything comes out of the message itself, which is what lets one construction serve both directions: the
     * direction bit is the header's own SMB2_FLAGS_SERVER_TO_REDIR, clear on a request this client signs and set
     * on a response it verifies. Only those two bits are taken - copying the flags word wholesale would drag in
     * SMB2_FLAGS_SIGNED, which is set on every signed message, and corrupt the nonce for ordinary traffic.
     * </p>
     *
     * @param data
     *            buffer holding the message
     * @param offset
     *            offset of the SMB2 header within {@code data}
     * @return the 12-byte nonce
     */
    static byte[] gmacNonce(final byte[] data, final int offset) {
        final byte[] nonce = new byte[GMAC_NONCE_LENGTH];

        // The MessageId is already little-endian in the header, and the nonce wants it in that same order, so it
        // is copied rather than re-encoded.
        System.arraycopy(data, offset + MID_OFFSET, nonce, 0, 8);

        final int flags = SMBUtil.readInt4(data, offset + FLAGS_OFFSET);
        final int command = SMBUtil.readInt2(data, offset + COMMAND_OFFSET);

        int trailing = 0;
        if ((flags & ServerMessageBlock2.SMB2_FLAGS_SERVER_TO_REDIR) != 0) {
            trailing |= NONCE_FLAG_RESPONSE;
        }
        if (command == ServerMessageBlock2.SMB2_CANCEL) {
            trailing |= NONCE_FLAG_CANCEL;
        }
        nonce[8] = (byte) trailing;
        return nonce;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.SMBSigningDigest#sign(byte[], int, int, org.codelibs.jcifs.smb.internal.CommonServerMessageBlock,
     *      org.codelibs.jcifs.smb.internal.CommonServerMessageBlock)
     */
    @Override
    public synchronized void sign(final byte[] data, final int offset, final int length, final CommonServerMessageBlock request,
            final CommonServerMessageBlock response) {
        // zero out signature field
        final int index = offset + SIGNATURE_OFFSET;
        for (int i = 0; i < SIGNATURE_LENGTH; i++) {
            data[index + i] = 0;
        }

        // set signed flag
        final int oldFlags = SMBUtil.readInt4(data, offset + FLAGS_OFFSET);
        final int flags = oldFlags | ServerMessageBlock2.SMB2_FLAGS_SIGNED;
        SMBUtil.writeInt4(flags, data, offset + FLAGS_OFFSET);

        // After the header is in its final state, so the nonce is derived from the same bytes the peer will
        // authenticate. Setting SMB2_FLAGS_SIGNED cannot change it - the nonce takes only the direction bit and
        // the command - but deriving it from a header still being edited would be fragile for no reason.
        final Mac mac = prepare(data, offset);

        mac.update(data, offset, length);

        final byte[] sig = mac.doFinal();
        System.arraycopy(sig, 0, data, offset + SIGNATURE_OFFSET, SIGNATURE_LENGTH);
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.SMBSigningDigest#verify(byte[], int, int, int, org.codelibs.jcifs.smb.internal.CommonServerMessageBlock)
     */
    @Override
    public synchronized boolean verify(final byte[] data, final int offset, final int length, final int extraPad,
            final CommonServerMessageBlock msg) {
        final int flags = SMBUtil.readInt4(data, offset + FLAGS_OFFSET);
        if ((flags & ServerMessageBlock2.SMB2_FLAGS_SIGNED) == 0) {
            log.error("The server did not sign a message we expected to be signed");
            return true;
        }

        final byte[] sig = new byte[SIGNATURE_LENGTH];
        System.arraycopy(data, offset + SIGNATURE_OFFSET, sig, 0, SIGNATURE_LENGTH);

        final int index = offset + SIGNATURE_OFFSET;
        for (int i = 0; i < SIGNATURE_LENGTH; i++) {
            data[index + i] = 0;
        }

        // The nonce comes out of the received header, so the direction bit is the server's - which is what makes
        // one construction serve both signing a request and verifying a response.
        final Mac mac = prepare(data, offset);

        mac.update(data, offset, length);

        final byte[] cmp = new byte[SIGNATURE_LENGTH];
        System.arraycopy(mac.doFinal(), 0, cmp, 0, SIGNATURE_LENGTH);
        if (!MessageDigest.isEqual(sig, cmp)) {
            return true;
        }
        return false;
    }

}
