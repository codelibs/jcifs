package org.codelibs.jcifs.smb1;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.codelibs.jcifs.smb1.util.Hexdump;
import org.codelibs.jcifs.smb1.util.LogStream;

/**
 * To filter 0 len updates and for debugging
 */

public class SigningDigest implements SmbConstants {

    static LogStream log = LogStream.getInstance();

    private MessageDigest digest;
    private byte[] macSigningKey;
    private boolean bypass = false;
    private int updates;
    private int signSequence;

    /**
     * Constructs a new signing digest with the specified MAC signing key.
     *
     * @param macSigningKey the MAC signing key for message authentication
     * @param bypass whether to bypass MAC signing
     * @throws SmbException if MD5 algorithm is not available
     */
    public SigningDigest(final byte[] macSigningKey, final boolean bypass) throws SmbException {
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (final NoSuchAlgorithmException ex) {
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
            throw new SmbException("MD5", ex);
        }

        this.macSigningKey = macSigningKey;
        this.bypass = bypass;
        this.updates = 0;
        this.signSequence = 0;

        if (LogStream.level >= 5) {
            log.println("macSigningKey:");
            Hexdump.hexdump(log, macSigningKey, 0, macSigningKey.length);
        }
    }

    /**
     * Constructs a new signing digest using transport and authentication credentials.
     *
     * @param transport the SMB transport for this signing context
     * @param auth the NTLM password authentication credentials
     * @throws SmbException if MD5 algorithm is not available or key generation fails
     */
    public SigningDigest(final SmbTransport transport, final NtlmPasswordAuthentication auth) throws SmbException {
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (final NoSuchAlgorithmException ex) {
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
            throw new SmbException("MD5", ex);
        }

        try {
            switch (LM_COMPATIBILITY) {
            case 0:
            case 1:
            case 2:
                macSigningKey = new byte[40];
                auth.getUserSessionKey(transport.server.encryptionKey, macSigningKey, 0);
                System.arraycopy(auth.getUnicodeHash(transport.server.encryptionKey), 0, macSigningKey, 16, 24);
                break;
            case 3:
            case 4:
            case 5:
                macSigningKey = new byte[16];
                auth.getUserSessionKey(transport.server.encryptionKey, macSigningKey, 0);
                break;
            default:
                macSigningKey = new byte[40];
                auth.getUserSessionKey(transport.server.encryptionKey, macSigningKey, 0);
                System.arraycopy(auth.getUnicodeHash(transport.server.encryptionKey), 0, macSigningKey, 16, 24);
                break;
            }
        } catch (final Exception ex) {
            throw new SmbException("", ex);
        }
        if (LogStream.level >= 5) {
            log.println("LM_COMPATIBILITY=" + LM_COMPATIBILITY);
            Hexdump.hexdump(log, macSigningKey, 0, macSigningKey.length);
        }
    }

    /**
     * Updates the digest with the specified data.
     *
     * @param input the input buffer containing data to digest
     * @param offset the offset in the buffer where data starts
     * @param len the length of data to digest
     */
    public void update(final byte[] input, final int offset, final int len) {
        if (LogStream.level >= 5) {
            log.println("update: " + updates + " " + offset + ":" + len);
            Hexdump.hexdump(log, input, offset, Math.min(len, 256));
            log.flush();
        }
        if (len == 0) {
            return; /* CRITICAL */
        }
        digest.update(input, offset, len);
        updates++;
    }

    /**
     * Computes and returns the message digest.
     *
     * @return the computed digest bytes
     */
    public byte[] digest() {
        byte[] b = digest.digest();

        if (LogStream.level >= 5) {
            log.println("digest: ");
            Hexdump.hexdump(log, b, 0, b.length);
            log.flush();
        }
        updates = 0;

        return b;
    }

    /**
     * Performs MAC signing of the SMB.  This is done as follows.
     * The signature field of the SMB is overwritted with the sequence number;
     * The MD5 digest of the MAC signing key + the entire SMB is taken;
     * The first 8 bytes of this are placed in the signature field.
     *
     * @param data The data.
     * @param offset The starting offset at which the SMB header begins.
     * @param length The length of the SMB data starting at offset.
     */
    void sign(final byte[] data, final int offset, final int length, final ServerMessageBlock request, final ServerMessageBlock response) {
        request.signSeq = signSequence;
        if (response != null) {
            response.signSeq = signSequence + 1;
            response.verifyFailed = false;
        }

        try {
            update(macSigningKey, 0, macSigningKey.length);
            final int index = offset + SmbConstants.SIGNATURE_OFFSET;
            for (int i = 0; i < 8; i++) {
                data[index + i] = 0;
            }
            ServerMessageBlock.writeInt4(signSequence, data, index);
            update(data, offset, length);
            System.arraycopy(digest(), 0, data, index, 8);
            if (bypass) {
                bypass = false;
                System.arraycopy("BSRSPYL ".getBytes(), 0, data, index, 8);
            }
        } catch (final Exception ex) {
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
        } finally {
            signSequence += 2;
        }
    }

    /**
     * Performs MAC signature verification.  This calculates the signature
     * of the SMB and compares it to the signature field on the SMB itself.
     *
     * @param data The data.
     * @param offset The starting offset at which the SMB header begins.
     * @param length The length of the SMB data starting at offset.
     */
    boolean verify(final byte[] data, final int offset, final ServerMessageBlock response) {
        update(macSigningKey, 0, macSigningKey.length);
        int index = offset;
        update(data, index, SmbConstants.SIGNATURE_OFFSET);
        index += SmbConstants.SIGNATURE_OFFSET;
        final byte[] sequence = new byte[8];
        ServerMessageBlock.writeInt4(response.signSeq, sequence, 0);
        update(sequence, 0, sequence.length);
        index += 8;
        if (response.command == ServerMessageBlock.SMB_COM_READ_ANDX) {
            /* SmbComReadAndXResponse reads directly from the stream into separate byte[] b.
             */
            final SmbComReadAndXResponse raxr = (SmbComReadAndXResponse) response;
            final int length = response.length - raxr.dataLength;
            update(data, index, length - SmbConstants.SIGNATURE_OFFSET - 8);
            update(raxr.b, raxr.off, raxr.dataLength);
        } else {
            update(data, index, response.length - SmbConstants.SIGNATURE_OFFSET - 8);
        }
        final byte[] signature = digest();
        for (int i = 0; i < 8; i++) {
            if (signature[i] != data[offset + SmbConstants.SIGNATURE_OFFSET + i]) {
                if (LogStream.level >= 2) {
                    log.println("signature verification failure");
                    Hexdump.hexdump(log, signature, 0, 8);
                    Hexdump.hexdump(log, data, offset + SmbConstants.SIGNATURE_OFFSET, 8);
                }
                return response.verifyFailed = true;
            }
        }

        return response.verifyFailed = false;
    }

    @Override
    public String toString() {
        return "LM_COMPATIBILITY=" + LM_COMPATIBILITY + " MacSigningKey=" + Hexdump.toHexString(macSigningKey, 0, macSigningKey.length);
    }
}
