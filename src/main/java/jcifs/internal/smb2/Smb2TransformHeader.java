/*
 * © 2025 CodeLibs, Inc.
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
package jcifs.internal.smb2;

import jcifs.Encodable;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Transform Header for encrypted messages
 *
 * This header is used to encrypt SMB2/SMB3 messages and provides the necessary
 * cryptographic parameters for decryption including the nonce, session ID, and
 * authentication tag.
 *
 * @author mbechler
 */
public class Smb2TransformHeader implements Encodable {

    /**
     * Transform header protocol identifier: 0xFD534D42 (0xFD 'S' 'M' 'B')
     */
    public static final int TRANSFORM_PROTOCOL_ID = 0xFD534D42;

    /**
     * Size of the transform header in bytes
     */
    public static final int TRANSFORM_HEADER_SIZE = 52;

    private final byte[] signature = new byte[16];
    private final byte[] nonce = new byte[16];
    private int originalMessageSize;
    private int flags;
    private long sessionId;

    /**
     * Create a new SMB2 Transform Header
     */
    public Smb2TransformHeader() {
    }

    /**
     * Create a new SMB2 Transform Header with specified parameters
     *
     * @param nonce
     *            nonce for encryption (12 bytes for CCM, 16 bytes for GCM)
     * @param originalMessageSize
     *            size of the original unencrypted message
     * @param flags
     *            transform flags (SMB 3.1.1) or encryption algorithm (SMB 3.0/3.0.2)
     * @param sessionId
     *            session identifier
     */
    public Smb2TransformHeader(final byte[] nonce, final int originalMessageSize, final int flags, final long sessionId) {
        if (nonce.length == 12) {
            // For CCM cipher, pad nonce to 16 bytes with zeros
            System.arraycopy(nonce, 0, this.nonce, 0, 12);
            // Last 4 bytes remain zero-initialized
        } else if (nonce.length == 16) {
            // For GCM cipher, use full 16-byte nonce
            System.arraycopy(nonce, 0, this.nonce, 0, 16);
        } else {
            throw new IllegalArgumentException("Nonce must be 12 bytes (CCM) or 16 bytes (GCM)");
        }
        this.originalMessageSize = originalMessageSize;
        this.flags = flags;
        this.sessionId = sessionId;
    }

    /**
     * Gets the signature or authentication tag for the encrypted message
     *
     * @return the signature/authentication tag
     */
    public byte[] getSignature() {
        return this.signature;
    }

    /**
     * Sets the signature or authentication tag for the encrypted message
     *
     * @param signature
     *            the signature/authentication tag to set
     */
    public void setSignature(final byte[] signature) {
        if (signature.length != 16) {
            throw new IllegalArgumentException("Signature must be 16 bytes");
        }
        System.arraycopy(signature, 0, this.signature, 0, 16);
    }

    /**
     * Gets the nonce used for encryption
     *
     * @return the nonce
     */
    public byte[] getNonce() {
        return this.nonce;
    }

    /**
     * Sets the nonce for encryption
     *
     * @param nonce
     *            the nonce to set (12 bytes for CCM, 16 bytes for GCM)
     */
    public void setNonce(final byte[] nonce) {
        if (nonce.length == 12) {
            // For CCM cipher, pad nonce to 16 bytes with zeros
            java.util.Arrays.fill(this.nonce, (byte) 0);
            System.arraycopy(nonce, 0, this.nonce, 0, 12);
        } else if (nonce.length == 16) {
            // For GCM cipher, use full 16-byte nonce
            System.arraycopy(nonce, 0, this.nonce, 0, 16);
        } else {
            throw new IllegalArgumentException("Nonce must be 12 bytes (CCM) or 16 bytes (GCM)");
        }
    }

    /**
     * Gets the size of the original unencrypted message
     *
     * @return the original message size
     */
    public int getOriginalMessageSize() {
        return this.originalMessageSize;
    }

    /**
     * Sets the size of the original unencrypted message
     *
     * @param originalMessageSize
     *            the original message size to set
     */
    public void setOriginalMessageSize(final int originalMessageSize) {
        this.originalMessageSize = originalMessageSize;
    }

    /**
     * Gets the flags field which contains flags in SMB 3.1.1 or encryption algorithm ID in SMB 3.0/3.0.2
     *
     * @return the flags (SMB 3.1.1) or encryption algorithm (SMB 3.0/3.0.2)
     */
    public int getFlags() {
        return this.flags;
    }

    /**
     * Sets the flags field which contains flags in SMB 3.1.1 or encryption algorithm ID in SMB 3.0/3.0.2
     *
     * @param flags
     *            the flags to set
     */
    public void setFlags(final int flags) {
        this.flags = flags;
    }

    /**
     * Gets the session ID associated with this encrypted message
     *
     * @return the session ID
     */
    public long getSessionId() {
        return this.sessionId;
    }

    /**
     * Sets the session ID for this encrypted message
     *
     * @param sessionId
     *            the session ID to set
     */
    public void setSessionId(final long sessionId) {
        this.sessionId = sessionId;
    }

    @Override
    public int size() {
        return TRANSFORM_HEADER_SIZE;
    }

    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        // Protocol ID
        SMBUtil.writeInt4(TRANSFORM_PROTOCOL_ID, dst, dstIndex);
        dstIndex += 4;

        // Signature (16 bytes)
        System.arraycopy(this.signature, 0, dst, dstIndex, 16);
        dstIndex += 16;

        // Nonce (16 bytes)
        System.arraycopy(this.nonce, 0, dst, dstIndex, 16);
        dstIndex += 16;

        // Original message size
        SMBUtil.writeInt4(this.originalMessageSize, dst, dstIndex);
        dstIndex += 4;

        // Reserved (2 bytes)
        SMBUtil.writeInt2(0, dst, dstIndex);
        dstIndex += 2;

        // Flags (2 bytes)
        SMBUtil.writeInt2(this.flags, dst, dstIndex);
        dstIndex += 2;

        // Session ID (8 bytes)
        SMBUtil.writeInt8(this.sessionId, dst, dstIndex);
        dstIndex += 8;

        return dstIndex - start;
    }

    /**
     * Decode a transform header from byte array
     *
     * @param buffer
     *            buffer to decode from
     * @param bufferIndex
     *            offset in buffer
     * @return new transform header instance
     */
    public static Smb2TransformHeader decode(final byte[] buffer, int bufferIndex) {
        final Smb2TransformHeader header = new Smb2TransformHeader();

        // Check protocol ID
        final int protocolId = SMBUtil.readInt4(buffer, bufferIndex);
        if (protocolId != TRANSFORM_PROTOCOL_ID) {
            throw new IllegalArgumentException("Invalid transform header protocol ID: 0x" + Integer.toHexString(protocolId));
        }
        bufferIndex += 4;

        // Read signature
        System.arraycopy(buffer, bufferIndex, header.signature, 0, 16);
        bufferIndex += 16;

        // Read nonce
        System.arraycopy(buffer, bufferIndex, header.nonce, 0, 16);
        bufferIndex += 16;

        // Read original message size
        header.originalMessageSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // Skip reserved (2 bytes)
        bufferIndex += 2;

        // Read flags
        header.flags = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // Read session ID
        header.sessionId = SMBUtil.readInt8(buffer, bufferIndex);

        return header;
    }

    /**
     * Get the associated data for AEAD encryption (everything except signature)
     *
     * @return byte array containing associated data
     */
    public byte[] getAssociatedData() {
        final byte[] aad = new byte[52]; // Use full header size to ensure all data fits
        int index = 0;

        // Protocol ID
        SMBUtil.writeInt4(TRANSFORM_PROTOCOL_ID, aad, index);
        index += 4;

        // Skip signature (16 bytes of zeros for AAD)
        index += 16;

        // Nonce
        System.arraycopy(this.nonce, 0, aad, index, 16);
        index += 16;

        // Original message size
        SMBUtil.writeInt4(this.originalMessageSize, aad, index);
        index += 4;

        // Reserved
        SMBUtil.writeInt2(0, aad, index);
        index += 2;

        // Flags
        SMBUtil.writeInt2(this.flags, aad, index);
        index += 2;

        // Session ID (8 bytes)
        SMBUtil.writeInt8(this.sessionId, aad, index);

        return aad;
    }
}
