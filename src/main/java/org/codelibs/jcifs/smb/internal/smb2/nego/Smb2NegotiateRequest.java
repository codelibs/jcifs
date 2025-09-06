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
package org.codelibs.jcifs.smb.internal.smb2.nego;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.SmbNegotiationRequest;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Negotiate Protocol request message.
 *
 * This command is used to negotiate the SMB protocol dialect
 * and security parameters between client and server.
 *
 * @author mbechler
 */
public class Smb2NegotiateRequest extends ServerMessageBlock2Request<Smb2NegotiateResponse> implements SmbNegotiationRequest {

    private final int[] dialects;
    private int capabilities;
    private final byte[] clientGuid = new byte[16];
    private final int securityMode;
    private final NegotiateContextRequest[] negotiateContexts;
    private byte[] preauthSalt;

    /**
     * Constructs an SMB2 negotiate request with the specified configuration and security mode.
     *
     * @param config the configuration for this request
     * @param securityMode the security mode flags for negotiation
     */
    public Smb2NegotiateRequest(final Configuration config, final int securityMode) {
        super(config, SMB2_NEGOTIATE);
        this.securityMode = securityMode;

        if (!config.isDfsDisabled()) {
            this.capabilities |= Smb2Constants.SMB2_GLOBAL_CAP_DFS;
        }

        if (config.isEncryptionEnabled() && config.getMaximumVersion() != null
                && config.getMaximumVersion().atLeast(DialectVersion.SMB300)) {
            this.capabilities |= Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION;
        }

        final Set<DialectVersion> dvs =
                DialectVersion.range(DialectVersion.max(DialectVersion.SMB202, config.getMinimumVersion()), config.getMaximumVersion());

        this.dialects = new int[dvs.size()];
        int i = 0;
        for (final DialectVersion ver : dvs) {
            this.dialects[i] = ver.getDialect();
            i++;
        }

        if (config.getMaximumVersion().atLeast(DialectVersion.SMB210)) {
            System.arraycopy(config.getMachineId(), 0, this.clientGuid, 0, this.clientGuid.length);
        }

        final List<NegotiateContextRequest> negoContexts = new LinkedList<>();
        if (config.getMaximumVersion() != null && config.getMaximumVersion().atLeast(DialectVersion.SMB311)) {
            final byte[] salt = new byte[32];
            config.getRandom().nextBytes(salt);
            negoContexts.add(
                    new PreauthIntegrityNegotiateContext(config, new int[] { PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512 }, salt));
            this.preauthSalt = salt;

            if (config.isEncryptionEnabled()) {
                // Build cipher list based on AES-256 support
                List<Integer> ciphers = new ArrayList<>();

                // Prefer GCM over CCM for better performance
                if (config.isAES256Enabled()) {
                    ciphers.add(EncryptionNegotiateContext.CIPHER_AES256_GCM);
                    ciphers.add(EncryptionNegotiateContext.CIPHER_AES256_CCM);
                }

                // Always include AES-128 for compatibility
                ciphers.add(EncryptionNegotiateContext.CIPHER_AES128_GCM);
                ciphers.add(EncryptionNegotiateContext.CIPHER_AES128_CCM);

                int[] cipherArray = ciphers.stream().mapToInt(Integer::intValue).toArray();
                negoContexts.add(new EncryptionNegotiateContext(config, cipherArray));
            }

            // Add compression context for SMB3 compression support
            if (config.isCompressionEnabled()) {
                negoContexts.add(new CompressionNegotiateContext(config, new int[] { CompressionNegotiateContext.COMPRESSION_LZ77,
                        CompressionNegotiateContext.COMPRESSION_LZ77_HUFFMAN, CompressionNegotiateContext.COMPRESSION_LZNT1 }));
            }
        }

        this.negotiateContexts = negoContexts.toArray(new NegotiateContextRequest[negoContexts.size()]);
    }

    /**
     * Gets the security mode flags for this negotiation request.
     *
     * @return the securityMode
     */
    public int getSecurityMode() {
        return this.securityMode;
    }

    @Override
    public boolean isSigningEnforced() {
        return (getSecurityMode() & Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0;
    }

    /**
     * Gets the client capabilities flags.
     *
     * @return the capabilities
     */
    public int getCapabilities() {
        return this.capabilities;
    }

    /**
     * Gets the array of SMB dialect versions supported by the client.
     *
     * @return the dialects
     */
    public int[] getDialects() {
        return this.dialects;
    }

    /**
     * Gets the client GUID used for identification.
     *
     * @return the clientGuid
     */
    public byte[] getClientGuid() {
        return this.clientGuid;
    }

    /**
     * Gets the negotiate contexts for SMB 3.1.1 negotiation.
     *
     * @return the negotiateContexts
     */
    public NegotiateContextRequest[] getNegotiateContexts() {
        return this.negotiateContexts;
    }

    /**
     * Gets the pre-authentication integrity salt for SMB 3.1.1.
     *
     * @return the preauthSalt
     */
    public byte[] getPreauthSalt() {
        return this.preauthSalt;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request#createResponse(org.codelibs.jcifs.smb.CIFSContext,
     *      org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2NegotiateResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2NegotiateResponse> req) {
        return new Smb2NegotiateResponse(tc.getConfig());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        int size = Smb2Constants.SMB2_HEADER_LENGTH + 36 + size8(2 * this.dialects.length, 4);
        if (this.negotiateContexts != null) {
            for (final NegotiateContextRequest ncr : this.negotiateContexts) {
                size += 8 + size8(ncr.size());
            }
        }
        return size8(size);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(36, dst, dstIndex);
        SMBUtil.writeInt2(this.dialects.length, dst, dstIndex + 2);
        dstIndex += 4;

        SMBUtil.writeInt2(this.securityMode, dst, dstIndex);
        SMBUtil.writeInt2(0, dst, dstIndex + 2); // Reserved
        dstIndex += 4;

        SMBUtil.writeInt4(this.capabilities, dst, dstIndex);
        dstIndex += 4;

        System.arraycopy(this.clientGuid, 0, dst, dstIndex, 16);
        dstIndex += 16;

        // if SMB 3.11 support negotiateContextOffset/negotiateContextCount
        int negotitateContextOffsetOffset = 0;
        if (this.negotiateContexts == null || this.negotiateContexts.length == 0) {
            SMBUtil.writeInt8(0, dst, dstIndex);
        } else {
            negotitateContextOffsetOffset = dstIndex;
            SMBUtil.writeInt2(this.negotiateContexts.length, dst, dstIndex + 4);
            SMBUtil.writeInt2(0, dst, dstIndex + 6);
        }
        dstIndex += 8;

        for (final int dialect : this.dialects) {
            SMBUtil.writeInt2(dialect, dst, dstIndex);
            dstIndex += 2;
        }

        dstIndex += pad8(dstIndex);

        if (this.negotiateContexts != null && this.negotiateContexts.length != 0) {
            SMBUtil.writeInt4(dstIndex - getHeaderStart(), dst, negotitateContextOffsetOffset);
            for (final NegotiateContextRequest nc : this.negotiateContexts) {
                SMBUtil.writeInt2(nc.getContextType(), dst, dstIndex);
                final int lenOffset = dstIndex + 2;
                dstIndex += 4;
                SMBUtil.writeInt4(0, dst, dstIndex);
                dstIndex += 4; // Reserved
                final int dataLen = size8(nc.encode(dst, dstIndex));
                SMBUtil.writeInt2(dataLen, dst, lenOffset);
                dstIndex += dataLen;
            }
        }
        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

}
