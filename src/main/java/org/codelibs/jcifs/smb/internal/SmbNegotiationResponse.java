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
package org.codelibs.jcifs.smb.internal;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.util.transport.Response;

/**
 * Interface for SMB protocol negotiation response handling.
 * Represents the server's response to a protocol negotiation request, containing negotiated
 * dialect version, security settings, capabilities, and buffer sizes for the SMB connection.
 *
 * @author mbechler
 */
public interface SmbNegotiationResponse extends CommonServerMessageBlock, Response {

    /**
     * Check if the negotiation response is valid
     *
     * @param cifsContext the CIFS context
     * @param request the negotiation request
     * @return whether the protocol negotiation was successful
     */
    boolean isValid(CIFSContext cifsContext, SmbNegotiationRequest request);

    /**
     * Gets the SMB dialect version selected by the server.
     *
     * @return selected dialect
     */
    DialectVersion getSelectedDialect();

    /**
     * Checks whether the server has SMB message signing enabled.
     *
     * @return whether the server has signing enabled
     */
    boolean isSigningEnabled();

    /**
     * Checks whether the server requires SMB message signing.
     *
     * @return whether the server requires signing
     */
    boolean isSigningRequired();

    /**
     * Checks whether the server supports Distributed File System (DFS).
     *
     * @return whether the server supports DFS
     */
    boolean isDFSSupported();

    /**
     * Sets up the given request with negotiated parameters.
     *
     * @param request the request to configure
     */
    void setupRequest(CommonServerMessageBlock request);

    /**
     * Sets up the given response with negotiated parameters.
     *
     * @param resp the response to configure
     */
    void setupResponse(Response resp);

    /**
     * Checks whether SMB message signing has been successfully negotiated.
     *
     * @return whether signing has been negotiated
     */
    boolean isSigningNegotiated();

    /**
     * Checks whether a specific capability has been negotiated.
     *
     * @param cap the capability flag to check
     * @return whether capability is negotiated
     */
    boolean haveCapabilitiy(int cap);

    /**
     * Gets the negotiated send buffer size.
     *
     * @return the send buffer size
     */
    int getSendBufferSize();

    /**
     * Gets the negotiated receive buffer size.
     *
     * @return the receive buffer size
     */
    int getReceiveBufferSize();

    /**
     * Gets the negotiated maximum transaction buffer size.
     *
     * @return the transaction buffer size
     */
    int getTransactionBufferSize();

    /**
     * Gets the number of initial credits granted by the server for SMB2.
     *
     * @return number of initial credits the server grants
     */
    int getInitialCredits();

    /**
     * Checks whether a connection can be reused for the given configuration.
     *
     * @param tc the CIFS context to check compatibility with
     * @param forceSigning whether signing is being forced
     * @return whether a connection can be reused for this config
     */
    boolean canReuse(CIFSContext tc, boolean forceSigning);

}
