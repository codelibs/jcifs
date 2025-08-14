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
package jcifs.internal;

/**
 * Container class for SMB protocol negotiation state.
 * Holds the negotiation request, response, and raw buffer data exchanged
 * between client and server during SMB protocol version negotiation.
 *
 * @author mbechler
 */
public final class SmbNegotiation {

    private final SmbNegotiationRequest request;
    private final SmbNegotiationResponse response;
    private final byte[] negoReqBuffer;
    private final byte[] negoRespBuffer;

    /**
     * @param request
     * @param response
     * @param negoRespBuffer
     * @param negoReqBuffer
     *
     */
    public SmbNegotiation(final SmbNegotiationRequest request, final SmbNegotiationResponse response, final byte[] negoReqBuffer,
            final byte[] negoRespBuffer) {
        this.request = request;
        this.response = response;
        this.negoReqBuffer = negoReqBuffer;
        this.negoRespBuffer = negoRespBuffer;
    }

    /**
     * @return the request
     */
    public SmbNegotiationRequest getRequest() {
        return this.request;
    }

    /**
     * @return the response
     */
    public SmbNegotiationResponse getResponse() {
        return this.response;
    }

    /**
     * @return the negoReqBuffer
     */
    public byte[] getRequestRaw() {
        return this.negoReqBuffer;
    }

    /**
     * @return the negoRespBuffer
     */
    public byte[] getResponseRaw() {
        return this.negoRespBuffer;
    }
}
