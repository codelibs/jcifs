/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.codelibs.jcifs.smb.CIFSException;

/**
 * Security Support Provider (SSP) context.
 *
 * This interface provides context for security support provider
 * operations during SMB authentication.
 *
 * @author mbechler
 */
public interface SSPContext {

    /**
     * Gets the signing key for the session.
     * @return the signing key for the session
     * @throws CIFSException if an error occurs retrieving the signing key
     */
    byte[] getSigningKey() throws CIFSException;

    /**
     * Checks whether the security context is established.
     * @return whether the context is established
     */
    boolean isEstablished();

    /**
     * Initializes the security context with the given token.
     * @param token the input token bytes
     * @param off offset into the token array
     * @param len length of token data
     * @return result token
     * @throws SmbException if an SMB protocol error occurs
     * @throws CIFSException if a general CIFS error occurs
     */
    byte[] initSecContext(byte[] token, int off, int len) throws CIFSException;

    /**
     * Gets the NetBIOS name of the remote endpoint.
     * @return the name of the remote endpoint
     */
    String getNetbiosName();

    /**
     * Disposes of the security context and releases any associated resources.
     * @throws CIFSException if an error occurs during disposal
     */
    void dispose() throws CIFSException;

    /**
     * Checks whether the specified security mechanism is supported.
     * @param mechanism the security mechanism OID to check
     * @return whether the specified mechanism is supported
     */
    boolean isSupported(ASN1ObjectIdentifier mechanism);

    /**
     * Checks whether the specified mechanism is the preferred mechanism.
     * @param selectedMech the selected mechanism OID
     * @return whether the specified mechanism is preferred
     */
    boolean isPreferredMech(ASN1ObjectIdentifier selectedMech);

    /**
     * Gets the negotiated context flags.
     * @return context flags
     */
    int getFlags();

    /**
     * Gets the array of supported security mechanism OIDs.
     * @return array of supported mechanism OIDs
     */
    ASN1ObjectIdentifier[] getSupportedMechs();

    /**
     * Checks whether this mechanism supports message integrity.
     * @return whether this mechanisms supports integrity
     */
    boolean supportsIntegrity();

    /**
     * Calculates a Message Integrity Code (MIC) for the given data.
     * @param data the data to calculate MIC for
     * @return MIC
     * @throws CIFSException if an error occurs calculating the MIC
     */
    byte[] calculateMIC(byte[] data) throws CIFSException;

    /**
     * Verifies a Message Integrity Code (MIC) for the given data.
     * @param data the data to verify
     * @param mic the MIC to verify against
     * @throws CIFSException if the MIC verification fails or an error occurs
     */
    void verifyMIC(byte[] data, byte[] mic) throws CIFSException;

    /**
     * Checks whether Message Integrity Code (MIC) is available for use.
     * @return whether MIC can be used
     */
    boolean isMICAvailable();

}
