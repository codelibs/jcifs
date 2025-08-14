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
package jcifs.util.transport;

/**
 * Interface for transport response messages.
 * This interface represents responses received from network transports.
 */
public interface Response extends Message {

    /**
     * Checks if the response has been received.
     *
     * @return whether the response is received
     */
    boolean isReceived();

    /**
     * Set received status
     */
    void received();

    /**
     * Unset received status
     */
    void clearReceived();

    /**
     * Gets the number of credits granted by the server.
     *
     * @return number of credits granted by the server
     */
    int getGrantedCredits();

    /**
     * Gets the error status code.
     *
     * @return status code
     */
    int getErrorCode();

    /**
     * Sets the message ID.
     *
     * @param k the message ID to set
     */
    void setMid(long k);

    /**
     * Gets the message ID.
     *
     * @return mid
     */
    long getMid();

    /**
     * Verifies the signature of this response.
     *
     * @param buffer the buffer containing the signature data
     * @param i the starting index in the buffer
     * @param size the size of the signature data
     * @return whether signature verification is successful
     */
    boolean verifySignature(byte[] buffer, int i, int size);

    /**
     * Checks if signature verification failed.
     *
     * @return whether signature verification failed
     */
    boolean isVerifyFailed();

    /**
     * Checks if the response indicates an error.
     *
     * @return whether the response is an error
     */
    boolean isError();

    /**
     * Set error status
     */
    void error();

    /**
     * Gets the expiration time for this response.
     *
     * @return the message timeout
     */
    Long getExpiration();

    /**
     * Sets the expiration time for this response.
     *
     * @param exp the message timeout to set
     */
    void setExpiration(Long exp);

    /**
     * Resets this response to its initial state.
     */
    void reset();

    /**
     * Gets the exception associated with this response.
     *
     * @return an exception linked to an error
     */
    Exception getException();

    /**
     * Sets an exception for this response.
     *
     * @param e the exception to set
     */
    void exception(Exception e);

    /**
     * Gets the next response in the chain.
     *
     * @return chained response
     */
    Response getNextResponse();

}
