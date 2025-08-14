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
 * Base class for transport-layer messages in the jCIFS network communication.
 * Provides common functionality for message handling and processing.
 *
 * @author mbechler
 */
public interface Message {

    /**
     * Indicate that this message should retain it's raw payload
     */
    void retainPayload();

    /**
     * Determines whether to retain the message payload.
     *
     * @return whether to retain the message payload
     */
    boolean isRetainPayload();

    /**
     * Gets the raw payload of the message.
     *
     * @return the raw response message
     */
    byte[] getRawPayload();

    /**
     * Sets the raw payload of the message.
     *
     * @param rawPayload the raw message payload to set
     */
    void setRawPayload(byte[] rawPayload);
}
