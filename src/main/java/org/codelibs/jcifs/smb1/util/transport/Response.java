package org.codelibs.jcifs.smb1.util.transport;

/**
 * Abstract base class for transport layer response objects.
 * Represents a response that can be received through the SMB1 transport layer.
 */
public abstract class Response {

    /**
     * Default constructor for Response.
     */
    public Response() {
        // Default constructor
    }

    /**
     * The expiration time for this response in milliseconds.
     */
    public long expiration;
    /**
     * Flag indicating whether this response has been received.
     */
    public boolean isReceived;
}
