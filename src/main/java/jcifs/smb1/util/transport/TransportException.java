package jcifs.smb1.util.transport;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Exception thrown when transport-level errors occur in JCIFS SMB communication.
 */
public class TransportException extends IOException {

    /** The root cause exception */
    private Throwable rootCause;

    /**
     * Constructs a new TransportException with no detail message.
     */
    public TransportException() {
    }

    /**
     * Constructs a new TransportException with the specified detail message.
     *
     * @param msg the detail message
     */
    public TransportException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new TransportException with the specified root cause.
     *
     * @param rootCause the root cause of this exception
     */
    public TransportException(final Throwable rootCause) {
        this.rootCause = rootCause;
    }

    /**
     * Constructs a new TransportException with the specified detail message and root cause.
     *
     * @param msg the detail message
     * @param rootCause the root cause of this exception
     */
    public TransportException(final String msg, final Throwable rootCause) {
        super(msg);
        this.rootCause = rootCause;
    }

    /**
     * Returns the root cause of this exception.
     *
     * @return the root cause or null if none was set
     */
    public Throwable getRootCause() {
        return rootCause;
    }

    @Override
    public String toString() {
        if (rootCause != null) {
            final StringWriter sw = new StringWriter();
            final PrintWriter pw = new PrintWriter(sw);
            rootCause.printStackTrace(pw);
            return super.toString() + "\n" + sw;
        }
        return super.toString();
    }
}
