package jcifs.smb1.util.transport;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

public class TransportException extends IOException {

    private Throwable rootCause;

    public TransportException() {
    }

    public TransportException(final String msg) {
        super(msg);
    }

    public TransportException(final Throwable rootCause) {
        this.rootCause = rootCause;
    }

    public TransportException(final String msg, final Throwable rootCause) {
        super(msg);
        this.rootCause = rootCause;
    }

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
