package jcifs.smb1.util.transport;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;

import jcifs.smb1.util.LogStream;

/**
 * This class simplifies communication for protocols that support
 * multiplexing requests. It encapsulates a stream and some protocol
 * knowledge (provided by a concrete subclass) so that connecting,
 * disconnecting, sending, and receiving can be syncronized
 * properly. Apparatus is provided to send and receive requests
 * concurrently.
 */

public abstract class Transport implements Runnable {

    /**
     * Default constructor for Transport.
     */
    public Transport() {
        // Default constructor
    }

    static int id = 0;
    static LogStream log = LogStream.getInstance();

    /**
     * Reads exactly len bytes from the input stream into the buffer.
     *
     * @param in the input stream to read from
     * @param b the buffer to read into
     * @param off the offset in the buffer to start writing
     * @param len the number of bytes to read
     * @return the number of bytes actually read
     * @throws IOException if an I/O error occurs
     */
    public static int readn(final InputStream in, final byte[] b, final int off, final int len) throws IOException {
        int i = 0, n = -5;

        while (i < len) {
            n = in.read(b, off + i, len - i);
            if (n <= 0) {
                break;
            }
            i += n;
        }

        return i;
    }

    /* state values
     * 0 - not connected
     * 1 - connecting
     * 2 - run connected
     * 3 - connected
     * 4 - error
     */
    int state = 0;

    String name = "Transport" + id++;
    Thread thread;
    TransportException te;

    /**
     * Map of pending requests to their corresponding responses.
     */
    protected HashMap response_map = new HashMap(4);

    /**
     * Creates a key for the specified request for response matching.
     *
     * @param request the request to create a key for
     * @throws IOException if an I/O error occurs
     */
    protected abstract void makeKey(Request request) throws IOException;

    /**
     * Reads and returns the key of the next message without consuming it.
     *
     * @return the request key of the next message
     * @throws IOException if an I/O error occurs
     */
    protected abstract Request peekKey() throws IOException;

    /**
     * Sends a request to the remote endpoint.
     *
     * @param request the request to send
     * @throws IOException if an I/O error occurs
     */
    protected abstract void doSend(Request request) throws IOException;

    /**
     * Receives a response from the remote endpoint.
     *
     * @param response the response object to populate
     * @throws IOException if an I/O error occurs
     */
    protected abstract void doRecv(Response response) throws IOException;

    /**
     * Skips an unexpected or unrecognized message.
     *
     * @throws IOException if an I/O error occurs
     */
    protected abstract void doSkip() throws IOException;

    /**
     * Sends a request and waits for the corresponding response.
     *
     * @param request the request to send
     * @param response the response object to populate
     * @param timeout the maximum time to wait for the response in milliseconds
     * @throws IOException if an I/O error occurs during communication
     */
    public synchronized void sendrecv(final Request request, final Response response, long timeout) throws IOException {
        makeKey(request);
        response.isReceived = false;
        try {
            response_map.put(request, response);
            doSend(request);
            response.expiration = System.currentTimeMillis() + timeout;
            while (!response.isReceived) {
                wait(timeout);
                timeout = response.expiration - System.currentTimeMillis();
                if (timeout <= 0) {
                    throw new TransportException(name + " timedout waiting for response to " + request);
                }
            }
        } catch (final IOException ioe) {
            if (LogStream.level > 2) {
                ioe.printStackTrace(log);
            }
            try {
                disconnect(true);
            } catch (final IOException ioe2) {
                ioe2.printStackTrace(log);
            }
            throw ioe;
        } catch (final InterruptedException ie) {
            throw new TransportException(ie);
        } finally {
            response_map.remove(request);
        }
    }

    private void loop() {
        while (thread == Thread.currentThread()) {
            try {
                final Request key = peekKey();
                if (key == null) {
                    throw new IOException("end of stream");
                }
                synchronized (this) {
                    final Response response = (Response) response_map.get(key);
                    if (response == null) {
                        if (LogStream.level >= 4) {
                            log.println("Invalid key, skipping message");
                        }
                        doSkip();
                    } else {
                        doRecv(response);
                        response.isReceived = true;
                        notifyAll();
                    }
                }
            } catch (final Exception ex) {
                final String msg = ex.getMessage();
                final boolean timeout = msg != null && msg.equals("Read timed out");
                /* If just a timeout, try to disconnect gracefully
                 */
                final boolean hard = !timeout;

                if (!timeout && LogStream.level >= 3) {
                    ex.printStackTrace(log);
                }

                try {
                    disconnect(hard);
                } catch (final IOException ioe) {
                    ioe.printStackTrace(log);
                }
            }
        }
    }

    /* Build a connection. Only one thread will ever call this method at
     * any one time. If this method throws an exception or the connect timeout
     * expires an encapsulating TransportException will be thrown from connect
     * and the transport will be in error.
     */

    /**
     * Establishes a connection to the remote endpoint.
     *
     * @throws Exception if the connection fails
     */
    protected abstract void doConnect() throws Exception;

    /* Tear down a connection. If the hard parameter is true, the diconnection
     * procedure should not initiate or wait for any outstanding requests on
     * this transport.
     */

    /**
     * Tears down the connection to the remote endpoint.
     *
     * @param hard if true, disconnect immediately without waiting for outstanding requests
     * @throws IOException if an I/O error occurs
     */
    protected abstract void doDisconnect(boolean hard) throws IOException;

    /**
     * Establishes a connection to the remote endpoint.
     *
     * @param timeout the maximum time to wait for the connection in milliseconds
     * @throws TransportException if the connection fails or times out
     */
    public synchronized void connect(final long timeout) throws TransportException {
        try {
            switch (state) {
            case 0:
                break;
            case 3:
                return; // already connected
            case 4:
                state = 0;
                throw new TransportException("Connection in error", te);
            default:
                final TransportException te = new TransportException("Invalid state: " + state);
                state = 0;
                throw te;
            }

            state = 1;
            te = null;
            thread = new Thread(this, name);
            thread.setDaemon(true);

            synchronized (thread) {
                thread.start();
                thread.wait(timeout); /* wait for doConnect */

                switch (state) {
                case 1: /* doConnect never returned */
                    state = 0;
                    thread = null;
                    throw new TransportException("Connection timeout");
                case 2:
                    if (te != null) { /* doConnect throw Exception */
                        state = 4; /* error */
                        thread = null;
                        throw te;
                    }
                    state = 3; /* Success! */
                }
            }
        } catch (final InterruptedException ie) {
            state = 0;
            thread = null;
            throw new TransportException(ie);
        } finally {
            /* This guarantees that we leave in a valid state
             */
            if (state != 0 && state != 3 && state != 4) {
                if (LogStream.level >= 1) {
                    log.println("Invalid state: " + state);
                }
                state = 0;
                thread = null;
            }
        }
    }

    /**
     * Disconnects from the remote endpoint.
     *
     * @param hard if true, disconnect immediately without waiting for outstanding requests
     * @throws IOException if an I/O error occurs during disconnection
     */
    public synchronized void disconnect(boolean hard) throws IOException {
        IOException ioe = null;

        switch (state) {
        case 0: /* not connected - just return */
            return;
        case 2:
            hard = true;
        case 3: /* connected - go ahead and disconnect */
            if (response_map.size() != 0 && !hard) {
                break; /* outstanding requests */
            }
            try {
                doDisconnect(hard);
            } catch (final IOException ioe0) {
                ioe = ioe0;
            }
        case 4: /* in error - reset the transport */
            thread = null;
            state = 0;
            break;
        default:
            if (LogStream.level >= 1) {
                log.println("Invalid state: " + state);
            }
            thread = null;
            state = 0;
            break;
        }

        if (ioe != null) {
            throw ioe;
        }
    }

    @Override
    public void run() {
        final Thread run_thread = Thread.currentThread();
        Exception ex0 = null;

        try {
            /* We cannot synchronize (run_thread) here or the caller's
             * thread.wait( timeout ) cannot reaquire the lock and
             * return which would render the timeout effectively useless.
             */
            doConnect();
        } catch (final Exception ex) {
            ex0 = ex; // Defer to below where we're locked
            return;
        } finally {
            synchronized (run_thread) {
                if (run_thread != thread) {
                    /* Thread no longer the one setup for this transport --
                     * doConnect returned too late, just ignore.
                     */
                    if ((ex0 != null) && (LogStream.level >= 2)) {
                        ex0.printStackTrace(log);
                    }
                    return;
                }
                if (ex0 != null) {
                    te = new TransportException(ex0);
                }
                state = 2; // run connected
                run_thread.notify();
            }
        }

        /* Proccess responses
         */
        loop();
    }

    @Override
    public String toString() {
        return name;
    }
}
