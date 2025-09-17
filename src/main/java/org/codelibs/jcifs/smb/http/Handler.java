/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.http;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import org.codelibs.jcifs.smb.CIFSContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A <code>URLStreamHandler</code> used to provide NTLM authentication
 * capabilities to the default HTTP handler. This acts as a wrapper,
 * handling authentication and passing control to the underlying
 * stream handler.
 *
 * @deprecated {@link NtlmHttpURLConnection} is broken by design.
 */
@Deprecated
public class Handler extends URLStreamHandler {

    private static final Logger log = LoggerFactory.getLogger(Handler.class);

    /**
     * The default HTTP port (<code>80</code>).
     */
    public static final int DEFAULT_HTTP_PORT = 80;

    private static final Map<String, URLStreamHandler> PROTOCOL_HANDLERS = new HashMap<>();

    private static final String HANDLER_PKGS_PROPERTY = "java.protocol.handler.pkgs";

    /**
     * Vendor-specific default packages. If no packages are specified in
     * "java.protocol.handler.pkgs", the VM uses one or more default
     * packages, which are vendor specific. Sun's is included below
     * for convenience; others could be as well. If a particular vendor's
     * package isn't listed, it can be specified in
     * "java.protocol.handler.pkgs".
     */
    private static final String[] JVM_VENDOR_DEFAULT_PKGS = { "sun.net.www.protocol" };

    private static URLStreamHandlerFactory factory;

    private final CIFSContext transportContext;

    /**
     * Sets the URL stream handler factory for the environment. This
     * allows specification of the factory used in creating underlying
     * stream handlers. This can be called once per JVM instance.
     *
     * @param factory
     *            The URL stream handler factory.
     */
    public static void setURLStreamHandlerFactory(final URLStreamHandlerFactory factory) {
        synchronized (PROTOCOL_HANDLERS) {
            if (Handler.factory != null) {
                throw new IllegalStateException("URLStreamHandlerFactory already set.");
            }
            PROTOCOL_HANDLERS.clear();
            Handler.factory = factory;
        }
    }

    /**
     * Constructs a handler with the specified CIFS context.
     *
     * @param tc context to use
     */
    public Handler(final CIFSContext tc) {
        this.transportContext = tc;
    }

    /**
     * Returns the default HTTP port.
     *
     * @return An <code>int</code> containing the default HTTP port.
     */
    @Override
    protected int getDefaultPort() {
        return DEFAULT_HTTP_PORT;
    }

    @Override
    protected URLConnection openConnection(URL url) throws IOException {
        url = new URL(url, url.toExternalForm(), getDefaultStreamHandler(url.getProtocol()));
        return new NtlmHttpURLConnection((HttpURLConnection) url.openConnection(), this.transportContext);
    }

    private static URLStreamHandler getDefaultStreamHandler(final String protocol) throws IOException {
        synchronized (PROTOCOL_HANDLERS) {
            URLStreamHandler handler = PROTOCOL_HANDLERS.get(protocol);
            if (handler != null) {
                return handler;
            }
            if (factory != null) {
                handler = factory.createURLStreamHandler(protocol);
            }
            if (handler == null) {
                final String path = System.getProperty(HANDLER_PKGS_PROPERTY);
                final StringTokenizer tokenizer = new StringTokenizer(path, "|");
                while (tokenizer.hasMoreTokens()) {
                    final String provider = tokenizer.nextToken().trim();
                    if (provider.equals("jcifs.")) {
                        continue;
                    }
                    final String className = provider + "." + protocol + ".Handler";
                    try {
                        Class<?> handlerClass = null;
                        try {
                            handlerClass = Class.forName(className);
                        } catch (final Exception ex) {
                            log.debug("Failed to load handler class " + className, ex);
                        }
                        if (handlerClass == null) {
                            handlerClass = ClassLoader.getSystemClassLoader().loadClass(className);
                        }
                        handler = (URLStreamHandler) handlerClass.newInstance();
                        break;
                    } catch (final Exception ex) {
                        log.debug("Failed to initialize handler " + className, ex);
                    }
                }
            }
            if (handler == null) {
                for (final String element : JVM_VENDOR_DEFAULT_PKGS) {
                    final String className = element + "." + protocol + ".Handler";
                    try {
                        Class<?> handlerClass = null;
                        try {
                            handlerClass = Class.forName(className);
                        } catch (final Exception ex) {
                            log.debug("Failed to load handler class " + className, ex);
                        }
                        if (handlerClass == null) {
                            handlerClass = ClassLoader.getSystemClassLoader().loadClass(className);
                        }
                        handler = (URLStreamHandler) handlerClass.newInstance();
                    } catch (final Exception ex) {
                        log.debug("Failed to initialize handler " + className, ex);
                    }
                    if (handler != null) {
                        break;
                    }
                }
            }
            if (handler == null) {
                throw new IOException("Unable to find default handler for protocol: " + protocol);
            }
            PROTOCOL_HANDLERS.put(protocol, handler);
            return handler;
        }
    }

}
