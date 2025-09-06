/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

import org.codelibs.jcifs.smb.context.SingletonContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * URL handler for transparent smb:// URL handling
 *
 */
public class Handler extends URLStreamHandler {

    private static final Logger log = LoggerFactory.getLogger(Handler.class);
    private CIFSContext transportContext;

    /**
     * Default constructor for SMB URL handler.
     */
    public Handler() {
    }

    /**
     * Constructs an SMB URL handler with the specified CIFS context.
     *
     * @param tc the CIFS context to use
     */
    public Handler(final CIFSContext tc) {
        this.transportContext = tc;
    }

    @Override
    protected int getDefaultPort() {
        return SmbConstants.DEFAULT_PORT;
    }

    @Override
    public URLConnection openConnection(final URL u) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Opening file " + u);
        }
        return new SmbFile(u, getTransportContext());
    }

    /**
     * @return
     */
    private CIFSContext getTransportContext() {
        if (this.transportContext == null) {
            this.transportContext = SingletonContext.getInstance();
        }
        return this.transportContext;
    }

    @Override
    protected void parseURL(final URL u, String spec, final int start, int limit) {
        final String host = u.getHost();
        String path, ref;
        int port;

        if (spec.equals("smb://")) {
            spec = "smb:////";
            limit += 2;
        } else if (!spec.startsWith("smb://") && host != null && host.length() == 0) {
            spec = "//" + spec;
            limit += 2;
        }
        super.parseURL(u, spec, start, limit);
        path = u.getPath();
        ref = u.getRef();
        if (ref != null) {
            path += '#' + ref;
        }
        port = u.getPort();
        if (port == -1) {
            port = getDefaultPort();
        }
        setURL(u, "smb", u.getHost(), port, u.getAuthority(), u.getUserInfo(), path, u.getQuery(), null);
    }
}
