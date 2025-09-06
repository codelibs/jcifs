/*
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

package org.codelibs.jcifs.smb1;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
 * URL handler for SMB1 protocol URLs.
 */
public class Handler extends URLStreamHandler {

    static final URLStreamHandler SMB_HANDLER = new Handler();

    /**
     * Default constructor for SMB1 URL handler.
     */
    public Handler() {
    }

    @Override
    protected int getDefaultPort() {
        return SmbConstants.DEFAULT_PORT;
    }

    @Override
    public URLConnection openConnection(final URL u) throws IOException {
        return new SmbFile(u);
    }

    @Override
    protected void parseURL(final URL u, String spec, final int start, int limit) {
        final String host = u.getHost();
        String path, ref;
        int port;

        if (spec.equals("smb1://")) {
            spec = "smb1:////";
            limit += 2;
        } else if (!spec.startsWith("smb1://") && host != null && host.length() == 0) {
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
