/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
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

/**
This class can be extended by applications that wish to trap authentication related exceptions and automatically retry the exceptional operation with different credentials. Read <a href="../../../authhandler.html">jCIFS Exceptions and NtlmAuthenticator</a> for complete details.
 */

/**
 * An abstract class for NTLM authentication in SMB1 protocol.
 * Provides a callback mechanism for retrieving user credentials when authentication is required.
 */
public abstract class NtlmAuthenticator {

    /**
     * Default constructor.
     */
    protected NtlmAuthenticator() {
        // Protected constructor for abstract class
    }

    private static NtlmAuthenticator auth;

    private String url;
    private SmbAuthException sae;

    private void reset() {
        url = null;
        sae = null;
    }

    /**
     * Set the default <code>NtlmAuthenticator</code>. Once the default authenticator is set it cannot be changed. Calling this metho again will have no effect.
     * @param a the authenticator to set as default
     */

    public synchronized static void setDefault(final NtlmAuthenticator a) {
        if (auth != null) {
            return;
        }
        auth = a;
    }

    /**
     * Gets the URL that is requesting authentication.
     * @return the URL requiring authentication
     */
    protected final String getRequestingURL() {
        return url;
    }

    /**
     * Gets the authentication exception that triggered this request.
     * @return the authentication exception
     */
    protected final SmbAuthException getRequestingException() {
        return sae;
    }

    /**
     * Used internally by jCIFS when an <code>SmbAuthException</code> is trapped to retrieve new user credentials.
     * @param url the URL that requires authentication
     * @param sae the authentication exception that was thrown
     * @return credentials returned by prompt or null if none available
     */

    public static NtlmPasswordAuthentication requestNtlmPasswordAuthentication(final String url, final SmbAuthException sae) {
        if (auth == null) {
            return null;
        }
        synchronized (auth) {
            auth.url = url;
            auth.sae = sae;
            return auth.getNtlmPasswordAuthentication();
        }
    }

    /**
     * An application extending this class must provide an implementation for this method that returns new user credentials try try when accessing SMB resources described by the <code>getRequestingURL</code> and <code>getRequestingException</code> methods.
     * If this method returns <code>null</code> the <code>SmbAuthException</code> that triggered the authenticator check will simply be rethrown. The default implementation returns <code>null</code>.
     * @return the authentication credentials or null if none available
     */
    protected NtlmPasswordAuthentication getNtlmPasswordAuthentication() {
        return null;
    }
}
