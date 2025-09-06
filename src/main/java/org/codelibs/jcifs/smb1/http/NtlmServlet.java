/*
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

package org.codelibs.jcifs.smb1.http;

import java.io.IOException;
import java.util.Enumeration;

import org.codelibs.jcifs.smb1.Config;
import org.codelibs.jcifs.smb1.NtlmPasswordAuthentication;
import org.codelibs.jcifs.smb1.SmbAuthException;
import org.codelibs.jcifs.smb1.SmbSession;
import org.codelibs.jcifs.smb1.UniAddress;
import org.codelibs.jcifs.smb1.netbios.NbtAddress;
import org.codelibs.jcifs.smb1.util.Base64;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * This servlet may be used with pre-2.3 servlet containers
 * to protect content with NTLM HTTP Authentication. Servlets that
 * extend this abstract base class may be authenticatied against an SMB
 * server or domain controller depending on how the
 * {@code org.codelibs.jcifs.smb1.smb1.client.domain} or {@code org.codelibs.jcifs.smb1.http.domainController}
 * properties are be specified. <b>With later containers the
 * {@code NtlmHttpFilter} should be used</b>. For custom NTLM HTTP Authentication schemes the {@code NtlmSsp} may be used.
 *
 * <p>
 * Read <a href="../../../ntlmhttpauth.html">jCIFS NTLM HTTP Authentication and the Network Explorer Servlet</a> related information.
 */

public abstract class NtlmServlet extends HttpServlet {

    /**
     * Default constructor.
     */
    protected NtlmServlet() {
        super();
    }

    /** The default domain for NTLM authentication */
    private String defaultDomain;

    /** The domain controller for authentication */
    private String domainController;

    /** Flag to enable load balancing across domain controllers */
    private boolean loadBalance;

    /** Flag to enable basic authentication */
    private boolean enableBasic;

    /** Flag to allow insecure basic authentication */
    private boolean insecureBasic;

    /** The authentication realm */
    private String realm;

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

        /* Set org.codelibs.jcifs.smb1 properties we know we want; soTimeout and cachePolicy to 10min.
         */
        Config.setProperty("jcifs.client.soTimeout", "300000");
        Config.setProperty("jcifs.netbios.cachePolicy", "600");

        final Enumeration e = config.getInitParameterNames();
        String name;
        while (e.hasMoreElements()) {
            name = (String) e.nextElement();
            if (name.startsWith("jcifs.")) {
                Config.setProperty(name, config.getInitParameter(name));
            }
        }
        defaultDomain = Config.getProperty("jcifs.client.domain");
        domainController = Config.getProperty("jcifs.http.domainController");
        if (domainController == null) {
            domainController = defaultDomain;
            loadBalance = Config.getBoolean("jcifs.http.loadBalance", true);
        }
        enableBasic = Boolean.parseBoolean(Config.getProperty("jcifs.http.enableBasic"));
        insecureBasic = Boolean.parseBoolean(Config.getProperty("jcifs.http.insecureBasic"));
        realm = Config.getProperty("jcifs.http.basicRealm");
        if (realm == null) {
            realm = "jCIFS";
        }
    }

    @Override
    protected void service(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        UniAddress dc;
        final boolean offerBasic = enableBasic && (insecureBasic || request.isSecure());
        final String msg = request.getHeader("Authorization");
        if (msg != null && (msg.startsWith("NTLM ") || offerBasic && msg.startsWith("Basic "))) {
            if (loadBalance) {
                dc = new UniAddress(NbtAddress.getByName(domainController, 0x1C, null));
            } else {
                dc = UniAddress.getByName(domainController, true);
            }
            NtlmPasswordAuthentication ntlm;
            if (msg.startsWith("NTLM ")) {
                final byte[] challenge = SmbSession.getChallenge(dc);
                ntlm = NtlmSsp.authenticate(request, response, challenge);
                if (ntlm == null) {
                    return;
                }
            } else {
                final String auth = new String(Base64.decode(msg.substring(6)), "US-ASCII");
                int index = auth.indexOf(':');
                String user = index != -1 ? auth.substring(0, index) : auth;
                final String password = index != -1 ? auth.substring(index + 1) : "";
                index = user.indexOf('\\');
                if (index == -1) {
                    index = user.indexOf('/');
                }
                final String domain = index != -1 ? user.substring(0, index) : defaultDomain;
                user = index != -1 ? user.substring(index + 1) : user;
                ntlm = new NtlmPasswordAuthentication(domain, user, password);
            }
            try {
                SmbSession.logon(dc, ntlm);
            } catch (final SmbAuthException sae) {
                response.setHeader("WWW-Authenticate", "NTLM");
                if (offerBasic) {
                    response.addHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
                }
                response.setHeader("Connection", "close");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.flushBuffer();
                return;
            }
            final HttpSession ssn = request.getSession();
            ssn.setAttribute("NtlmHttpAuth", ntlm);
            ssn.setAttribute("ntlmdomain", ntlm.getDomain());
            ssn.setAttribute("ntlmuser", ntlm.getUsername());
        } else {
            final HttpSession ssn = request.getSession(false);
            if (ssn == null || ssn.getAttribute("NtlmHttpAuth") == null) {
                response.setHeader("WWW-Authenticate", "NTLM");
                if (offerBasic) {
                    response.addHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
                }
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.flushBuffer();
                return;
            }
        }
        super.service(request, response);
    }
}
