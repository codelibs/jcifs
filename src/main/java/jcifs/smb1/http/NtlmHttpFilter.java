/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Jason Pugsley" <jcifs at samba dot org>
 *                   "skeetz" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
 *                   and Marcel, Thomas, ...
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

package jcifs.smb1.http;

import java.io.IOException;
import java.util.Enumeration;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jcifs.smb1.Config;
import jcifs.smb1.UniAddress;
import jcifs.smb1.smb1.NtStatus;
import jcifs.smb1.smb1.NtlmChallenge;
import jcifs.smb1.smb1.NtlmPasswordAuthentication;
import jcifs.smb1.smb1.SmbAuthException;
import jcifs.smb1.smb1.SmbSession;
import jcifs.smb1.util.Base64;
import jcifs.smb1.util.LogStream;

/**
 * This servlet Filter can be used to negotiate password hashes with
 * MSIE clients using NTLM SSP. This is similar to {@code Authentication:
 * BASIC} but weakly encrypted and without requiring the user to re-supply
 * authentication credentials.
 * <p>
 * Read <a href="../../../ntlmhttpauth.html">jCIFS NTLM HTTP Authentication and the Network Explorer Servlet</a> for complete details.
 */

public class NtlmHttpFilter implements Filter {

    private static LogStream log = LogStream.getInstance();

    private String defaultDomain;
    private String domainController;
    private boolean loadBalance;
    private boolean enableBasic;
    private boolean insecureBasic;
    private String realm;

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        String name;
        int level;

        /* Set jcifs.smb1 properties we know we want; soTimeout and cachePolicy to 30min.
         */
        Config.setProperty("jcifs.smb1.smb.client.soTimeout", "1800000");
        Config.setProperty("jcifs.smb1.netbios.cachePolicy", "1200");
        /* The Filter can only work with NTLMv1 as it uses a man-in-the-middle
         * techinque that NTLMv2 specifically thwarts. A real NTLM Filter would
         * need to do a NETLOGON RPC that JCIFS will likely never implement
         * because it requires a lot of extra crypto not used by CIFS.
         */
        Config.setProperty("jcifs.smb1.smb.lmCompatibility", "0");
        Config.setProperty("jcifs.smb1.smb.client.useExtendedSecurity", "false");

        final Enumeration e = filterConfig.getInitParameterNames();
        while (e.hasMoreElements()) {
            name = (String) e.nextElement();
            if (name.startsWith("jcifs.smb1.")) {
                Config.setProperty(name, filterConfig.getInitParameter(name));
            }
        }
        defaultDomain = Config.getProperty("jcifs.smb1.smb.client.domain");
        domainController = Config.getProperty("jcifs.smb1.http.domainController");
        if (domainController == null) {
            domainController = defaultDomain;
            loadBalance = Config.getBoolean("jcifs.smb1.http.loadBalance", true);
        }
        enableBasic = Boolean.parseBoolean(Config.getProperty("jcifs.smb1.http.enableBasic"));
        insecureBasic = Boolean.parseBoolean(Config.getProperty("jcifs.smb1.http.insecureBasic"));
        realm = Config.getProperty("jcifs.smb1.http.basicRealm");
        if (realm == null) {
            realm = "jCIFS";
        }

        level = Config.getInt("jcifs.smb1.util.loglevel", -1);
        if (level != -1) {
            LogStream.setLevel(level);
        }
        if (LogStream.level > 2) {
            try {
                Config.store(log, "JCIFS PROPERTIES");
            } catch (final IOException ioe) {}
        }
    }

    @Override
    public void destroy() {
    }

    /**
     * This method simply calls {@code negotiate( req, resp, false )}
     * and then {@code chain.doFilter}. You can override and call
     * negotiate manually to achive a variety of different behavior.
     */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse resp = (HttpServletResponse) response;
        NtlmPasswordAuthentication ntlm = negotiate(req, resp, false);

        if (ntlm == null) {
            return;
        }

        chain.doFilter(new NtlmHttpServletRequest(req, ntlm), response);
    }

    /**
     * Negotiate password hashes with MSIE clients using NTLM SSP
     * @param req The servlet request
     * @param resp The servlet response
     * @param skipAuthentication If true the negotiation is only done if it is
     * initiated by the client (MSIE post requests after successful NTLM SSP
     * authentication). If false and the user has not been authenticated yet
     * the client will be forced to send an authentication (server sends
     * HttpServletResponse.SC_UNAUTHORIZED).
     * @return True if the negotiation is complete, otherwise false
     */
    protected NtlmPasswordAuthentication negotiate(final HttpServletRequest req, final HttpServletResponse resp,
            final boolean skipAuthentication) throws IOException, ServletException {
        UniAddress dc;
        String msg;
        NtlmPasswordAuthentication ntlm = null;
        msg = req.getHeader("Authorization");
        final boolean offerBasic = enableBasic && (insecureBasic || req.isSecure());

        if (msg != null && (msg.startsWith("NTLM ") || offerBasic && msg.startsWith("Basic "))) {
            if (msg.startsWith("NTLM ")) {
                final HttpSession ssn = req.getSession();
                byte[] challenge;

                if (loadBalance) {
                    NtlmChallenge chal = (NtlmChallenge) ssn.getAttribute("NtlmHttpChal");
                    if (chal == null) {
                        chal = SmbSession.getChallengeForDomain();
                        ssn.setAttribute("NtlmHttpChal", chal);
                    }
                    dc = chal.dc;
                    challenge = chal.challenge;
                } else {
                    dc = UniAddress.getByName(domainController, true);
                    challenge = SmbSession.getChallenge(dc);
                }

                ntlm = NtlmSsp.authenticate(req, resp, challenge);
                if (ntlm == null) {
                    return null;
                }
                /* negotiation complete, remove the challenge object */
                ssn.removeAttribute("NtlmHttpChal");
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
                dc = UniAddress.getByName(domainController, true);
            }
            try {

                SmbSession.logon(dc, ntlm);

                if (LogStream.level > 2) {
                    log.println("NtlmHttpFilter: " + ntlm + " successfully authenticated against " + dc);
                }
            } catch (final SmbAuthException sae) {
                if (LogStream.level > 1) {
                    log.println("NtlmHttpFilter: " + ntlm.getName() + ": 0x" + jcifs.smb1.util.Hexdump.toHexString(sae.getNtStatus(), 8)
                            + ": " + sae);
                }
                if (sae.getNtStatus() == NtStatus.NT_STATUS_ACCESS_VIOLATION) {
                    /* Server challenge no longer valid for
                     * externally supplied password hashes.
                     */
                    final HttpSession ssn = req.getSession(false);
                    if (ssn != null) {
                        ssn.removeAttribute("NtlmHttpAuth");
                    }
                }
                resp.setHeader("WWW-Authenticate", "NTLM");
                if (offerBasic) {
                    resp.addHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
                }
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                resp.setContentLength(0); /* Marcel Feb-15-2005 */
                resp.flushBuffer();
                return null;
            }
            req.getSession().setAttribute("NtlmHttpAuth", ntlm);
        } else if (!skipAuthentication) {
            final HttpSession ssn = req.getSession(false);
            if (ssn == null || (ntlm = (NtlmPasswordAuthentication) ssn.getAttribute("NtlmHttpAuth")) == null) {
                resp.setHeader("WWW-Authenticate", "NTLM");
                if (offerBasic) {
                    resp.addHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
                }
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                resp.setContentLength(0);
                resp.flushBuffer();
                return null;
            }
        }

        return ntlm;
    }

    // Added by cgross to work with weblogic 6.1.
    public void setFilterConfig(final FilterConfig f) {
        try {
            init(f);
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

    public FilterConfig getFilterConfig() {
        return null;
    }
}
