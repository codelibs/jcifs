/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.tests;


import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSException;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.ResolverType;
import jcifs.SmbResource;
import jcifs.SmbTreeHandle;
import jcifs.smb.JAASAuthenticator;
import jcifs.smb.Kerb5Authenticator;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTreeHandleInternal;
import jcifs.smb.SmbUnsupportedOperationException;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( {
    "javadoc", "restriction"
} )
@RunWith ( Parameterized.class )
public class KerberosTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(KerberosTest.class);


    /**
     * @param properties
     */
    public KerberosTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "smb2", "smb30", "smb31", "forceSpnegoIntegrity");
    }


    @Before
    public void setup () {
        Assume.assumeTrue("Skip kerberos auth", getProperties().get("test.skip.kerberos") == null);
    }


    @Test
    public void testKRB () throws Exception {
        Assume.assumeTrue(getContext().getConfig().getResolveOrder().contains(ResolverType.RESOLVER_DNS));
        Subject s = getSubjectWithJaas(getTestUser(), getTestUserPassword(), getTestUserDomainRequired());
        CIFSContext ctx = getContext().withCredentials(new Kerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword()));
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
    }


    @Test
    public void testJAAS () throws CIFSException, MalformedURLException {
        Assume.assumeTrue(getContext().getConfig().getResolveOrder().contains(ResolverType.RESOLVER_DNS));
        CIFSContext ctx = getContext().withCredentials(new JAASAuthenticator(getTestUserDomainRequired(), getTestUser(), getTestUserPassword()));
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
    }


    @Test
    public void testFallback () throws Exception {
        Subject s = getSubjectWithJaas(getTestUser(), getTestUserPassword(), getTestUserDomainRequired());
        Kerb5Authenticator auth = new Kerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword());
        auth.setForceFallback(true);
        CIFSContext ctx = getContext().withCredentials(auth);
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
    }


    @Test
    public void testReauthenticate () throws Exception {
        Assume.assumeTrue(getContext().getConfig().getResolveOrder().contains(ResolverType.RESOLVER_DNS));
        Subject s = getSubjectWithJaas(getTestUser(), getTestUserPassword(), getTestUserDomainRequired());
        Kerb5Authenticator creds = new RefreshableKerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword());
        CIFSContext ctx = getContext().withCredentials(creds);
        try ( SmbFile f = new SmbFile(getTestShareURL(), ctx);
              SmbTreeHandleInternal th = (SmbTreeHandleInternal) f.getTreeHandle();
              SmbSessionInternal session = (SmbSessionInternal) th.getSession() ) {
            Assume.assumeTrue("Not SMB2", th.isSMB2());
            f.exists();
            session.reauthenticate();
            f.exists();
        }
    }


    @Ignore("Cannot be reimplemented with public APIs because custom ticket lifetime is required")
    @Test
    public void testSessionExpiration () throws Exception {
        Assume.assumeTrue(getContext().getConfig().getResolveOrder().contains(ResolverType.RESOLVER_DNS));
        long start = System.currentTimeMillis() / 1000 * 1000;
        // this is not too great as it depends on timing/clockskew
        // first we need to obtain a ticket, therefor need valid credentials
        // then we need to wait until the ticket is expired
        int wait = 10 * 1000;
        // Subject s = getInitiatorSubject(getTestUser(), getTestUserPassword(), getTestUserDomainRequired(), princExp);
        Subject s = new Subject(); // This test is disabled, so this line is just for compilation
        Kerb5Authenticator creds = new RefreshableKerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword());
        CIFSContext ctx = getContext().withCredentials(creds);
        try ( SmbFile f = new SmbFile(getTestShareURL(), ctx) ) {
            try ( SmbTreeHandle th = f.getTreeHandle() ) {
                Assume.assumeTrue("Not SMB2", th.isSMB2());
            }

            f.exists();
            Thread.sleep(wait);

            try ( SmbResource r = f.resolve("test") ) {
                r.exists();
            }
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
        catch ( SmbException e ) {
            if ( ! ( e.getCause() instanceof GSSException ) ) {
                throw e;
            }
            log.error("Kerberos problem", e);
            Assume.assumeTrue("Kerberos problem, clockskew?", false);
        }
    }

    private Subject getSubjectWithJaas(String username, String password, String realm) throws LoginException {
        Configuration jaasConfig = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useTicketCache", "false");
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "false");
                options.put("principal", username + "@" + realm);
                // options.put("debug", "true"); // Uncomment for debugging
    
                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options)
                };
            }
        };
    
        LoginContext lc = new LoginContext("jcifs-kerberos", new Subject(), new PasswordHandler(password), jaasConfig);
        lc.login();
        return lc.getSubject();
    }

    private static class PasswordHandler implements CallbackHandler {
        private String password;

        PasswordHandler(String password) {
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(this.password.toCharArray());
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }
    }

    public final class RefreshableKerb5Authenticator extends Kerb5Authenticator {

        private static final long serialVersionUID = -4979600496889213143L;


        public RefreshableKerb5Authenticator ( Subject subject, String domain, String username, String password ) {
            super(subject, domain, username, password);
        }


        @Override
        public void refresh () throws CIFSException {
            try {
                System.out.println("Refreshing");
                setSubject(getSubjectWithJaas(getTestUser(), getTestUserPassword(), getTestUserDomainRequired()));
                System.out.println("Refreshed");
            }
            catch ( Exception e ) {
                throw new CIFSException("Failed to refresh credentials", e);
            }
        }


        @Override
        public Kerb5Authenticator clone () {
            Kerb5Authenticator auth = new RefreshableKerb5Authenticator(getSubject(), getUserDomain(), getUser(), getPassword());
            cloneInternal(auth, this);
            return auth;
        }
    }
}