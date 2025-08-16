/*
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
package jcifs.pac.kerberos;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * Kerberos credentials management class that handles authentication through JAAS.
 */
public class KerberosCredentials {

    private Subject subject;

    /**
     * Creates KerberosCredentials using the default JAAS configuration.
     *
     * @throws LoginException if authentication fails
     */
    public KerberosCredentials() throws LoginException {
        this(System.getProperty("jaaslounge.sso.jaas.config"));
    }

    /**
     * Creates KerberosCredentials using the specified JAAS login context.
     *
     * @param loginContextName the name of the JAAS login context
     * @throws LoginException if authentication fails
     */
    public KerberosCredentials(String loginContextName) throws LoginException {
        LoginContext lc = new LoginContext(loginContextName);
        lc.login();
        this.subject = lc.getSubject();
    }

    /**
     * Retrieves all Kerberos keys from the authenticated subject.
     *
     * @return array of KerberosKey objects
     */
    public KerberosKey[] getKeys() {
        List<Key> serverKeys = new ArrayList<>();

        Set<Object> serverPrivateCredentials = this.subject.getPrivateCredentials();
        for (Object credential : serverPrivateCredentials) {
            if (credential instanceof KerberosKey) {
                serverKeys.add((KerberosKey) credential);
            }
        }

        return serverKeys.toArray(new KerberosKey[0]);
    }

    /**
     * Retrieves a specific Kerberos key by key type.
     *
     * @param keyType the encryption type of the key to retrieve
     * @return the KerberosKey with the specified type, or null if not found
     */
    public KerberosKey getKey(int keyType) {
        KerberosKey serverKey = null;

        Set<Object> serverPrivateCredentials = this.subject.getPrivateCredentials();
        for (Object credential : serverPrivateCredentials) {
            if (credential instanceof KerberosKey) {
                if (((KerberosKey) credential).getKeyType() == keyType) {
                    serverKey = (KerberosKey) credential;
                }
            }
        }

        return serverKey;
    }

    /**
     * Returns the authenticated JAAS Subject.
     *
     * @return the authenticated Subject
     */
    public Subject getSubject() {
        return this.subject;
    }

}
