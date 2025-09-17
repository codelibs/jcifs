/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal.dfs;

import java.util.Map;

import org.codelibs.jcifs.smb.DfsReferralData;

/**
 * Internal interface for DFS referral data with extended functionality.
 * Extends the public DFS referral data interface with internal operations like
 * hostname resolution and referral data manipulation for internal DFS management.
 *
 * @author mbechler
 */
public interface DfsReferralDataInternal extends DfsReferralData {

    /**
     * Replaces the host with the given FQDN if it is currently unqualified
     *
     * @param fqdn the fully qualified domain name to use
     */
    void fixupHost(String fqdn);

    /**
     * Possibly appends the given domain name to the host name if it is currently unqualified
     *
     * @param domain the domain name to append
     */
    void fixupDomain(String domain);

    /**
     * Reduces path consumed by the given value
     *
     * @param i the number of characters to strip from path consumed
     */
    void stripPathConsumed(int i);

    @Override
    DfsReferralDataInternal next();

    /**
     * Set the UNC path link for this referral
     *
     * @param link the UNC path link to set
     */
    void setLink(String link);

    /**
     * Get the cache key for this referral
     *
     * @return cache key
     */
    String getKey();

    /**
     * Set the cache key for this referral
     *
     * @param key
     *            cache key
     */
    void setKey(String key);

    /**
     * Set the cache map for this referral
     *
     * @param map the cache map to associate with this referral
     */
    void setCacheMap(Map<String, DfsReferralDataInternal> map);

    /**
     * Replaces the entry with key in the cache map with this referral
     */
    void replaceCache();

    /**
     * Not exactly sure what that is all about, certainly legacy stuff
     *
     * @return resolveHashes
     */
    boolean isResolveHashes();

    /**
     * Check if this referral needs to be resolved further
     *
     * @return whether this refrral needs to be resolved further
     */
    boolean isIntermediate();

    /**
     * Combine this referral with another to form a chain
     *
     * @param next the referral to combine with
     * @return new referral, combining a chain of referrals
     */
    DfsReferralDataInternal combine(DfsReferralData next);

    /**
     * Append another referral to this referral chain
     *
     * @param dr the referral to append
     */
    void append(DfsReferralDataInternal dr);
}
