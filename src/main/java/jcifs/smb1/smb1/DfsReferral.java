/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb1.smb1;

import java.util.Map;

/**
 * Represents a DFS (Distributed File System) referral in SMB1 protocol.
 * This class extends SmbException to provide DFS referral information when a DFS path is encountered.
 */
public class DfsReferral extends SmbException {

    /** Number of characters consumed from the path */
    public int pathConsumed;
    /** Time to live for this referral in seconds */
    public long ttl;
    /** Target server for this referral */
    public String server; // Server
    /** Target share for this referral */
    public String share; // Share
    /** The complete UNC path link */
    public String link;
    /** Path relative to tree from which this referral was thrown */
    public String path; // Path relative to tree from which this referral was thrown
    /** Whether to resolve hashes in the path */
    public boolean resolveHashes;
    /** Expiration time for this referral entry */
    public long expiration;

    /** The next DFS referral in the chain */
    DfsReferral next;
    /** Map containing DFS referral entries */
    Map map;
    /** The cache key for this referral */
    String key = null;

    /**
     * Constructs a new DfsReferral instance
     */
    public DfsReferral() {
        this.next = this;
    }

    void append(final DfsReferral dr) {
        dr.next = next;
        next = dr;
    }

    @Override
    public String toString() {
        return "DfsReferral[pathConsumed=" + pathConsumed + ",server=" + server + ",share=" + share + ",link=" + link + ",path=" + path
                + ",ttl=" + ttl + ",expiration=" + expiration + ",resolveHashes=" + resolveHashes + "]";
    }
}
