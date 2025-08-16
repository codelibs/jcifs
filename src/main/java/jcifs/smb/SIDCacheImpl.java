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
package jcifs.smb;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SidResolver;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.UnicodeString;
import jcifs.dcerpc.rpc;
import jcifs.dcerpc.rpc.sid_t;
import jcifs.dcerpc.msrpc.LsaPolicyHandle;
import jcifs.dcerpc.msrpc.MsrpcEnumerateAliasesInDomain;
import jcifs.dcerpc.msrpc.MsrpcGetMembersInAlias;
import jcifs.dcerpc.msrpc.MsrpcLookupSids;
import jcifs.dcerpc.msrpc.MsrpcQueryInformationPolicy;
import jcifs.dcerpc.msrpc.SamrAliasHandle;
import jcifs.dcerpc.msrpc.SamrDomainHandle;
import jcifs.dcerpc.msrpc.SamrPolicyHandle;
import jcifs.dcerpc.msrpc.lsarpc;
import jcifs.dcerpc.msrpc.lsarpc.LsarTranslatedName;
import jcifs.dcerpc.msrpc.samr;

/**
 * Internal use only: SID resolver cache
 *
 * @author mbechler
 *
 * <p>This class is intended for internal use.</p>
 */
public class SIDCacheImpl implements SidResolver {

    private final Map<SID, SID> sidCache = new HashMap<>();

    /**
     * Constructs a SID cache implementation.
     *
     * @param baseContext the CIFS context for this cache
     */
    public SIDCacheImpl(final CIFSContext baseContext) {
    }

    void resolveSids(final DcerpcHandle handle, final LsaPolicyHandle policyHandle, final jcifs.SID[] sids) throws IOException {
        final MsrpcLookupSids rpc = new MsrpcLookupSids(policyHandle, sids);
        handle.sendrecv(rpc);
        switch (rpc.retval) {
        case 0:
        case NtStatus.NT_STATUS_NONE_MAPPED:
        case 0x00000107: // NT_STATUS_SOME_NOT_MAPPED
            break;
        default:
            throw new SmbException(rpc.retval, false);
        }

        for (int si = 0; si < sids.length; si++) {
            final SID out = sids[si].unwrap(SID.class);
            final LsarTranslatedName resp = rpc.names.names[si];
            out.domainName = null;
            switch (resp.sid_type) {
            case jcifs.SID.SID_TYPE_USER:
            case jcifs.SID.SID_TYPE_DOM_GRP:
            case jcifs.SID.SID_TYPE_DOMAIN:
            case jcifs.SID.SID_TYPE_ALIAS:
            case jcifs.SID.SID_TYPE_WKN_GRP:
                final rpc.unicode_string ustr = rpc.domains.domains[resp.sid_index].name;
                out.domainName = new UnicodeString(ustr, false).toString();
                break;
            }

            final UnicodeString ucstr = new UnicodeString(resp.name, false);
            out.acctName = ucstr.toString();
            out.type = resp.sid_type;
            out.origin_server = null;
            out.origin_ctx = null;
        }
    }

    void resolveSids0(final String authorityServerName, final CIFSContext tc, final jcifs.SID[] sids) throws CIFSException {
        synchronized (this.sidCache) {
            try (DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + authorityServerName + "[\\PIPE\\lsarpc]", tc)) {
                String server = authorityServerName;
                final int dot = server.indexOf('.');
                if (dot > 0 && !Character.isDigit(server.charAt(0))) {
                    server = server.substring(0, dot);
                }
                try (LsaPolicyHandle policyHandle = new LsaPolicyHandle(handle, "\\\\" + server, 0x00000800)) {
                    resolveSids(handle, policyHandle, sids);
                }
            } catch (final IOException e) {
                throw new CIFSException("Failed to resolve SIDs", e);
            }
        }
    }

    @Override
    public void resolveSids(final CIFSContext tc, final String authorityServerName, final jcifs.SID[] sids, final int offset,
            final int length) throws CIFSException {
        final ArrayList<SID> list = new ArrayList<>(sids.length);
        int si;

        synchronized (this.sidCache) {
            for (si = 0; si < length; si++) {
                final SID s = sids[offset + si].unwrap(SID.class);
                final SID sid = this.sidCache.get(s);
                if (sid != null) {
                    s.type = sid.type;
                    s.domainName = sid.domainName;
                    s.acctName = sid.acctName;
                } else {
                    list.add(s);
                }
            }

            if (list.size() > 0) {
                final SID[] resolved = list.toArray(new SID[list.size()]);
                resolveSids0(authorityServerName, tc, resolved);
                for (si = 0; si < resolved.length; si++) {
                    this.sidCache.put(resolved[si], resolved[si]);
                }
            }
        }
    }

    /**
     * Resolve an array of SIDs using a cache and at most one MSRPC request.
     * <p>
     * This method will attempt
     * to resolve SIDs using a cache and cache the results of any SIDs that
     * required resolving with the authority. SID cache entries are currently not
     * expired because under normal circumstances SID information never changes.
     *
     * @param authorityServerName
     *            The hostname of the server that should be queried. For maximum efficiency this should be the hostname
     *            of a domain controller however a member server will work as well and a domain controller may not
     *            return names for SIDs corresponding to local accounts for which the domain controller is not an
     *            authority.
     * @param tc
     *            The context that should be used to communicate with the named server.
     * @param sids
     *            The SIDs that should be resolved. After this function is called, the names associated with the SIDs
     *            may be queried with the <code>toDisplayString</code>, <code>getDomainName</code>, and <code>getAccountName</code>
     *            methods.
     */
    @Override
    public void resolveSids(final CIFSContext tc, final String authorityServerName, final jcifs.SID[] sids) throws CIFSException {
        final ArrayList<SID> list = new ArrayList<>(sids.length);
        int si;

        synchronized (this.sidCache) {
            for (si = 0; si < sids.length; si++) {
                final SID s = sids[si].unwrap(SID.class);
                final SID sid = this.sidCache.get(s);
                if (sid != null) {
                    s.type = sid.type;
                    s.domainName = sid.domainName;
                    s.acctName = sid.acctName;
                } else {
                    list.add(s);
                }
            }

            if (list.size() > 0) {
                final SID[] resolved = list.toArray(new SID[list.size()]);
                resolveSids0(authorityServerName, tc, resolved);
                for (si = 0; si < resolved.length; si++) {
                    this.sidCache.put(resolved[si], resolved[si]);
                }
            }
        }
    }

    @Override
    public SID getServerSid(final CIFSContext tc, final String server) throws CIFSException {
        final lsarpc.LsarDomainInfo info = new lsarpc.LsarDomainInfo();
        MsrpcQueryInformationPolicy rpc;

        synchronized (this.sidCache) {
            try (DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + server + "[\\PIPE\\lsarpc]", tc)) {
                // NetApp doesn't like the 'generic' access mask values
                try (LsaPolicyHandle policyHandle = new LsaPolicyHandle(handle, null, 0x00000001)) {
                    rpc = new MsrpcQueryInformationPolicy(policyHandle, (short) lsarpc.POLICY_INFO_ACCOUNT_DOMAIN, info);
                    handle.sendrecv(rpc);
                    if (rpc.retval != 0) {
                        throw new SmbException(rpc.retval, false);
                    }
                }

                return new SID(info.sid, jcifs.SID.SID_TYPE_DOMAIN, new UnicodeString(info.name, false).toString(), null, false);
            } catch (final IOException e) {
                throw new CIFSException("Failed to get SID from server", e);
            }
        }
    }

    @Override
    public SID[] getGroupMemberSids(final CIFSContext tc, final String authorityServerName, final jcifs.SID domsid, final int rid,
            final int flags) throws CIFSException {
        final lsarpc.LsarSidArray sidarray = new lsarpc.LsarSidArray();
        MsrpcGetMembersInAlias rpc = null;

        synchronized (this.sidCache) {
            try (DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + authorityServerName + "[\\PIPE\\samr]", tc)) {
                final SamrPolicyHandle policyHandle = new SamrPolicyHandle(handle, authorityServerName, 0x00000030);
                final SamrDomainHandle domainHandle = new SamrDomainHandle(handle, policyHandle, 0x00000200, domsid.unwrap(sid_t.class));
                try (SamrAliasHandle aliasHandle = new SamrAliasHandle(handle, domainHandle, 0x0002000c, rid)) {
                    rpc = new MsrpcGetMembersInAlias(aliasHandle, sidarray);
                    handle.sendrecv(rpc);
                    if (rpc.retval != 0) {
                        throw new SmbException(rpc.retval, false);
                    }
                    final SID[] sids = new SID[rpc.sids.num_sids];

                    final String origin_server = handle.getServer();
                    final CIFSContext origin_ctx = handle.getTransportContext();

                    for (int i = 0; i < sids.length; i++) {
                        sids[i] = new SID(rpc.sids.sids[i].sid, 0, null, null, false);
                        sids[i].origin_server = origin_server;
                        sids[i].origin_ctx = origin_ctx;
                    }
                    if (sids.length > 0 && (flags & SID.SID_FLAG_RESOLVE_SIDS) != 0) {
                        resolveSids(origin_ctx, origin_server, sids);
                    }
                    return sids;
                }
            } catch (final IOException e) {
                throw new CIFSException("Failed to get group member SIDs", e);
            }
        }

    }

    /**
     *
     * {@inheritDoc}
     *
     * @see jcifs.SidResolver#getLocalGroupsMap(jcifs.CIFSContext, java.lang.String, int)
     */
    @Override
    public Map<jcifs.SID, List<jcifs.SID>> getLocalGroupsMap(final CIFSContext tc, final String authorityServerName, final int flags)
            throws CIFSException {
        final SID domSid = getServerSid(tc, authorityServerName);
        synchronized (this.sidCache) {
            try (DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + authorityServerName + "[\\PIPE\\samr]", tc)) {
                final samr.SamrSamArray sam = new samr.SamrSamArray();
                try (SamrPolicyHandle policyHandle = new SamrPolicyHandle(handle, authorityServerName, 0x02000000);
                        SamrDomainHandle domainHandle = new SamrDomainHandle(handle, policyHandle, 0x02000000, domSid)) {
                    final MsrpcEnumerateAliasesInDomain rpc = new MsrpcEnumerateAliasesInDomain(domainHandle, 0xFFFF, sam);
                    handle.sendrecv(rpc);
                    if (rpc.retval != 0) {
                        throw new SmbException(rpc.retval, false);
                    }

                    final Map<jcifs.SID, List<jcifs.SID>> map = new HashMap<>();

                    for (int ei = 0; ei < rpc.sam.count; ei++) {
                        final samr.SamrSamEntry entry = rpc.sam.entries[ei];

                        final SID[] mems = getGroupMemberSids(tc, authorityServerName, domSid, entry.idx, flags);
                        final SID groupSid = new SID(domSid, entry.idx);
                        groupSid.type = jcifs.SID.SID_TYPE_ALIAS;
                        groupSid.domainName = domSid.getDomainName();
                        groupSid.acctName = new UnicodeString(entry.name, false).toString();

                        for (final SID mem : mems) {
                            List<jcifs.SID> groups = map.get(mem);
                            if (groups == null) {
                                groups = new ArrayList<>();
                                map.put(mem, groups);
                            }
                            if (!groups.contains(groupSid)) {
                                groups.add(groupSid);
                            }
                        }
                    }

                    return map;
                }
            } catch (final IOException e) {
                throw new CIFSException("Failed to resolve groups", e);
            }
        }
    }
}
