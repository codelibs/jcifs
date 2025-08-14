package jcifs.smb1.dcerpc.msrpc;

import jcifs.smb1.smb1.SID;

class LsarSidArrayX extends lsarpc.LsarSidArray {

    LsarSidArrayX(final SID[] sids) {
        this.num_sids = sids.length;
        this.sids = new lsarpc.LsarSidPtr[sids.length];
        for (int si = 0; si < sids.length; si++) {
            this.sids[si] = new lsarpc.LsarSidPtr();
            this.sids[si].sid = sids[si];
        }
    }
}
