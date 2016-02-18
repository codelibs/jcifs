import java.util.*;
import jcifs.smb.*;

public class GetGroupMemberSidsFromURL {

    public static void main( String[] argv ) throws Exception {
        if (argv.length < 1) {
            System.err.println("usage: GetGroupMemberSidsFromURL <smburl>");
            System.exit(1);
        }

        SmbFile file = new SmbFile(argv[0]);
        String server = file.getServer();
        NtlmPasswordAuthentication auth = (NtlmPasswordAuthentication)file.getPrincipal();
        ACE[] security = file.getSecurity(true);

        for (int ai = 0; ai < security.length; ai++) {
            ACE ace = security[ai];
            SID sid = ace.getSID();
            if (sid.equals(SID.EVERYONE) ||
                        sid.equals(SID.CREATOR_OWNER) ||
                        sid.equals(SID.SYSTEM))
                continue;

            System.out.println(sid.toString() + " (" + sid.toDisplayString() + ") members:");

            SID[] mems = sid.getGroupMemberSids(server, auth, SID.SID_FLAG_RESOLVE_SIDS);
            for (int mi = 0; mi < mems.length; mi++) {
                SID mem = mems[mi];
                System.out.println("  " + mem.getType() + " " + mem.toDisplayString());
            }
        }
    }
}
