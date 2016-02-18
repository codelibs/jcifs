import java.util.*;
import jcifs.smb.*;

public class GetLocalGroupMemberSidsFromURL {

    public static void main( String[] argv ) throws Exception {
        if (argv.length < 1) {
            System.err.println("usage: GetLocalGroupMemberSidsFromURL <smburl>");
            System.exit(1);
        }

        SmbFile file = new SmbFile(argv[0]);
        String server = file.getServer();
        NtlmPasswordAuthentication auth = (NtlmPasswordAuthentication)file.getPrincipal();
        ACE[] security = file.getSecurity(true);

        SID serverSid = SID.getServerSid(server, auth);

        for (int ai = 0; ai < security.length; ai++) {
            ACE ace = security[ai];
            SID sid = ace.getSID();

            if (sid.getType() == SID.SID_TYPE_ALIAS && serverSid.equals(sid.getDomainSid())) {
                System.out.println(sid.toString() + " (" + sid.toDisplayString() + ") members:");

                SID[] mems = sid.getGroupMemberSids(server, auth, SID.SID_FLAG_RESOLVE_SIDS);
                for (int mi = 0; mi < mems.length; mi++) {
                    SID mem = mems[mi];
                    System.out.println("  " + mem.getType() + " " + mem.toDisplayString());
                }
            }
        }
    }
}
