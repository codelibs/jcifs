import java.util.*;
import jcifs.smb.*;

public class GetGroupMemberSids {

    public static void main( String[] argv ) throws Exception {
        if (argv.length < 2) {
            System.err.println("usage: GetGroupMemberSids <smburl> <sidstr>");
            System.exit(1);
        }

        SmbFile file = new SmbFile(argv[0]);
        String server = file.getServer();
        NtlmPasswordAuthentication auth = (NtlmPasswordAuthentication)file.getPrincipal();
        SID sid = new SID(argv[1]);
        sid.resolve(server, auth);

        System.out.println("type=" + sid.getType());

        SID[] mems = sid.getGroupMemberSids(server, auth, SID.SID_FLAG_RESOLVE_SIDS);

        for (int mi = 0; mi < mems.length; mi++) {
            SID mem = mems[mi];
            System.out.println(mem.getType() + " " + mem.toDisplayString());
        }
    }
}
