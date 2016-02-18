import java.util.*;
import jcifs.smb.*;

public class GetLocalGroupsMap {

    public static void main( String[] argv ) throws Exception {

        SmbFile file = new SmbFile(argv[0]);
        String server = file.getServer();
        NtlmPasswordAuthentication auth = (NtlmPasswordAuthentication)file.getPrincipal();
        Map map = SID.getLocalGroupsMap(server,
                    auth,
                    SID.SID_FLAG_RESOLVE_SIDS);


        Iterator kiter = map.keySet().iterator();
        while (kiter.hasNext()) {
            SID userSid = (SID)kiter.next();

            System.out.println(userSid.getType() + " " + userSid.toDisplayString() + ":");

            ArrayList groupSids = (ArrayList)map.get(userSid);
            Iterator giter = groupSids.iterator();
            while (giter.hasNext()) {
                SID group = (SID)giter.next();
                System.out.println("  " + group.getType() + " " + group.toDisplayString());
            }
        }
    }
}
