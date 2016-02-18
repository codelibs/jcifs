import java.util.*;
import jcifs.smb.*;

public class GetServerSidFromURL {

    public static void main( String[] argv ) throws Exception {
        if (argv.length < 1) {
            System.err.println("usage: GetServerSidFromURL <smburl>");
            System.exit(1);
        }

        SmbFile file = new SmbFile(argv[0]);
        String server = file.getServer();
        NtlmPasswordAuthentication auth = (NtlmPasswordAuthentication)file.getPrincipal();

        SID serverSid = SID.getServerSid(server, auth);

        System.out.println(serverSid);
    }
}
