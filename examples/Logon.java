import jcifs.*;
import jcifs.smb.*;

public class Logon {

    /* java Logon 192.168.1.15 "dom;user:pass"
     */

    public static void main( String argv[] ) throws Exception {
        UniAddress dc = UniAddress.getByName( argv[0] );
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication( argv[1] );
        SmbSession.logon( dc, auth );
    }
}

