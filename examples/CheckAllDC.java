import jcifs.netbios.NbtAddress;
import jcifs.*;
import jcifs.smb.*;

public class CheckAllDC {

    public static void main( String argv[] ) throws Exception {

        if( argv.length < 2 ) {
            System.err.println( "usage: CheckAllDC <domain> <dom;user:pass>" );
            System.exit(1);
        }

        NbtAddress[] addrs = NbtAddress.getAllByName( argv[0], 0x1C, null, null );

        for( int i = 0; i < addrs.length; i++ ) {
            System.out.println( addrs[i] );
            UniAddress dc = new UniAddress( addrs[i] );
            NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication( argv[1] );
            SmbSession.logon( dc, auth );
        }
    }
}
