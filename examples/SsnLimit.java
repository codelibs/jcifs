import jcifs.*;
import jcifs.smb.*;

public class SsnLimit {

    public static void main( String argv[] ) throws Exception {
        jcifs.Config.setProperty( "jcifs.smb.client.ssnLimit", "1" );
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication( null, null, null );
        UniAddress addr = UniAddress.getByName( argv[0] );
        for( int i = 0; i < 25; i++ ) {
            SmbSession.logon( addr, auth );
            Thread.sleep( 1000 );
        }
        Thread.sleep( 10000 );
    }
}

