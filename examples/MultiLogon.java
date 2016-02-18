import jcifs.smb.*;

public class MultiLogon {

    public static void main( String argv[] ) throws Exception {
        if (argv.length < 1) {
            System.err.println( "usage: Dual <cred1> <cred2> <smburl>\n");
            return;
        }

        NtlmPasswordAuthentication auth1 = new NtlmPasswordAuthentication( argv[0] );
        NtlmPasswordAuthentication auth2 = new NtlmPasswordAuthentication( argv[1] );

        SmbFile f1 = new SmbFile( argv[2], auth1 );
        SmbFile f2 = new SmbFile( argv[2], auth2 );

        f1.exists();
        f2.exists();
    }
}

