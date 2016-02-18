import jcifs.netbios.NbtAddress;
import jcifs.util.*;
import jcifs.smb.*;
import java.util.Date;

public class AuthListFiles extends NtlmAuthenticator {

    public static String readLine() throws Exception {
        int c;
        StringBuffer sb = new StringBuffer();
        while(( c = System.in.read() ) != '\n' ) {
            if( c == -1 ) return "";
            sb.append( (char)c );
        }
        return sb.toString().trim();
    }

    public AuthListFiles( String[] argv ) throws Exception {
        NtlmAuthenticator.setDefault( this );

        SmbFile file = new SmbFile( argv[0] );

        SmbFile[] files = file.listFiles();

        for( int i = 0; i < files.length; i++ ) {
            System.out.print( " " + files[i].getName() );
        }
        System.out.println();
    }

    protected NtlmPasswordAuthentication getNtlmPasswordAuthentication() {
        System.out.println( getRequestingException().getMessage() + " for " + getRequestingURL() );
        try {
            System.out.print( "username: " );
            String username = readLine();

            System.out.print( "password: " );
            String password = readLine();

            if( password.length() == 0 ) {
                return null;
            }
            return new NtlmPasswordAuthentication( null, username, password );
        } catch( Exception e ) {
        }
        return null;
    }


    public static void main( String[] argv ) throws Exception {
        new AuthListFiles( argv );
    }
}
