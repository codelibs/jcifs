import java.net.*;
import java.util.*;

public class URLTest {

    public static void main( String[] argv ) throws Exception {
        URL url;

        jcifs.Config.registerSmbURLHandler();

        if( argv.length > 2 ) {
            url = new URL( new URL( new URL( argv[0] ), argv[1] ), argv[2] );
        } else if( argv.length > 1 ) {
            url = new URL( new URL( argv[0] ), argv[1] );
        } else {
            url = new URL( argv[0] );
        }
        System.out.println( "   authority: " + url.getAuthority() );
        System.out.println( "        file: " + url.getFile() );
        System.out.println( "        host: " + url.getHost() );
        System.out.println( "        port: " + url.getPort() );
        System.out.println( "        path: " + url.getPath() );
        System.out.println( "       query: " + url.getQuery() );
        System.out.println( "         ref: " + url.getRef() );
        System.out.println( "    userinfo: " + url.getUserInfo() );
        System.out.println( "externalform: " + url.toExternalForm() );
        System.out.println( "      string: " + url.toString() );

        System.exit( 0 );
    }
}
