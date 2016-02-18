import java.net.URL;
import java.io.InputStream;

public class GetURL {

    public static void main( String argv[] ) throws Exception {

        jcifs.Config.registerSmbURLHandler();

        URL url = new URL( argv[0] );
        InputStream in = url.openStream();

        if( in != null ) {
            byte[] buf = new byte[4096];
            int n;
            while(( n = in.read( buf )) != -1 ) {
                System.out.write( buf, 0, n );
            }
        } else {
            System.out.println( "stream waz null" );
        }
        in.close();
    }
}

