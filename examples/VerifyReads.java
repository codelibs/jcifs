import java.net.MalformedURLException;
import jcifs.smb.*;
import java.io.*;

public class VerifyReads {

    int maxDepth;
    byte[] buf = new byte[8192];

    VerifyReads( int maxDepth ) {
        this.maxDepth = maxDepth;
    }

    void mkdir( File dir ) {
        if( dir != null && !dir.exists() ) {
            mkdir( dir.getParentFile() );
            dir.mkdir();
        }
    }

    void copy( SmbFile f, String path, int depth ) throws MalformedURLException, IOException {
        int i, d;
        File localFile, dir;
        SmbFile[] list;

        if( depth == 0 ) {
            return;
        }

        localFile = new File( path + "/" + f.getName() );
        d = f.getName().lastIndexOf( '.' );

        if( f.isDirectory() ) {

            list = f.listFiles();

            for( i = 0; i < list.length; i++ ) {
                copy( list[i], path + "/" + f.getName(), depth - 1 );
            }
        } else if( d > 1 && f.getName().substring( d ).equalsIgnoreCase( ".ini" )) {

            mkdir( new File( path ));

            SmbFileInputStream in = new SmbFileInputStream( f );
            FileOutputStream out = new FileOutputStream( localFile );

            while(( i = in.read( buf )) > 0 ) {
                out.write( buf, 0, i );
            }

            in.close();
            out.close();
        }
    }

    public static void main(String[] argv) throws Exception {
        VerifyReads cd;
        SmbFile top;
        int depth;

        if( argv.length < 2 ) {
            System.err.println( "Must specify ini directory location (e.g. smb://mydom\\;user:pass@nyc-19b9/apps) followd by the maximum traversal depth");
            System.exit( 1 );
        }

        depth = Integer.parseInt( argv[1] );
        cd = new VerifyReads( depth );
        top = new SmbFile( argv[0] );

        if( !top.isDirectory() ) {
            System.err.println( "The path specified is not a directory" );
            System.exit( 1 );
        }

        cd.copy( top, ".", depth );
    }
}

