import java.net.MalformedURLException;
import jcifs.smb.*;
import java.io.*;

public class VerifyIO {

    static File get( SmbFile f0 ) throws Exception {
        int i;
        File f1;
        byte[] buf = new byte[8192];

        f1 = new File( f0.getName() );
        FileOutputStream out = new FileOutputStream( f1 );
        SmbFileInputStream in = new SmbFileInputStream( f0 );

        while(( i = in.read( buf )) > 0 ) {
            out.write( buf, 0, i );
            System.err.print( '.' );
        }

        in.close();
        out.close();

        return f1;
    }
    static void put( SmbFile f2 ) throws Exception {
        int i;
        byte[] buf = new byte[8192];

        FileInputStream in = new FileInputStream( f2.getName() );
        SmbFileOutputStream out = new SmbFileOutputStream( f2 );

        while(( i = in.read( buf )) > 0 ) {
            out.write( buf, 0, i );
            System.err.print( '-' );
        }

        in.close();
        out.close();
    }

    public static void main(String[] argv) throws Exception {
        BufferedReader in;
        String name;

        if( argv.length < 2 ) {
            System.err.println( "Must provide file of SMB URLs and destination directory" );
            System.exit( 1 );
        }

        in = new BufferedReader( new FileReader( argv[0] ));
        while(( name = in.readLine() ) != null ) {
            SmbFile f0, f2;
            File f1;

            System.err.print( name + ": " );
            f0 = new SmbFile( name );
            f1 = get( f0 );

            if( f0.length() != f1.length() ) {
                throw new RuntimeException( "File lengths do not match: f0=" + f0.length() + ",f1=" + f1.length() );
            }

            f2 = new SmbFile( argv[1] + "/" + f0.getName() );
            put( f2 );

            if( f1.length() != f2.length() ) {
                throw new RuntimeException( "File lengths do not match: f1=" + f1.length() + ",f2=" + f2.length() );
            }

            f1.delete();
            System.err.println( " ok" );
        }
    }
}

