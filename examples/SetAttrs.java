import jcifs.smb.*;

public class SetAttrs {

    public static void main( String argv[] ) throws Exception {
        if( argv.length < 2 ) {
            System.err.println( "usage: SetAttrs <smburl> <hexval>" );
            return;
        }

        SmbFile f = new SmbFile( argv[0] );
        SmbFileInputStream in = new SmbFileInputStream( f );
        int attrs = Integer.parseInt( argv[1], 16 );

        f.setAttributes( attrs );
    }
}

