import jcifs.smb.SmbFile;

public class CopyTo {

    public static void main( String argv[] ) throws Exception {

        SmbFile from = new SmbFile( argv[0] );
        SmbFile to = new SmbFile( argv[1] );
        from.copyTo( to );
    }
}

