import jcifs.smb.SmbFile;

public class Mkdir {

    public static void main( String argv[] ) throws Exception {
        (new SmbFile( argv[0] )).mkdir();
    }
}

