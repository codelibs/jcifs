import jcifs.smb.SmbFile;

public class Equals {

    public static void main( String argv[] ) throws Exception {

        SmbFile f1 = new SmbFile( argv[0] );
        SmbFile f2 = new SmbFile( argv[1] );
System.out.println( f1 );
System.out.println( f2 );
        System.err.println( f1.equals( f2 ));
    }
}

