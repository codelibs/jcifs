import jcifs.smb.*;

public class TestCopy {

    public static void main( String[] args ) throws Exception {

        if( args.length < 1 ) {
            System.err.println( "usage: TestCopy <from1> <to1> [<from2> <to2> [<from3 ...]]");
            System.exit(1);
        }

        for( int i = 0; i < args.length; i += 2 ) {
            try {
                SmbFile remote = new SmbFile( args[i] );
                if( remote.exists() ) {
                    SmbFile local = new SmbFile( args[i + 1] );
                    remote.copyTo( local );
                }
            } catch( Exception e ) {
                System.err.println( args[i] + " -> " + args[i + 1] );
                e.printStackTrace();
            }
        }
    }
}
