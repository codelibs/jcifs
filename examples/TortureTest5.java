import jcifs.UniAddress;
import java.util.Enumeration;

public class TortureTest5 extends Thread {

    String name;

    TortureTest5( String name ) {
        this.name = name;
    }

    public void run() {
        try {
            System.out.println( UniAddress.getByName( name ));
        } catch( Exception e ) {
            e.printStackTrace();
        }
    }

    public static void main( String[] argv ) throws Exception {
    //  jcifs.util.Config.setProperty( "retryCount", "1" );
    //  jcifs.util.Config.setProperty( "soTimeout", "1000" );

        Thread[] threads = new Thread[30];
        for( int i = 0; i < argv.length; i++ ) {
            threads[i] = new TortureTest5( argv[i] );
        }
        for( int t = 0; t < argv.length; t++ ) {
            threads[t].start();
        }
        for( int j = 0; j < argv.length; j++ ) {
            threads[j].join();
        }
        System.exit( 0 );
    }
}
