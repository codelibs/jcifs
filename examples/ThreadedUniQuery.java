import java.net.UnknownHostException;
import jcifs.*;

public class ThreadedUniQuery {

    static class QThread extends Thread {
        String name; 

        QThread( String name ) {
            super( name + "-thread" );
            this.name = name;
        }

        public void run() {
            try {
                System.out.println( getName() + ": started" );
                for( int i = 0; i < 15; i++ ) {
                    Thread.sleep( (long)(Math.random() * 1000L ));
                    try {
                        UniAddress.getByName( name, true );
                    } catch( UnknownHostException uhe ) {
                        uhe.printStackTrace();
                    }
                }
                System.out.println( getName() + ": done" );
            } catch( Exception x ) {
                x.printStackTrace();
            }
        }
    }

    public static void main(String[] argv) throws Exception {
        if( argv.length < 2 ) {
            System.out.println( "java ThreadedUniQuery name [name [name [...]]]" );
            return;
        }

        QThread[] t = new QThread[argv.length];
        for( int i = 0; i < argv.length; i++ ) {
            t[i] = new QThread( argv[i] );
        }
        for( int j = 0; j < argv.length; j++ ) {
            t[j].start();
        }
        for( int j = 0; j < argv.length; j++ ) {
            t[j].join();
        }
        Runtime.getRuntime().exit(0);
    }
}
