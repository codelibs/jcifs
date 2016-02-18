import jcifs.netbios.*;

public class ThreadedNbtQuery {

    static class QThread extends Thread {
        String name; 

        QThread( String name ) {
            this.name = name;
        }

        public void run() {
            try {
                yield();
                System.out.println( getName() + ": started" );
                NbtAddress.getByName( name );
                System.out.println( getName() + ": done" );
            } catch( Exception x ) {
                x.printStackTrace();
            }
        }
    }

    public static void main(String[] argv) throws Exception {
        if( argv.length < 2 ) {
            System.out.println( "java ThreadedNbtQuery name [name [name [...]]]" );
            return;
        }

        QThread[] t = new QThread[argv.length];
        for( int i = 0; i < argv.length; i++ ) {
            t[i] = new QThread( argv[i] );
        }
        for( int j = 0; j < argv.length; j++ ) {
            t[j].start();
        }
    }
}
