import jcifs.smb.*;

public class Interleave {

    static class IThread extends Thread {
        String url;

        IThread( String url ) {
            this.url = url;
        }

        public void run() {
            try {
                yield();
                System.out.println( getName() + ": started" );
                SmbFileOutputStream o = new SmbFileOutputStream( url );
                o.close();
                System.out.println( getName() + ": done" );
            } catch( Exception x ) {
                x.printStackTrace();
            }
        }
    }

    public static void main(String[] argv) throws Exception {
        if( argv.length < 2 ) {
            System.out.println( "java Interleave dir numThreads" );
            return;
        }
    
        int numThreads = Integer.parseInt( argv[1] );
        IThread[] t = new IThread[numThreads];
        for( int i = 0; i < numThreads; i++ ) {
            t[i] = new IThread( argv[0] + "/it" + i + ".tmp" );
        }
        for( int j = 0; j < numThreads; j++ ) {
            t[j].start();
        }
    }
}
