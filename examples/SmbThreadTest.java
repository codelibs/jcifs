import jcifs.smb.SmbFile;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;


import java.util.Random;
import java.net.MalformedURLException;
import java.io.IOException;

public class SmbThreadTest extends Thread {

    int maxDepth;
    int id;
    String url;
    NtlmPasswordAuthentication auth;
    long start_time;

    static Random rnd = new Random(1234);
    static long test_time = 100*1000;
    static long num_sessions = 1000;
    static long session_time = (test_time / num_sessions) * 400;

    static boolean verbose = false;


    SmbThreadTest(NtlmPasswordAuthentication auth, String url, int maxDepth, int id) {
        this.url = url;
        this.auth = auth;
        this.maxDepth = maxDepth;
        this.id = id;
        this.start_time = System.currentTimeMillis();
    }

    void traverse( SmbFile f, int depth ) throws MalformedURLException, IOException {

        if( depth == 0 ) {
            return;
        }
        SmbFile[] l = null;
        try {
            if (f.exists())
                l = f.listFiles();
        } catch (SmbAuthException ae) {
            System.err.println("SAE: " + ae.getMessage());
            ae.printStackTrace( System.err );
            return;
        } catch (NullPointerException npe) {
            System.err.println("NPE");
            npe.printStackTrace( System.err );
            return;
        }
        for(int i = 0; l != null && i < l.length; i++ ) {
            try {
                boolean exists = l[i].exists();
                if (verbose) {
                    System.out.print(id);
                    for( int j = maxDepth - depth; j > 0; j-- ) {
                       System.out.print( "    " );
                    }
                    System.out.println( l[i] + " " + exists );
                }
                if( l[i].isDirectory() ) {
                    traverse( l[i], depth - 1 );
                }
            } catch (SmbAuthException ae) {
                System.err.println("SAE: " + ae.getMessage());
                ae.printStackTrace( System.err );
            } catch( IOException ioe ) {
                System.out.println( l[i] + ":" );
                ioe.printStackTrace( System.out );
            }
            try {
                Thread.sleep(Math.abs(rnd.nextInt(2)+1));
            } catch (InterruptedException e) {

            } 
        }
    }

    public void run () {
        SmbFile f = null;
        int runs = 0;
        while(true) {
            try {
                Thread.sleep(100);
            }catch (InterruptedException e) {}

            while (f == null) {
                try {
                    f = new SmbFile(url, auth);
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                    e.printStackTrace();
                }
            }
            try {
                traverse(f, maxDepth);
            } catch (Exception e) {
                System.err.println(e.getMessage());
                e.printStackTrace();
            }
            runs++;
            long time =  System.currentTimeMillis() - start_time;
            if (time > session_time) {
                System.err.println(id + " exit (" + time/runs + ")");
                return;
            }
        }
    }

    public static void createThreads(String url, int i, int count) {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(null);
        int num = 0;
        System.err.println("creating " + count  + " threads");
        while (num < count) {
            SmbThreadTest sc = new SmbThreadTest(auth, url, 3, i * 100 + num++);
            sc.start();
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }
    }

    public static void main(String[] argv) throws Exception {
        for(int i = 0; i < num_sessions; i++) {
            createThreads(argv[0], i+1, Math.abs(rnd.nextInt(4)+1));
            sleep((test_time / num_sessions)*100);
        }
        sleep(6000000);
    }
}

