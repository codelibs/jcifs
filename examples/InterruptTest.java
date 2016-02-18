import java.io.InterruptedIOException;
import jcifs.util.transport.TransportException;
import jcifs.smb.*;

public class InterruptTest extends Thread {

    String url;

    public InterruptTest(String url) {
        this.url = url;
    }
    public void run() {
        for (int i = 0; i < 100; i++) {
            try {
                SmbFileInputStream in = new SmbFileInputStream(url);

                byte[] b = new byte[10];
                while(in.read( b ) > 0) {
                    ;
                }

                in.close();
            } catch(InterruptedIOException iioe) {
                System.out.println("InterruptedIOException");
                continue;
            } catch(SmbException se) {
                Throwable t = se.getRootCause();
                if (t instanceof TransportException) {
                    TransportException te = (TransportException)t;
                    t = te.getRootCause();
                    if (t instanceof InterruptedException) {
                        System.out.println("InterruptedException in constructor");
                        continue;
                    }
                }
                se.printStackTrace();
                try { Thread.sleep(500); } catch(InterruptedException ie) {}
            } catch(Exception e) {
                e.printStackTrace();
                break;
            }
        }
    }

    public static void main( String argv[] ) throws Exception {
        InterruptTest it = new InterruptTest(argv[0]);
        it.start();
        for (int i = 0; i < 20; i++) {
            Thread.sleep(200);
            it.interrupt();
        }
    }
}

