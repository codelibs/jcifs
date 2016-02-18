import jcifs.smb.*;

public class CopyToTest extends Thread {

    String url1, url2;

    CopyToTest(String url1, String url2) {
        this.url1 = url1;
        this.url2 = url2;
    }

    public void run() {
        for (int i = 0; i < 1; i++) {
            try {
                SmbFile file = new SmbFile(url1);
                SmbFile to = new SmbFile(url2);
                file.copyTo(to);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        CopyToTest cts = new CopyToTest(args[0], args[1]);
        cts.start();
        Thread.sleep(50000);
    }
}
