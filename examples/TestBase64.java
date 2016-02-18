import jcifs.util.Base64;
import jcifs.util.Hexdump;

public class TestBase64 {

    public void run(String str) throws Exception
    {
        Base64 b64 = new Base64();

        byte[] bytes = b64.decode(str);

        Hexdump.hexdump(System.out, bytes, 0, bytes.length);
    }

    public static void main(String[] argv) throws Exception {
        if (argv.length < 1) {
            System.err.println( "usage: TestBase64 <b64>" );
            System.exit(1);
        }
        TestBase64 t = new TestBase64();
        t.run(argv[0]);
    }
}
