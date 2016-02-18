import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Method;
import java.io.PrintStream;
import java.io.InputStream;

import jcifs.Config;

/*
This test was used to provoke the following exception:

Exception in thread "main" .java.lang.ExceptionInInitializerError
    at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
    at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:39)
    at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:25)
    at java.lang.reflect.Method.invoke(Method.java:592)
    at ClassLoaderTest.main(ClassLoaderTest.java:46)
Caused by: java.util.ConcurrentModificationException
    at java.util.Hashtable$Enumerator.next(Hashtable.java:1020)
    at java.util.Hashtable.putAll(Hashtable.java:469)
    at jcifs.Config.load(Config.java:164)
    at jcifs.Config.<clinit>(Config.java:70)

caused by this line of code in the jcifs.Config static initializer:

  prp.putAll( System.getProperties() );

The fix is to simply clone() the system properties like:

  prp.putAll( (java.util.Map)System.getProperties().clone() );

At least this removes the error.
*/

public class ClassLoaderTest implements Runnable {

    static final int MULT = 1;

    public void run()
    {
        for (int i = 0; i < (ClassLoaderTest.MULT * 700); i++) {
            System.setProperty("i" + i, "x");
            System.err.print('.');
        }
    }

    public static void main(String[] argv) throws Exception
    {
        if (argv.length < 1) {
            System.err.println("usage: ClassLoaderTest <jcifsjarpath>");
            System.exit(1);
        }

        ClassLoaderTest clt = new ClassLoaderTest();
        (new Thread(clt)).start();

        for (int j = 0; j < (ClassLoaderTest.MULT * 100); j++) {
            URL url = new URL(argv[0]);
            URLClassLoader ucl = URLClassLoader.newInstance(new URL[] {url});
            Class c = ucl.loadClass("jcifs.Config");
/*
            Method m = c.getMethod("list", PrintStream.class);
            m.invoke(null, new Object[] { System.err });
*/
            Method m = c.getMethod("load", InputStream.class);
            m.invoke(null, new Object[] { null });
            ucl = null;
            System.err.print('+');
        }

    }
}
