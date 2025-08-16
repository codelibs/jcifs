package jcifs.smb1.smb1;

import java.io.IOException;
import java.io.InputStream;

/**
 * Test class for SMB file locking operations.
 * This class is used to test concurrent file access and locking behavior.
 */
public class TestLocking implements Runnable {

    /**
     * Default constructor for TestLocking
     */
    public TestLocking() {
        // Default constructor
    }

    int numThreads = 1;
    int numIter = 1;
    long delay = 100;
    String url = null;
    int numComplete = 0;
    long ltime = 0L;

    @Override
    public void run() {
        try {
            final SmbFile f = new SmbFile(url);
            final SmbFile d = new SmbFile(f.getParent());
            final byte[] buf = new byte[1024];

            for (int ii = 0; ii < numIter; ii++) {

                synchronized (this) {
                    ltime = System.currentTimeMillis();
                    wait();
                }

                try {
                    final double r = Math.random();
                    if (r < 0.333) {
                        f.exists();
                        //                      System.out.print('e');
                    } else if (r < 0.667) {
                        d.listFiles();
                        //                      System.out.print('l');
                    } else if (r < 1.0) {
                        final InputStream in = f.getInputStream();
                        while (in.read(buf) > 0) {
                            //                          System.out.print('r');
                        }
                        in.close();
                    }
                } catch (final IOException ioe) {
                    System.err.println(ioe.getMessage());
                    //ioe.printStackTrace(System.err);
                }

            }
        } catch (final Exception e) {
            e.printStackTrace();
        } finally {
            numComplete++;
        }
    }

    /**
     * Main method to run the locking test.
     *
     * @param args command line arguments: [-t numThreads] [-i numIter] [-d delay] url
     * @throws Exception if an error occurs during test execution
     */
    public static void main(final String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: TestLocking [-t <numThreads>] [-i <numIter>] [-d <delay>] url");
            System.exit(1);
        }

        final TestLocking t = new TestLocking();
        t.ltime = System.currentTimeMillis();

        for (int ai = 0; ai < args.length; ai++) {
            if (args[ai].equals("-t")) {
                ai++;
                t.numThreads = Integer.parseInt(args[ai]);
            } else if (args[ai].equals("-i")) {
                ai++;
                t.numIter = Integer.parseInt(args[ai]);
            } else if (args[ai].equals("-d")) {
                ai++;
                t.delay = Long.parseLong(args[ai]);
            } else {
                t.url = args[ai];
            }
        }

        final Thread[] threads = new Thread[t.numThreads];
        int ti;

        for (ti = 0; ti < t.numThreads; ti++) {
            threads[ti] = new Thread(t);
            System.out.print(threads[ti].getName());
            threads[ti].start();
        }

        while (t.numComplete < t.numThreads) {
            long delay;

            do {
                delay = 2L;

                synchronized (t) {
                    final long expire = t.ltime + t.delay;
                    final long ctime = System.currentTimeMillis();

                    if (expire > ctime) {
                        delay = expire - ctime;
                    }
                }

                if (delay > 2) {
                    System.out.println("delay=" + delay);
                }
                Thread.sleep(delay);
            } while (delay > 2);

            synchronized (t) {
                t.notifyAll();
            }
            //System.out.println("numComplete=" + t.numComplete + ",numThreads=" + t.numThreads);
        }

        for (ti = 0; ti < t.numThreads; ti++) {
            threads[ti].join();
            System.out.print(threads[ti].getName());
        }

        System.out.println();
    }
}
