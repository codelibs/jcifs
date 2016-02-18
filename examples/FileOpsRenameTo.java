/* Test the following file operations:
 * 
 * canRead
 *     false - a target that is already open by another process
 *     false - the target does not exist
 *     true  - the file exists and there are no sharing issues
 * canWrite
 *     true  - the file exists and there are no sharing issues
 *     false - the file is marked read-only
 *     false - the file does not exist
 * delete
 *     true  - the file existed and was succcessfully deleted
 *     false - the target did not exist
 *     false - the target is a share, server, workgroup or similar
 *     false - the target or file under the target directory failed was read-only
 * exists
 *     true  - the target, share, IPC share, named pipe, server, or workgroup exists
 *     false - the opposite of the above
 * isDirectory
 *     true  - the target is a workgroup, server, share, or directory
 *     false - the target is not one of the above or does not exist
 * isFile
 *     direct opposite of isDirectory
 * isHidden
 *     true  - target is share ending in $ or marked as hidden
 * length
 *     the file was created to be no larger than ~2G and reports back the size specified
 * mkdir
 *     true  - a directory was created successfuly
 *     false - the directory could not be created
 * renameTo
 *     true  - the target was renamed
 */

import jcifs.smb.*;
import java.io.IOException;
import java.util.Date;

public class FileOpsRenameTo {

    static final int ATTR_ALL = SmbFile.ATTR_ARCHIVE | SmbFile.ATTR_HIDDEN | SmbFile.ATTR_READONLY | SmbFile.ATTR_SYSTEM;

    public static void main( String argv[] ) throws Exception {

        if( argv.length != 1 ) {
            System.out.println( "Must provide an SMB URL of a remote location on which tests will be conducted." );
            System.exit( 1 );
        }

        SmbFile s = new SmbFile( argv[0] );
        SmbFile d = new SmbFile( s, "JcifsTestOpsDir/" );

    // Create a file to test against

    SmbFile f = null;
    try {
        f = new SmbFile( d, "foo.txt" );
        SmbFileOutputStream o = new SmbFileOutputStream( f );
        o.write( "The Common Internet File System (CIFS) is the de-facto file sharing protocol on the Microsoft Windows platform. It is the underlying networking protocol used when accessing shares with Windows Explorer, the Network Neighborhood, via a Map Network Drive...  dialog, the C:\\> net use * \\\\server\\share commands, or smbclient on UNIX, smbfs on Linux, and elsewhere.\r\n".getBytes() );
        o.close();
    } catch( IOException ioe ) {
        System.out.println( "fail - could not create file " + d + "foo.txt: " + ioe.getMessage() );
    }
    System.out.println( "okay - created file " + d + "foo.txt" );

    // renameTo - rename the file to bar.txt

        SmbFile b = new SmbFile( d, "bar.txt" );

        try {
            f.renameTo( b );
            System.out.println( "okay - renameTo " + f + " to " + b + " successful even with read-only" );
            try {
                b.renameTo(f);
            } catch( SmbException se ) {
                System.out.println( "fail - but failed to rename file back to original!" );
                throw se;
            }
        } catch( SmbException se ) {
            se.printStackTrace();
        }

    }
}

