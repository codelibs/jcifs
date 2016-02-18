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

public class FileOps {

    static final int ATTR_ALL = SmbFile.ATTR_ARCHIVE | SmbFile.ATTR_HIDDEN | SmbFile.ATTR_READONLY | SmbFile.ATTR_SYSTEM;

    public static void main( String argv[] ) throws Exception {

        if( argv.length != 1 ) {
            System.out.println( "Must provide an SMB URL of a remote location on which tests will be conducted." );
            System.exit( 1 );
        }

        SmbFile s = new SmbFile( argv[0] );
        SmbFile d = new SmbFile( s, "JcifsTestOpsDir/" );

    // delete - Delete the directory if it exists

        try {
            d.delete();
        } catch( SmbException se ) {
            System.out.println( "okay - delete " + d + " failed: " + se.getMessage() );
        }
        System.out.println( "okay - delete " + d + " successful" );

    // exists - Test the directory that should not exist

        if( d.exists() ) {
            System.out.println( "fail - " + d + " still exists" );
            System.exit( 1 );
        } else {
            System.out.println( "okay - " + d + " does not exist" );
        }

    // mkdir - Create the directory

        d.mkdir();
        System.out.println( "okay - mkdir " + d + " successful" );

    // exist - Test the directory which should exist now

        if( d.exists() ) {
            System.out.println( "okay - " + d + " exists" );
        } else {
            System.out.println( "fail - " + d + " was not successfuly created" );
            System.exit( 1 );
        }

    // mkdir - Try to create a directory even though it already exists

        try {
            d.mkdir();
            System.out.println( "fail - mkdir " + d + " successful" );
            System.exit( 1 );
        } catch( SmbException se ) {
            System.out.println( "okay - mkdir " + d + " failed: " + se.getMessage() );
        }

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

    // canRead - Test to see if the new file can be read

        if( f.canRead() ) {
            System.out.println( "okay - canRead " + f + " successful" );
        } else {
            System.out.println( "fail - canRead " + f + " failed" );
            System.exit( 1 );
        }

    // canWrite, getAttributes - Test the file for writing

        if( f.canWrite() && (f.getAttributes() & SmbFile.ATTR_READONLY) == 0 ) {
            System.out.println( "okay - canWrite " + f + " successful" );
        } else {
            System.out.println( "fail - canWrite " + f + " failed" );
            System.exit( 1 );
        }

    // setReadOnly

        try {
            f.setReadOnly();
            System.out.println( "okay - setReadOnly " + f + " successful" );
        } catch( SmbException se ) {
            System.out.println( "fail - setReadOnly " + f + " failed: " + se.getMessage() );
        }

    // canWrite - Test the file for writing

        if( f.canWrite() ) {
            System.out.println( "fail - canWrite " + f + " returned true but it should have been marked read-only ... continuing on" );
        } else {
            System.out.println( "okay - canWrite " + f + " failed" );
        }

    // Try to open the file for writing

        try {
            SmbFileOutputStream w = new SmbFileOutputStream( f );
            w.close();
            System.out.println( "fail - successfuly opened " + f + " for writing even though it should be marked read-only ... continuing on" );
        } catch( IOException ioe ) {
            System.out.println( "okay - correctly failed to open " + f + " for writing: " + ioe.getMessage() );
        }

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
            System.out.println( "fail - renameTo " + f + " should have been successful even though the file is marked read-only: " + se.getMessage() );
        }

    // setAttributes

        try {
            f.setAttributes( 0xFFFF );
            System.out.println( "okay - setAttributes " + f + " successful" );
        } catch( SmbException se ) {
            System.out.println( "fail - setAttributes " + f + " failed: " + se.getMessage() );
        }

    // getAttributes

        int attr;

        if((( attr = f.getAttributes() ) & ATTR_ALL ) == ATTR_ALL ) {
            System.out.println( "okay - getAttributes " + f + " successful" );
        } else {
            System.out.println( "fail - getAttributes " + f + " failed: 0x" + jcifs.util.Hexdump.toHexString( attr, 4 ));
            System.exit( 1 );
        }

    // isHidden - Test to see if the file is hidden

        if( f.isHidden() ) {
            System.out.println( "okay - isHidden " + f + " is hidden" );
        } else {
            System.out.println( "fail - isHidden " + f + " is not hidden but it should be ... continuing on" );
        }

    // canRead - Test canRead again with both hidden and read-only on

        if( f.canRead() ) {
            System.out.println( "okay - canRead " + f + " was successful with read-only and hidden both on" );
        } else {
            System.out.println( "fail - canRead " + f + " failed with read-only and hidden both on" );
        }

    // canWrite - Test the file for writing again with read-only and hidden

        if( f.canWrite() ) {
            System.out.println( "fail - canWrite " + f + " was successful even though read-only is set ... continuing on" );
        } else {
            System.out.println( "okay - canWrite " + f + " failed as it should being that read-only is set" );
        }

    // isDirectory - Test file as a directory

        if( f.isDirectory() ) {
            System.out.println( "fail - isDirectory " + f + " returned true but it is NOT a directory" );
        } else {
            System.out.println( "okay - isDirectory " + f + " is not a directory" );
        }

    // isDirectory - Test directory as a directory

        if( d.isDirectory() ) {
            System.out.println( "okay - isDirectory " + d + " is a directory" );
        } else {
            System.out.println( "fail - isDirectory " + d + " returned false but it really is a directory" );
        }

    // isDirectory - Test directory that does not exist

        b = new SmbFile( d, "bogus" );

        if( b.isDirectory() ) {
            System.out.println( "fail - isDirectory " + b + " returned true but it does not exist" );
        } else {
            System.out.println( "okay - isDirectory " + b + " does not exist" );
        }

    // isFile - Test file as a file

        if( f.isFile() ) {
            System.out.println( "okay - isFile " + f + " is a file" );
        } else {
            System.out.println( "fail - isFile " + f + " return false but it is NOT a file" );
        }

    // isFile - Test directory as a file

        if( d.isFile() ) {
            System.out.println( "fail - isFile " + d + " returned true but it is NOT a file" );
        } else {
            System.out.println( "okay - isFile " + d + " is not a file" );
        }

    // length - Check to ensure that the length of the file is correct

        if( f.length() == 363 ) {
            System.out.println( "okay - length " + f + " is correct" );
        } else {
            System.out.println( "fail - length " + f + " is wrong: " + f.length() );
        }

    // setReadWrite

        try {
            f.setReadWrite();
            System.out.println( "okay - setReadWrite " + f + " successful" );
        } catch( SmbException se ) {
            System.out.println( "fail - setReadWrite " + f + " failed: " + se.getMessage() );
        }

    // setLastModified

        long t = (new Date()).getTime() - 1000 * 60;

        try {
            f.setLastModified( t );
            System.out.println( "okay - setLastModified " + f + " successful" );
        } catch( SmbException se ) {
            System.out.println( "fail - setLastModified " + f + " failed: " + se.getMessage() );
        }

    // lastModified

        if( f.lastModified() == t ) {
            System.out.println( "okay - lastModified " + f + " is correct" );
        } else {
            System.out.println( "fail - lastModified " + f + " is wrong: " + f.lastModified() + " vs " + t );
        }

    // setCreateTime

        try {
            f.setCreateTime( t );
            System.out.println( "okay - setCreateTime " + f + " successful" );
        } catch( SmbException se ) {
            System.out.println( "fail - setCreateTime " + f + " failed: " + se.getMessage() );
        }

    // createTime

        if( f.createTime() == t ) {
            System.out.println( "okay - createTime " + f + " is correct" );
        } else {
            System.out.println( "fail - createTime " + f + " is wrong: " + f.createTime() + " vs " + t );
        }

    // createNewFile

    // delete - See if we can delete the file even though it's read-only

        try {
            f.delete();
            System.out.println( "okay - delete " + f + " successful even though the file was read-only" );
        } catch( SmbException se ) {
            System.out.println( "fail - delete " + f + " should have turned off the read-only attribute to deleted the file: " + se.getMessage() );
        }

        SmbFile r = new SmbFile( d.getParent(), "JcifsDeleteMe/" );

    // Must delete any left over directory from a previous run

        try {
            r.delete();
            System.out.println( "okay - delete " + r + " successful" );
        } catch( SmbException se ) {
            System.out.println( "okay - delete " + r + " probably wasn't there: " + se.getMessage() );
        }

    // renameTo - Rename the whole directory to JcifsDeleteMe

        try {
            d.renameTo( r );
            System.out.println( "okay - renameTo " + d + " successful even though it is a directory" );
        } catch( SmbException se ) {
            System.out.println( "fail - renameTo " + d + " failed: " + se.getMessage() );
        }

    // delete - Now delete the whole workspace

        try {
            r.delete();
            System.out.println( "okay - delete " + r + " successful" );
        } catch( SmbException se ) {
            System.out.println( "fail - delete " + r + " failed: " + se.getMessage() );
        }
    }
}

