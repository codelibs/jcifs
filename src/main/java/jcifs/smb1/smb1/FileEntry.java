package jcifs.smb1.smb1;

/**
 * Represents a file or directory entry in SMB1 protocol.
 */
public interface FileEntry {

    /**
     * Gets the name of the file or directory.
     *
     * @return the file or directory name
     */
    String getName();

    /**
     * Gets the type of the entry.
     *
     * @return the entry type
     */
    int getType();

    /**
     * Gets the file attributes.
     *
     * @return the file attributes
     */
    int getAttributes();

    /**
     * Gets the creation time.
     *
     * @return the creation time in milliseconds since epoch
     */
    long createTime();

    /**
     * Gets the last modified time.
     *
     * @return the last modified time in milliseconds since epoch
     */
    long lastModified();

    /**
     * Gets the file size.
     *
     * @return the file size in bytes
     */
    long length();
}
