package jcifs.smb1.smb1;

public interface FileEntry {

    String getName();

    int getType();

    int getAttributes();

    long createTime();

    long lastModified();

    long length();
}
