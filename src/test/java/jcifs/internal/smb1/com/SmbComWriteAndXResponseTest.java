package jcifs.internal.smb1.com;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Properties;

public class SmbComWriteAndXResponseTest {

    private Configuration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        config = new PropertyConfiguration(new Properties());
    }

    /**
     * Test of readParameterWordsWireFormat method
     */
    @Test
    public void testReadParameterWordsWireFormat() {
        // Given
        byte[] buffer = new byte[] { (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0 };
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(8, result);
        assertEquals(0xffffL, instance.getCount());
    }

    /**
     * Test of readParameterWordsWireFormat with zero count
     */
    @Test
    public void testReadParameterWordsWireFormatZeroCount() {
        // Given
        byte[] buffer = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(8, result);
        assertEquals(0L, instance.getCount());
    }

    /**
     * Test of writeParameterWordsWireFormat method
     */
    @Test
    public void testWriteParameterWordsWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.writeParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    /**
     * Test of writeBytesWireFormat method
     */
    @Test
    public void testWriteBytesWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.writeBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    /**
     * Test of readBytesWireFormat method
     */
    @Test
    public void testReadBytesWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    /**
     * Test of toString method
     */
    @Test
    public void testToString() {
        // Given
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        String result = instance.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComWriteAndXResponse"));
        assertTrue(result.contains("count=0"));
    }
}
