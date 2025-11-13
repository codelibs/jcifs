package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComBlankResponse} class.
 */
@DisplayName("SmbComBlankResponse Tests")
public class SmbComBlankResponseTest {

    private CIFSContext context;
    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        Properties properties = new Properties();
        config = new PropertyConfiguration(properties);
        context = mock(CIFSContext.class);
        when(context.getConfig()).thenReturn(config);
    }

    @Test
    @DisplayName("Constructor creates blank response")
    public void shouldCreateBlankResponse() {
        // When
        SmbComBlankResponse response = new SmbComBlankResponse(config);

        // Then
        assertNotNull(response);
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat writes nothing")
    public void shouldWriteNoParameterWords() {
        // Given
        SmbComBlankResponse response = new SmbComBlankResponse(config);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = response.writeParameterWordsWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("writeBytesWireFormat writes nothing")
    public void shouldWriteNoBytes() {
        // Given
        SmbComBlankResponse response = new SmbComBlankResponse(config);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = response.writeBytesWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("readParameterWordsWireFormat reads nothing")
    public void shouldReadNoParameterWords() {
        // Given
        SmbComBlankResponse response = new SmbComBlankResponse(config);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("readBytesWireFormat reads nothing")
    public void shouldReadNoBytes() {
        // Given
        SmbComBlankResponse response = new SmbComBlankResponse(config);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("toString contains class name")
    public void shouldIncludeClassNameInToString() {
        // Given
        SmbComBlankResponse response = new SmbComBlankResponse(config);

        // When
        String result = response.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComBlankResponse"));
    }

    @Test
    @DisplayName("Multiple instances are independent")
    public void shouldCreateIndependentInstances() {
        // Given
        SmbComBlankResponse response1 = new SmbComBlankResponse(config);
        SmbComBlankResponse response2 = new SmbComBlankResponse(config);

        // Then
        assertNotNull(response1);
        assertNotNull(response2);
        assertNotSame(response1, response2);
    }

    @Test
    @DisplayName("Can be used with various buffer sizes")
    public void shouldWorkWithVariousBufferSizes() {
        // Given
        SmbComBlankResponse response = new SmbComBlankResponse(config);

        // When & Then - should not throw with various buffer sizes
        assertDoesNotThrow(() -> {
            response.writeParameterWordsWireFormat(new byte[0], 0);
            response.writeParameterWordsWireFormat(new byte[100], 0);
            response.writeBytesWireFormat(new byte[0], 0);
            response.writeBytesWireFormat(new byte[100], 0);
            response.readParameterWordsWireFormat(new byte[0], 0);
            response.readParameterWordsWireFormat(new byte[100], 0);
            response.readBytesWireFormat(new byte[0], 0);
            response.readBytesWireFormat(new byte[100], 0);
        });
    }
}
