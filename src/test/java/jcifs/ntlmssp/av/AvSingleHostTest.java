package jcifs.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import jcifs.Configuration;

class AvSingleHostTest {

    /**
     * Test constructor AvSingleHost(byte[] raw).
     * Should correctly parse the raw bytes.
     */
    @Test
    void testAvSingleHostRawConstructor() {
        byte[] rawData = new byte[48]; // 8 (size/zero) + 8 (customData) + 32 (machineId)
        // Simulate some data
        rawData[0] = 48; // size
        rawData[16] = 0x01; // machineId start
        rawData[17] = 0x02;

        AvSingleHost avSingleHost = new AvSingleHost(rawData);

        assertNotNull(avSingleHost);
        assertEquals(AvPair.MsvAvSingleHost, avSingleHost.getType());
        assertArrayEquals(rawData, avSingleHost.getRaw());
    }

    /**
     * Test constructor AvSingleHost(Configuration cfg).
     * Should use the machine ID from the configuration.
     */
    @Test
    void testAvSingleHostConfigurationConstructor() {
        Configuration mockConfig = mock(Configuration.class);
        byte[] expectedMachineId = new byte[32];
        expectedMachineId[0] = 0x0A;
        expectedMachineId[1] = 0x0B;
        when(mockConfig.getMachineId()).thenReturn(expectedMachineId);

        AvSingleHost avSingleHost = new AvSingleHost(mockConfig);

        assertNotNull(avSingleHost);
        assertEquals(AvPair.MsvAvSingleHost, avSingleHost.getType());
        byte[] value = avSingleHost.getRaw();
        assertNotNull(value);
        assertEquals(48, value.length); // Expected size: 8 + 8 + 32

        // Verify the machine ID part
        byte[] actualMachineId = new byte[32];
        System.arraycopy(value, 16, actualMachineId, 0, 32);
        assertArrayEquals(expectedMachineId, actualMachineId);

        // Verify the size field (first 4 bytes)
        assertEquals(48, (value[0] & 0xFF) | ((value[1] & 0xFF) << 8) | ((value[2] & 0xFF) << 16) | ((value[3] & 0xFF) << 24));
    }

    /**
     * Test constructor AvSingleHost(byte[] customData, byte[] machineId).
     * Should correctly encode custom data and machine ID.
     */
    @Test
    void testAvSingleHostCustomDataMachineIdConstructor() {
        byte[] customData = new byte[8];
        customData[0] = 0x01;
        customData[7] = 0x08;

        byte[] machineId = new byte[32];
        machineId[0] = 0x10;
        machineId[31] = 0x20;

        AvSingleHost avSingleHost = new AvSingleHost(customData, machineId);

        assertNotNull(avSingleHost);
        assertEquals(AvPair.MsvAvSingleHost, avSingleHost.getType());
        byte[] value = avSingleHost.getRaw();
        assertNotNull(value);
        assertEquals(48, value.length);

        // Verify the size field (first 4 bytes)
        assertEquals(48, (value[0] & 0xFF) | ((value[1] & 0xFF) << 8) | ((value[2] & 0xFF) << 16) | ((value[3] & 0xFF) << 24));
        // Verify the zero field (next 4 bytes)
        assertEquals(0, (value[4] & 0xFF) | ((value[5] & 0xFF) << 8) | ((value[6] & 0xFF) << 16) | ((value[7] & 0xFF) << 24));

        // Verify customData part
        byte[] actualCustomData = new byte[8];
        System.arraycopy(value, 8, actualCustomData, 0, 8);
        assertArrayEquals(customData, actualCustomData);

        // Verify machineId part
        byte[] actualMachineId = new byte[32];
        System.arraycopy(value, 16, actualMachineId, 0, 32);
        assertArrayEquals(machineId, actualMachineId);
    }

    /**
     * Test with customData and machineId that are not exactly 8 and 32 bytes respectively.
     * The constructor should still use the first 8/32 bytes.
     */
    @Test
    void testAvSingleHostCustomDataMachineIdConstructor_ShorterInputs() {
        byte[] customData = { 0x01, 0x02 }; // Shorter than 8
        byte[] machineId = { 0x10, 0x11, 0x12 }; // Shorter than 32

        AvSingleHost avSingleHost = new AvSingleHost(customData, machineId);

        assertNotNull(avSingleHost);
        byte[] value = avSingleHost.getRaw();
        assertNotNull(value);
        assertEquals(48, value.length);

        // Verify customData part (should be padded with zeros)
        byte[] expectedCustomData = { 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        byte[] actualCustomData = new byte[8];
        System.arraycopy(value, 8, actualCustomData, 0, 8);
        assertArrayEquals(expectedCustomData, actualCustomData);

        // Verify machineId part (should be padded with zeros)
        byte[] expectedMachineId = new byte[32];
        expectedMachineId[0] = 0x10;
        expectedMachineId[1] = 0x11;
        expectedMachineId[2] = 0x12;
        byte[] actualMachineId = new byte[32];
        System.arraycopy(value, 16, actualMachineId, 0, 32);
        assertArrayEquals(expectedMachineId, actualMachineId);
    }

    /**
     * Test with customData and machineId that are longer than 8 and 32 bytes respectively.
     * The constructor should only use the first 8/32 bytes.
     */
    @Test
    void testAvSingleHostCustomDataMachineIdConstructor_LongerInputs() {
        byte[] customData = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }; // Longer than 8
        byte[] machineId = new byte[40]; // Longer than 32
        for (int i = 0; i < 40; i++) {
            machineId[i] = (byte) i;
        }

        AvSingleHost avSingleHost = new AvSingleHost(customData, machineId);

        assertNotNull(avSingleHost);
        byte[] value = avSingleHost.getRaw();
        assertNotNull(value);
        assertEquals(48, value.length);

        // Verify customData part (should be truncated)
        byte[] expectedCustomData = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        byte[] actualCustomData = new byte[8];
        System.arraycopy(value, 8, actualCustomData, 0, 8);
        assertArrayEquals(expectedCustomData, actualCustomData);

        // Verify machineId part (should be truncated)
        byte[] expectedMachineId = new byte[32];
        for (int i = 0; i < 32; i++) {
            expectedMachineId[i] = (byte) i;
        }
        byte[] actualMachineId = new byte[32];
        System.arraycopy(value, 16, actualMachineId, 0, 32);
        assertArrayEquals(expectedMachineId, actualMachineId);
    }
}
