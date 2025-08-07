package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.NetbiosAddress;
import jcifs.NetbiosName;
import jcifs.ResolverType;
import jcifs.SmbConstants;

/**
 * Test class for NameServiceClientImpl focusing on public API methods.
 * This test only tests the public interface to avoid accessing private fields/methods.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("NameServiceClientImpl Tests")
class NameServiceClientImplTest {

    @Mock
    private CIFSContext mockContext;
    
    @Mock
    private Configuration mockConfig;
    
    @Mock
    private NetbiosAddress mockNetbiosAddress;
    
    @Mock
    private Address mockAddress;

    private NameServiceClientImpl nameServiceClient;

    @BeforeEach
    void setUp() throws UnknownHostException {
        // Configure mock context
        when(mockContext.getConfig()).thenReturn(mockConfig);
        
        // Setup basic configuration values
        when(mockConfig.getNetbiosSoTimeout()).thenReturn(5000);
        when(mockConfig.getNetbiosRetryTimeout()).thenReturn(3000);
        when(mockConfig.getNetbiosRetryCount()).thenReturn(3);
        when(mockConfig.getNetbiosLocalPort()).thenReturn(0);
        when(mockConfig.getNetbiosLocalAddress()).thenReturn(InetAddress.getByName("127.0.0.1"));
        when(mockConfig.getBroadcastAddress()).thenReturn(InetAddress.getByName("255.255.255.255"));
        when(mockConfig.getNetbiosSndBufSize()).thenReturn(576);
        when(mockConfig.getNetbiosRcvBufSize()).thenReturn(576);
        when(mockConfig.getResolveOrder()).thenReturn(Arrays.asList(ResolverType.RESOLVER_LMHOSTS, ResolverType.RESOLVER_DNS, ResolverType.RESOLVER_BCAST));
        when(mockConfig.getNetbiosHostname()).thenReturn("TESTHOST");
        when(mockConfig.getNetbiosScope()).thenReturn(null);
        when(mockConfig.getNetbiosCachePolicy()).thenReturn(SmbConstants.FOREVER);
        when(mockConfig.getWinsServers()).thenReturn(new InetAddress[0]);
        when(mockConfig.getOemEncoding()).thenReturn("Cp850");
        
        // Setup mock Name constructor behavior
        lenient().when(mockConfig.getResolveOrder()).thenReturn(Arrays.asList(ResolverType.RESOLVER_LMHOSTS, ResolverType.RESOLVER_DNS, ResolverType.RESOLVER_BCAST));
        
        // Create the name service client with mock context
        nameServiceClient = new NameServiceClientImpl(mockContext);
    }

    @Test
    @DisplayName("Should get local host name")
    void testGetLocalName() {
        // When
        NetbiosName localName = nameServiceClient.getLocalName();
        
        // Then
        assertNotNull(localName, "Local name should not be null");
        assertTrue(localName.getName().length() > 0, "Local name should not be empty");
    }

    @Test
    @DisplayName("Should get unknown name")
    void testGetUnknownName() {
        // When
        NetbiosName unknownName = nameServiceClient.getUnknownName();
        
        // Then
        assertNotNull(unknownName, "Unknown name should not be null");
        assertEquals("0.0.0.0", unknownName.getName(), "Unknown name should be 0.0.0.0");
    }

    @Test
    @DisplayName("Should handle null hostname in getByName")
    void testGetByNameWithNull() {
        // When/Then
        assertThrows(UnknownHostException.class, () -> {
            nameServiceClient.getByName(null);
        }, "Should throw UnknownHostException for null hostname");
    }

    @Test
    @DisplayName("Should handle empty hostname in getByName")
    void testGetByNameWithEmpty() {
        // When/Then
        assertThrows(UnknownHostException.class, () -> {
            nameServiceClient.getByName("");
        }, "Should throw UnknownHostException for empty hostname");
    }

    @Test
    @DisplayName("Should handle localhost in getByName")
    void testGetByNameWithLocalhost() throws UnknownHostException {
        // When
        Address address = nameServiceClient.getByName("localhost");
        
        // Then
        assertNotNull(address, "Should return address for localhost");
    }

    @Test
    @DisplayName("Should handle IP address in getByName")
    void testGetByNameWithIPAddress() throws UnknownHostException {
        // When
        Address address = nameServiceClient.getByName("127.0.0.1");
        
        // Then
        assertNotNull(address, "Should return address for IP address");
        assertEquals("127.0.0.1", address.getHostAddress(), "Should return correct IP address");
    }

    @Test
    @DisplayName("Should get all addresses by name")
    void testGetAllByName() throws UnknownHostException {
        // When
        Address[] addresses = nameServiceClient.getAllByName("localhost", false);
        
        // Then
        assertNotNull(addresses, "Should return addresses array");
        assertTrue(addresses.length > 0, "Should return at least one address");
    }

    @Test
    @DisplayName("Should handle NetBIOS name resolution")
    void testGetNbtByName() throws UnknownHostException {
        // When/Then - Should throw UnknownHostException for non-existent names
        UnknownHostException exception = assertThrows(UnknownHostException.class, () -> {
            nameServiceClient.getNbtByName("NONEXISTENT");
        }, "Should throw UnknownHostException for non-existent NetBIOS name");
        
        // Verify the exception message indicates name resolution failure
        assertTrue(exception.getMessage().contains("NONEXISTENT") || 
                   exception.getMessage().contains("unknown") ||
                   exception.getMessage().contains("not found"),
                   "Exception message should indicate name resolution failure");
    }

    @Test
    @DisplayName("Should handle NetBIOS name with type and scope")
    void testGetNbtByNameWithTypeAndScope() throws UnknownHostException {
        // When/Then - Should throw UnknownHostException for non-existent names
        UnknownHostException exception = assertThrows(UnknownHostException.class, () -> {
            nameServiceClient.getNbtByName("NONEXISTENT", 0x20, null);
        }, "Should throw UnknownHostException for non-existent NetBIOS name with type");
        
        // Verify the exception message indicates name resolution failure
        assertTrue(exception.getMessage().contains("NONEXISTENT") || 
                   exception.getMessage().contains("unknown") ||
                   exception.getMessage().contains("not found"),
                   "Exception message should indicate name resolution failure");
    }

    @Test
    @DisplayName("Should handle NetBIOS all by name")
    void testGetNbtAllByName() throws UnknownHostException {
        // When/Then - Should throw UnknownHostException for non-existent names
        UnknownHostException exception = assertThrows(UnknownHostException.class, () -> {
            nameServiceClient.getNbtAllByAddress("NONEXISTENT");
        }, "Should throw UnknownHostException for non-existent NetBIOS name");
        
        // Verify the exception message indicates name resolution failure
        assertTrue(exception.getMessage().contains("NONEXISTENT") || 
                   exception.getMessage().contains("unknown") ||
                   exception.getMessage().contains("not found"),
                   "Exception message should indicate name resolution failure");
    }

    @Test
    @DisplayName("Should handle constructor with context")
    void testConstructor() {
        // When
        NameServiceClientImpl client = new NameServiceClientImpl(mockContext);
        
        // Then
        assertNotNull(client, "Should create client instance");
    }

    @Test
    @DisplayName("Should handle constructor with null context")
    void testConstructorWithNullContext() {
        // When/Then
        assertThrows(Exception.class, () -> {
            new NameServiceClientImpl(null);
        }, "Should throw exception for null context");
    }


    @Test
    @DisplayName("Should handle node status for mock address")
    void testGetNodeStatus() throws UnknownHostException {
        // Given
        InetAddress realInetAddress = InetAddress.getByName("127.0.0.1");
        when(mockNetbiosAddress.toInetAddress()).thenReturn(realInetAddress);
        when(mockNetbiosAddress.unwrap(NbtAddress.class)).thenReturn(null);
        
        // When/Then - This will throw UnknownHostException when trying to get node status
        assertThrows(UnknownHostException.class, () -> {
            nameServiceClient.getNodeStatus(mockNetbiosAddress);
        }, "Should throw UnknownHostException when node status cannot be retrieved");
    }

    @Test
    @DisplayName("Should handle getByName with boolean flag")
    void testGetByNameWithFlag() throws UnknownHostException {
        // When
        Address address = nameServiceClient.getByName("localhost", false);
        
        // Then
        assertNotNull(address, "Should return address for localhost");
    }

    @Test
    @DisplayName("Should validate context configuration access")
    void testContextAccess() {
        // When
        NameServiceClientImpl client = new NameServiceClientImpl(mockContext);
        
        // Then
        assertNotNull(client, "Client should be created successfully");
        verify(mockContext, atLeastOnce()).getConfig();
    }
}