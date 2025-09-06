/*
 * © 2025 CodeLibs, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.internal.smb2.rdma;

import java.util.Arrays;
import java.util.List;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.rdma.disni.DisniRdmaProvider;
import org.codelibs.jcifs.smb.internal.smb2.rdma.tcp.TcpRdmaProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating RDMA provider instances.
 *
 * This factory attempts to select the best available RDMA provider
 * based on system capabilities and configuration preferences.
 */
public class RdmaProviderFactory {

    /**
     * Private constructor to prevent instantiation
     */
    private RdmaProviderFactory() {
        // Factory class - not instantiable
    }

    private static final Logger log = LoggerFactory.getLogger(RdmaProviderFactory.class);

    /**
     * Create RDMA provider based on preference string
     *
     * @param preference provider preference ("auto", "disni", "tcp", etc.)
     * @return best available RDMA provider, or null if none available
     */
    public static RdmaProvider createProvider(String preference) {
        if ("auto".equalsIgnoreCase(preference)) {
            return selectBestProvider();
        }

        switch (preference.toLowerCase()) {
        case "disni":
            RdmaProvider disniProvider = new DisniRdmaProvider();
            if (disniProvider.isAvailable()) {
                return disniProvider;
            }
            log.warn("DiSNI RDMA provider requested but not available");
            break;

        case "tcp":
            return new TcpRdmaProvider();

        default:
            log.warn("Unknown RDMA provider preference: {}", preference);
            break;
        }

        return null;
    }

    /**
     * Get RDMA provider based on configuration
     *
     * @param config the configuration to read provider preference from
     * @return RDMA provider instance, or null if none available
     */
    public static RdmaProvider getProvider(Configuration config) {
        String preference = config.getRdmaProvider();
        return createProvider(preference != null ? preference : "auto");
    }

    /**
     * Select the best available RDMA provider
     *
     * @return best RDMA provider, or null if none available
     */
    public static RdmaProvider selectBestProvider() {
        // Try providers in order of preference
        List<RdmaProvider> providers = Arrays.asList(new DisniRdmaProvider(), // InfiniBand/RoCE - highest performance
                new TcpRdmaProvider() // TCP fallback - always available
        );

        for (RdmaProvider provider : providers) {
            if (provider.isAvailable()) {
                log.info("Selected RDMA provider: {}", provider.getProviderName());
                return provider;
            }
        }

        log.warn("No RDMA providers available");
        return null;
    }

    /**
     * Check if any RDMA provider is available
     *
     * @return true if at least one RDMA provider is available
     */
    public static boolean isRdmaAvailable() {
        return selectBestProvider() != null;
    }

    /**
     * Get list of all available RDMA providers
     *
     * @return list of available providers
     */
    public static List<String> getAvailableProviders() {
        List<RdmaProvider> allProviders = Arrays.asList(new DisniRdmaProvider(), new TcpRdmaProvider());

        return allProviders.stream()
                .filter(RdmaProvider::isAvailable)
                .map(RdmaProvider::getProviderName)
                .collect(java.util.stream.Collectors.toList());
    }
}
