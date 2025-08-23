/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import jcifs.CIFSException;
import jcifs.Configuration;

/**
 * Configuration implementation reading the classic jcifs settings from properties
 *
 * @author mbechler
 */
public final class PropertyConfiguration extends BaseConfiguration implements Configuration {

    private boolean useMultiChannelExplicitlySet = false;
    private boolean channelBindingPolicyExplicitlySet = false;

    /**
     * Create a configuration backed by properties
     *
     * @param props properties object containing JCIFS configuration settings
     * @throws CIFSException if configuration initialization fails
     */
    public PropertyConfiguration(Properties props) throws CIFSException {
        super(false);
        initFromProperties(props);
        initDefaults(); // Use original initDefaults
    }

    /**
     * Initialize configuration from properties
     */
    private void initFromProperties(Properties props) {
        String value;

        // Standard jCIFS properties
        value = props.getProperty("jcifs.smb.client.username");
        if (value != null) {
            this.defaultUserName = value;
        }

        value = props.getProperty("jcifs.smb.client.password");
        if (value != null) {
            this.defaultPassword = value;
        }

        value = props.getProperty("jcifs.smb.client.domain");
        if (value != null) {
            this.defaultDomain = value;
        }

        value = props.getProperty("jcifs.netbios.hostname");
        if (value != null) {
            this.netbiosHostname = value;
        }

        value = props.getProperty("jcifs.netbios.scope");
        if (value != null) {
            this.netbiosScope = value;
        }

        value = props.getProperty("jcifs.smb.client.connTimeout");
        if (value != null) {
            try {
                this.smbConnectionTimeout = Integer.parseInt(value);
            } catch (NumberFormatException e) {
                // Invalid value ignored
            }
        }

        value = props.getProperty("jcifs.smb.client.soTimeout");
        if (value != null) {
            try {
                this.smbSocketTimeout = Integer.parseInt(value);
            } catch (NumberFormatException e) {
                // Invalid value ignored
            }
        }

        value = props.getProperty("jcifs.encoding");
        if (value != null) {
            this.oemEncoding = value;
        }

        value = props.getProperty("jcifs.smb.client.useUnicode");
        if (value != null) {
            this.useUnicode = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.smb.client.useBatching");
        if (value != null) {
            this.useBatching = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.smb.client.signingPreferred");
        if (value != null) {
            this.signingPreferred = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.smb.client.signingEnforced");
        if (value != null) {
            this.signingEnforced = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.smb.client.encryptionEnforced");
        if (value != null) {
            this.encryptionEnabled = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.smb.client.disablePlainTextPasswords");
        if (value != null) {
            this.disablePlainTextPasswords = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.netbios.wins");
        if (value != null) {
            try {
                this.winsServer = new InetAddress[] { InetAddress.getByName(value) };
            } catch (UnknownHostException e) {
                // Invalid address ignored
            }
        }

        value = props.getProperty("jcifs.netbios.laddr");
        if (value != null) {
            try {
                this.netbiosLocalAddress = InetAddress.getByName(value);
            } catch (UnknownHostException e) {
                // Invalid address ignored
            }
        }

        value = props.getProperty("jcifs.netbios.baddr");
        if (value != null) {
            try {
                this.broadcastAddress = InetAddress.getByName(value);
            } catch (UnknownHostException e) {
                // Invalid address ignored
            }
        }

        value = props.getProperty("jcifs.resolveOrder");
        if (value != null) {
            initResolverOrder(value);
        }

        value = props.getProperty("jcifs.native.os");
        if (value != null) {
            this.nativeOs = value;
        }

        // Also support the alternative property name used in tests
        value = props.getProperty("jcifs.smb.client.nativeOs");
        if (value != null) {
            this.nativeOs = value;
        }

        value = props.getProperty("jcifs.smb.client.nativeLanMan");
        if (value != null) {
            this.nativeLanMan = value;
        }

        // Dialect version properties - these should throw exceptions for invalid values
        String minVersion = props.getProperty("jcifs.smb.client.minVersion");
        String maxVersion = props.getProperty("jcifs.smb.client.maxVersion");
        if (minVersion != null || maxVersion != null) {
            initProtocolVersions(minVersion, maxVersion);
        }

        // Multi-Channel Configuration
        value = props.getProperty("jcifs.smb.client.useMultiChannel");
        if (value != null) {
            this.useMultiChannelExplicitlySet = true;
            // Handle invalid boolean values by falling back to default
            if ("true".equalsIgnoreCase(value)) {
                this.useMultiChannel = true;
            } else if ("false".equalsIgnoreCase(value)) {
                this.useMultiChannel = false;
            }
            // For invalid values, leave useMultiChannelExplicitlySet as false so default applies
            if (!"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value)) {
                this.useMultiChannelExplicitlySet = false;
            }
        }

        value = props.getProperty("jcifs.smb.client.maxChannels");
        if (value != null) {
            try {
                int intValue = Integer.parseInt(value);
                if (intValue > 0) {
                    this.maxChannels = intValue;
                }
            } catch (NumberFormatException e) {
                // Invalid values ignored
            }
        }

        value = props.getProperty("jcifs.smb.client.channelBindingPolicy");
        if (value != null) {
            this.channelBindingPolicy = initChannelBindingPolicy(value);
        }

        value = props.getProperty("jcifs.smb.client.loadBalancingStrategy");
        if (value != null && !value.trim().isEmpty()) {
            this.loadBalancingStrategy = value.trim();
        }

        value = props.getProperty("jcifs.smb.client.channelHealthCheckInterval");
        if (value != null) {
            try {
                int intValue = Integer.parseInt(value);
                if (intValue > 0) {
                    this.channelHealthCheckInterval = intValue;
                }
            } catch (NumberFormatException e) {
                // Invalid values ignored
            }
        }

        // Directory leasing configuration
        value = props.getProperty("jcifs.smb.client.useDirectoryLeasing");
        if (value != null) {
            this.useDirectoryLeasing = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.smb.client.directoryCacheScope");
        if (value != null) {
            this.directoryCacheScope = value;
        }

        value = props.getProperty("jcifs.smb.client.directoryCacheTimeout");
        if (value != null) {
            try {
                this.directoryCacheTimeout = Long.parseLong(value);
            } catch (NumberFormatException e) {
                // Invalid value ignored
            }
        }

        value = props.getProperty("jcifs.smb.client.directoryNotificationsEnabled");
        if (value != null) {
            this.directoryNotificationsEnabled = Boolean.parseBoolean(value);
        }

        value = props.getProperty("jcifs.smb.client.maxDirectoryCacheEntries");
        if (value != null) {
            try {
                this.maxDirectoryCacheEntries = Integer.parseInt(value);
            } catch (NumberFormatException e) {
                // Invalid value ignored
            }
        }
    }

    @Override
    protected void initDefaults() throws CIFSException {
        // Set PropertyConfiguration-specific defaults before calling super.initDefaults()
        if (!this.useMultiChannelExplicitlySet) {
            this.useMultiChannel = true; // PropertyConfiguration defaults to enabled
        }

        // Call parent initialization for all other defaults
        super.initDefaults();
    }
}
