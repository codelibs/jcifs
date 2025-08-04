package jcifs;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

/**
 * Test suite that runs all JCIFS tests
 */
@Suite
@SuiteDisplayName("JCIFS Complete Test Suite")
@SelectPackages({ "jcifs.util", "jcifs.smb", "jcifs.config", "jcifs.internal.smb2", "jcifs.ntlmssp" })
public class AllTestsSuite {
    // Test suite configuration
}