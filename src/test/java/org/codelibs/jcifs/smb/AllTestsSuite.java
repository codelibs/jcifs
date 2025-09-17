package org.codelibs.jcifs.smb;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

/**
 * Test suite that runs all JCIFS tests
 */
@Suite
@SuiteDisplayName("JCIFS Complete Test Suite")
@SelectPackages({ "org.codelibs.jcifs.smb.util", "org.codelibs.jcifs.smb.impl", "org.codelibs.jcifs.smb.config",
        "org.codelibs.jcifs.smb.internal.smb2", "org.codelibs.jcifs.smb.ntlmssp" })
public class AllTestsSuite {
    // Test suite configuration
}