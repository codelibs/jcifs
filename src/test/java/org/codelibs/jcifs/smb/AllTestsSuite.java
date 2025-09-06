package org.codelibs.jcifs.smb;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

/**
 * Test suite that runs all JCIFS tests
 */
@Suite
@SuiteDisplayName("JCIFS Complete Test Suite")
@SelectPackages({ "org.codelibs.jcifs" })
public class AllTestsSuite {
    // Test suite configuration
}