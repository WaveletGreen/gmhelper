package org.encryption.gmhelper.util;

import org.encryption.gmhelper.cert.test.SM2PrivateKeyTest;
import org.encryption.gmhelper.cert.test.SM2X509CertMakerTest;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.encryption.gmhelper.cert.test.FileSNAllocatorTest;
import org.encryption.gmhelper.cert.test.SM2CertUtilTest;
import org.encryption.gmhelper.cert.test.SM2PfxMakerTest;

@RunWith(Suite.class)
@SuiteClasses({BCECUtilTest.class, SM2UtilTest.class, SM3UtilTest.class, SM4UtilTest.class,
    SM2KeyExchangeUtilTest.class, SM2PreprocessSignerTest.class,
    // ------------------------------------
    FileSNAllocatorTest.class, SM2CertUtilTest.class, SM2PfxMakerTest.class, SM2PrivateKeyTest.class,
    SM2X509CertMakerTest.class})
public class AllTest {
}
