package org.encryption.gmhelper.cert.test;

import org.encryption.gmhelper.cert.FileSNAllocator;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class FileSNAllocatorTest {

    @Test
    public void TestIncrementAndGetSN() throws Exception {
        FileSNAllocator allocator = new FileSNAllocator();
        BigInteger sn = allocator.incrementAndGet();
        System.out.println("sn:" + sn.toString(10));
        BigInteger sn2 = allocator.incrementAndGet();
        System.out.println("sn2:" + sn2.toString(10));
        if (sn2.compareTo(sn.add(BigInteger.ONE)) != 0) {
            Assert.fail("sn2 != (sn + 1)");
        }
    }
}
