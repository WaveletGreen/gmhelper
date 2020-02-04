package org.zz.gmhelper;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * SM3密码摘要算法
 * <p>
 * SM3密码摘要算法是中国国家密码管理局2010年公布的中国商用密码杂凑算法标准。
 * SM3算法适用于商用密码应用中的数字签名和验证，是在SHA-256基础上改进实现的一种算法。
 * SM3算法采用Merkle-Damgard结构，消息分组长度为512位，摘要值长度为256位。
 * SM3算法的压缩函数与SHA-256的压缩函数具有相似的结构,但是SM3算法的设计更加复杂,比如压缩函数的每一轮都使用2个消息字。
 * 现今为止，SM3算法的安全性相对较高
 */
public class SM3Util extends GMBaseUtil {

    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    public static boolean verify(byte[] srcData, byte[] sm3Hash) {
        byte[] newHash = hash(srcData);
        if (Arrays.equals(newHash, sm3Hash)) {
            return true;
        } else {
            return false;
        }
    }

    public static byte[] hmac(byte[] key, byte[] srcData) {
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(srcData, 0, srcData.length);
        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    }
}
