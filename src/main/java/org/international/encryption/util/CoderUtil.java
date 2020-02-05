package org.international.encryption.util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public final class CoderUtil {

    private static BASE64Encoder base64Encoder;
    private static BASE64Decoder base64Decoder;

    static {
        base64Encoder = new BASE64Encoder();
        base64Decoder = new BASE64Decoder();
    }

    /**
     * base64 编码
     *
     * @param data
     * @return
     */
    public static String encodeBase64(byte[] data) {
        return base64Encoder.encodeBuffer(data);
    }

    /**
     * base64 解码
     *
     * @param data
     * @return
     * @throws IOException
     */
    public static byte[] decodeBase64(String data) throws IOException {
        return base64Decoder.decodeBuffer(data);
    }

    /**
     * 2进制数字转换为16进制字符串
     *
     * @param data
     * @return
     */
    public static String encodeByteToHex(byte[] data) {
        if (data == null || data.length < 1) {
            return null;
        }

        StringBuffer hex = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int h = data[i] & 0XFF;
            if (h < 16) {
                hex.append("0");
            }
            hex.append(Integer.toHexString(h));
        }

        return hex.toString();
    }

    /**
     * 16进制字符串转换为2进制数字
     *
     * @param hex
     * @return
     */
    public static byte[] decodeHex2Byte(String hex) {
        if (hex == null || "".equals(hex)) {
            return null;
        }

        int length = hex.length() >> 1;
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) {
            int n = i << 1;
            int height = Integer.valueOf(hex.substring(n, n + 1), 16);
            int low = Integer.valueOf(hex.substring(n + 1, n + 2), 16);
            data[i] = (byte) (height * 16 + low);
        }

        return data;
    }

    /**
     * 分段加密
     * @param cipher
     * @param data
     * @param out
     * @param maxBlock
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static void doSection(Cipher cipher, byte[] data, ByteArrayOutputStream out, int maxBlock) throws BadPaddingException, IllegalBlockSizeException {
        int inputLen = data.length;
        int offSet = 0;
        int i = 0;
        byte[] cache;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > maxBlock) {
                cache = cipher.doFinal(data, offSet, maxBlock);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * maxBlock;
        }
    }

}
