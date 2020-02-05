package org.international.encryption.util;

import org.international.encryption.common.EncType;
import org.international.encryption.common.SecureType;
import org.international.encryption.secure.BaseSecure;
import org.international.encryption.secure.SecureFactory;

import java.io.IOException;

/**
 * @author chenerzhu
 * @create 2018-08-06 10:55
 **/
public class SecureUtils {
    /**
     * 使用指定方法，指定加密key,指定编码(结果内容编码，key编码) 加密
     *
     * @param value 需要加密的数据
     * @param key   加密公钥，仅针对RSA
     * @param type  加密类型
     * @return 加密后的数据
     */
    public static String encrypt(String value, String key, SecureType type, EncType contentEncType, EncType keyEncType) {
        byte[] data = value.getBytes();
        BaseSecure secure = SecureFactory.getSecure(type, key);
        secure.setKeyEncType(keyEncType);
        secure.setContentEncType(contentEncType);
        return secure.getEncrypt(data, contentEncType);
    }

    /**
     * 使用指定方法，指定解密key,指定编码(结果内容编码，key编码) 解密
     *
     * @param value 需要解密的数据
     * @param key   解密私钥，仅针对RSA
     * @param type  解密类型
     * @return 解密后的数据
     */
    public static String decrypt(String value, String key, SecureType type, EncType contentEncType, EncType keyEncType) {
        byte[] data = value.getBytes();
        BaseSecure secure = SecureFactory.getSecure(type, key);
        secure.setKeyEncType(keyEncType);
        secure.setContentEncType(contentEncType);
        return secure.getDecrypt(data, contentEncType);
    }

    /**
     * md5加密
     *
     * @param content 需要加密的数据
     * @return 加密后的数据
     */
    public static String getMD5(String content) {
        return encrypt(content, null, SecureType.MD5, EncType.HEX, null);
    }

    /**
     * sha加密
     *
     * @param content 需要加密的数据
     * @return 加密后的数据
     */
    public static String getSHA(String content) {
        return encrypt(content, null, SecureType.SHA, EncType.HEX, null);
    }

    /**
     * md5加密
     *
     * @param content 需要加密的数据
     * @return 加密后的数据
     */
    public static String getMD5(String content, EncType contentEncType) {
        return encrypt(content, null, SecureType.MD5, contentEncType, null);
    }

    /**
     * sha加密
     *
     * @param content 需要加密的数据
     * @return 加密后的数据
     */
    public static String getSHA(String content, EncType contentEncType) {
        return encrypt(content, null, SecureType.SHA, contentEncType, null);
    }

    /**
     * RSA默认编码加密  私钥加密
     *
     * @param value      需要加密的数据
     * @param privateKey 加密的私钥
     * @return 加密后的数据
     */
    public static String encryptRSAPrivate(String value, String privateKey) {
        return encrypt(value, privateKey, SecureType.RSA_PRIVATE, EncType.BASE64, EncType.BASE64);
    }

    /**
     * RSA默认编码加密 公钥加密
     *
     * @param value     需要加密的数据
     * @param publicKey 加密的公钥
     * @return 加密后的数据
     */
    public static String encryptRSAPublic(String value, String publicKey) {
        return encrypt(value, publicKey, SecureType.RSA_PUBLIC, EncType.BASE64, EncType.BASE64);
    }

    /**
     * RSA默认编码解密 私钥解密
     *
     * @param value      需要解密的数据
     * @param privateKey 解密的私钥
     * @return 解密后的数据
     */
    public static String decryptRSAPrivate(String value, String privateKey) {
        return decrypt(value, privateKey, SecureType.RSA_PRIVATE, EncType.BASE64, EncType.BASE64);
    }

    /**
     * RSA默认编码解密 公钥解密
     *
     * @param value     需要解密的数据
     * @param publicKey 解密的公钥
     * @return 解密后的数据
     */
    public static String decryptRSAPublic(String value, String publicKey) {
        return decrypt(value, publicKey, SecureType.RSA_PUBLIC, EncType.BASE64, EncType.BASE64);
    }

    /**
     * RSA指定编码加密 私钥加密
     *
     * @param value          需要加密的数据
     * @param privateKey     解密的私钥
     * @param contentEncType 加密的内容编码
     * @param keyEncType     私钥编码
     * @return 解密后的数据
     */
    public static String encryptRSAPrivate(String value, String privateKey, EncType contentEncType, EncType keyEncType) {
        return encrypt(value, privateKey, SecureType.RSA_PRIVATE, contentEncType, keyEncType);
    }

    /**
     * RSA指定编码加密 公钥加密
     *
     * @param value          需要解密的数据
     * @param publicKey      解密的公钥
     * @param contentEncType 加密的内容编码
     * @param keyEncType     公钥编码
     * @return 解密后的数据
     */
    public static String encryptRSAPublic(String value, String publicKey, EncType contentEncType, EncType keyEncType) {
        return encrypt(value, publicKey, SecureType.RSA_PUBLIC, contentEncType, keyEncType);
    }

    /**
     * RSA指定编码解密 私钥解密
     *
     * @param value          需要解密的数据
     * @param privateKey     解密的私钥
     * @param contentEncType 加密的内容编码
     * @param keyEncType     私钥编码
     * @return 解密后的数据
     */
    public static String decryptRSAPrivate(String value, String privateKey, EncType contentEncType, EncType keyEncType) {
        return decrypt(value, privateKey, SecureType.RSA_PRIVATE, contentEncType, keyEncType);
    }

    /**
     * RSA指定编码解密 公钥解密
     *
     * @param value          需要解密的数据
     * @param publicKey      解密的公钥
     * @param contentEncType 加密的内容编码
     * @param keyEncType     公钥编码
     * @return 解密后的数据
     */
    public static String decryptRSAPublic(String value, String publicKey, EncType contentEncType, EncType keyEncType) {
        return decrypt(value, publicKey, SecureType.RSA_PUBLIC, contentEncType, keyEncType);
    }

    /**
     * DES默认编码加密
     *
     * @param value 需要加密的数据
     * @param key   加密的key
     * @return 加密后的数据
     */
    public static String encryptDES(String value, String key) {
        return encrypt(value, key, SecureType.DES, EncType.BASE64, EncType.DEFAULT);
    }

    /**
     * DES默认编码解密
     *
     * @param value 需要解密的数据
     * @param key   解密的key
     * @return 解密后的数据
     */
    public static String decryptDES(String value, String key) {
        return decrypt(value, key, SecureType.DES, EncType.BASE64, EncType.DEFAULT);
    }

    /**
     * DES指定编码加密
     *
     * @param value          需要加密的数据
     * @param key            加密的key
     * @param contentEncType 加密的内容编码
     * @param keyEncType     key编码
     * @return 加密后的数据
     */
    public static String encryptDES(String value, String key, EncType contentEncType, EncType keyEncType) {
        return encrypt(value, key, SecureType.DES, contentEncType, keyEncType);
    }

    /**
     * DES指定编码解密
     *
     * @param value          需要解密的数据
     * @param key            解密的key
     * @param contentEncType 加密的内容编码
     * @param keyEncType     key编码
     * @return 解密后的数据
     */
    public static String decryptDES(String value, String key, EncType contentEncType, EncType keyEncType) {
        return decrypt(value, key, SecureType.DES, contentEncType, keyEncType);
    }

    /**
     * 3DES默认编码加密
     *
     * @param value 需要加密的数据
     * @param key   加密的key
     * @return 加密后的数据
     */
    public static String encrypt3DES(String value, String key) {
        return encrypt(value, key, SecureType.DES3, EncType.BASE64, EncType.DEFAULT);
    }

    /**
     * 3DES默认编码解密
     *
     * @param value
     * @param key
     * @return
     */
    public static String decrypt3DES(String value, String key) {
        return decrypt(value, key, SecureType.DES3, EncType.BASE64, EncType.DEFAULT);
    }

    /**
     * 3DES指定编码加密
     *
     * @param value
     * @param key
     * @return
     */
    public static String encrypt3DES(String value, String key, EncType contentEncType, EncType keyEncType) {
        return encrypt(value, key, SecureType.DES3, contentEncType, keyEncType);
    }

    /**
     * 3DES指定编码解密
     *
     * @param value
     * @param key
     * @return
     */
    public static String decrypt3DES(String value, String key, EncType contentEncType, EncType keyEncType) {
        return decrypt(value, key, SecureType.DES3, contentEncType, keyEncType);
    }

    /**
     * AES默认编码加密
     *
     * @param value
     * @param key
     * @return
     */
    public static String encryptAES(String value, String key) {
        return encrypt(value, key, SecureType.AES, EncType.BASE64, EncType.DEFAULT);
    }

    /**
     * AES默认编码解密
     *
     * @param value
     * @param key
     * @return
     */
    public static String decryptAES(String value, String key) {
        return decrypt(value, key, SecureType.AES, EncType.BASE64, EncType.DEFAULT);
    }

    /**
     * AES指定编码加密
     *
     * @param value
     * @param key
     * @return
     */
    public static String encryptAES(String value, String key, EncType contentEncType, EncType keyEncType) {
        return encrypt(value, key, SecureType.AES, contentEncType, keyEncType);
    }

    /**
     * AES指定编码解密
     *
     * @param value
     * @param key
     * @return
     */
    public static String decryptAES(String value, String key, EncType contentEncType, EncType keyEncType) {
        return decrypt(value, key, SecureType.AES, contentEncType, keyEncType);
    }

    /**
     * 2进制数字转换为16进制字符串
     *
     * @param data
     * @return
     */
    public static String encodeByteToHex(byte[] data) {
        return CoderUtil.encodeByteToHex(data);
    }

    /**
     * 16进制字符串转换为2进制数字
     *
     * @param hex
     * @return
     */
    public static byte[] decodeHex2Byte(String hex) {
        return CoderUtil.decodeHex2Byte(hex);
    }

    /**
     * 2进制数字转换Base64
     *
     * @param data
     * @return
     */
    public static String encodeByte2Base64(byte[] data) {
        return CoderUtil.encodeBase64(data);
    }

    /**
     * Base64转二进制
     *
     * @param data
     * @return
     * @throws IOException
     */
    public static byte[] decodeBase642Byte(String data) throws IOException {
        return CoderUtil.decodeBase64(data);
    }
}