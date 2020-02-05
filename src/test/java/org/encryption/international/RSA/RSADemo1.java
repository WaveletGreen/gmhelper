package org.encryption.international.RSA;

import org.encryption.international.util.CoderUtil;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * @author chenerzhu
 * @create 2018-08-04 13:05
 **/
public class RSADemo1 {
    public static String data = "hello world";

    private int keyLength = 1024;

    @Test
    public void rsaTest() throws Exception {

        KeyPair keyPair = genKeyPair(keyLength);

        //获取公钥，并以base64格式打印出来
        PublicKey publicKey = keyPair.getPublic();
        System.out.println("公钥：" + new String(CoderUtil.encodeBase64(publicKey.getEncoded())));

        //获取私钥，并以base64格式打印出来
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("私钥：" + new String(CoderUtil.encodeBase64(privateKey.getEncoded())));

        //公钥加密
        byte[] encryptedBytes = encrypt(data.getBytes(), publicKey);
        String ss = new String(encryptedBytes);
        //避免显示为乱码
        String xss = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("加密后：" + ss);
        System.out.println("加密后xss：" + xss);

        //私钥解密
        byte[] decryptedBytes = decrypt(encryptedBytes, privateKey);
        String sx = new String(decryptedBytes);
        System.out.println("解密后：" + sx);

        Assert.assertEquals(sx, data);
    }

    //生成密钥对
    public static KeyPair genKeyPair(int keyLength) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    //公钥加密
    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");//java默认"RSA"="RSA/ECB/PKCS1Padding"
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

    //私钥解密
    public static byte[] decrypt(byte[] content, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(content);
    }
}