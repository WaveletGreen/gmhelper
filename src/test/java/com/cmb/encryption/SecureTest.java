package com.cmb.encryption;


import com.common.*;
import com.secure.*;
import com.util.CoderUtil;
import org.junit.Test;

import java.io.IOException;

/**
 * @author chenerzhu
 * @create 2018-08-06 10:31
 **/
public class SecureTest {
    private static final String INPUT_STR = "test secure test secure";
    public static String publicKeyString =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+DMP46lVNr3qNjLbMOOcO8mL9SiM7ZNVf+bYm" +
                    "pw+VVmhLiWSRP9uGqyp1z6/kKmcmAl876nuLUNOLwo6uk4PPuCxOCtlv3uq3XsuqfF0j/jdSNfIS" +
                    "h5pKuL3dSmSWHJ+luh8JQmWRIaV+uVcQx7/XT0LKd7vTYoCWpR1vCKwJlwIDAQAB";
    public static String privateKeyString =
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL4Mw/jqVU2veo2Mtsw45w7yYv1K" +
                    "Iztk1V/5tianD5VWaEuJZJE/24arKnXPr+QqZyYCXzvqe4tQ04vCjq6Tg8+4LE4K2W/e6rdey6p8" +
                    "XSP+N1I18hKHmkq4vd1KZJYcn6W6HwlCZZEhpX65VxDHv9dPQsp3u9NigJalHW8IrAmXAgMBAAEC" +
                    "gYEAkS7NUs0o51TDaXjyeCaMFLYD+vz01z2bZ1sq1HJRDENbH0FRK0i+Gi2OHTvQYZwm+jlbqTji" +
                    "sjXHtX+mYiTczrOmnxvjaUt6ZT40w20vKsnDha+cY2RtLPcyB6+HoFUA4EsWS+vaCBqlX2iJBTH4" +
                    "Kte/azlKUYZPQcqGFbvLB6ECQQDooFR/EJzsV2SNNikC6H4APyghkgg63kE98caEQXiywpSJQfTB" +
                    "DfqtBwmmSAE5F1VQQIKyHs0yx1qoqDbZT7zxAkEA0SVGOnbTSmypslN3+/x9aGG8yo2lbfk4rdvz" +
                    "gRr1tdJC2MnG80STlV9nf7xfxozpeGn1droW43bSUzDzJSfPBwJAeiZ+V/50OBInxZKz9Ef6qcyA" +
                    "GSiiU68TGSDUuevbIhrUfkJ478qUX7j7UyoqIj1jWfGV70wHOeu+aiNyMagSMQJASYoVu5D0koLK" +
                    "2I1I7y3E2uMjAwXzWUv8hgWFBax5IUmhf6DTd85xJmC5f8y40JPTtCdtzCV6ztiE9AOOO05YGQJB" +
                    "AIPU/p74uGuP1okZeLhSICt+evdTcQLKMhZtlx8nUtPbR56ll2kBt9b39t8aJNnoPEgt+ubvNPFQ" +
                    "PC3T/4d7W9M=";

    @Test
    public void md5Test() {
        System.out.println("======= MD5 ========");
        byte[] data = INPUT_STR.getBytes();
        MD5Secure codec = (MD5Secure) SecureFactory.getSecure(SecureType.MD5, null);
        System.out.println("md5 hex:" + codec.getEncrypt2Hex(data));
        System.out.println("md5 base64:" + codec.getEncrypt2Base64(data));
    }

    @Test
    public void shaTest() {
        System.out.println("======== SHA ========");
        byte[] data = INPUT_STR.getBytes();
        SHASecure codec = (SHASecure) SecureFactory.getSecure(SecureType.SHA, null);
        System.out.println("sha hex:" + codec.getEncrypt2Hex(data));
        System.out.println("sha base64:" + codec.getEncrypt2Base64(data));
    }

    @Test
    public void desTest() throws Exception {
        System.out.println("========= DES ========");
        byte[] data = INPUT_STR.getBytes();
        DESSecure codecA = (DESSecure) SecureFactory.getSecure(SecureType.DES, "AAAAAAAAAAAAAAAA");
        String secretKey = codecA.getSecretKey();
        System.out.println("key DES:" + secretKey);
        byte[] encryptData = codecA.encrypt(data);
        System.out.println("encryptData hex DES:" + codecA.getEncrypt2Hex(data));
        System.out.println("encryptData base64 DES:" + codecA.getEncrypt2Base64(data));


        DESSecure codecB = (DESSecure) SecureFactory.getSecure(SecureType.DES, secretKey);
        System.out.println("decryptData hex DES:" + codecB.getDecrypt2Hex(codecA.getEncrypt2Hex(data).getBytes()));
        System.out.println("decryptData base64 DES:" + codecB.getDecrypt2Base64("LN4koqnzOrj70kYdmXeO34egve7MHE/T".getBytes()));
    }

    @Test
    public void des3Test() throws Exception {
        System.out.println("========= 3DES ========");
        byte[] data = INPUT_STR.getBytes();
        DES3Secure codecA = (DES3Secure) SecureFactory.getSecure(SecureType.DES3, "AAAAAAAAAAAAAAAA");
        String secretKey = codecA.getSecretKey();
        System.out.println("key 3DES:" + secretKey);
        byte[] encryptData = codecA.encrypt(data);
        System.out.println("encryptData hex 3DES:" + codecA.getEncrypt2Hex(data));
        System.out.println("encryptData base64 3DES:" + codecA.getEncrypt2Base64(data));


        DES3Secure codecB = (DES3Secure) SecureFactory.getSecure(SecureType.DES3, secretKey);
        System.out.println("decryptData hex 3DES:" + codecB.getDecrypt2Hex(codecA.getEncrypt2Hex(data).getBytes()));
        System.out.println("decryptData base64 3DES:" + codecB.getDecrypt2Base64(codecA.getEncrypt2Base64(data).getBytes()));
    }

    @Test
    public void aesTest() throws Exception {
        System.out.println("=========== AES ===========");
        byte[] data = INPUT_STR.getBytes();
        AESSecure codecA = (AESSecure) SecureFactory.getSecure(SecureType.AES, "AAAAAAAAAAAAAAAA");
        String secretKey = codecA.getSecretKey();

        System.out.println("key AES:" + secretKey);
        byte[] encryptData = codecA.encrypt(data);
        System.out.println("encryptData hex AES:" + codecA.getEncrypt2Hex(data));
        System.out.println("encryptData base64 AES:" + codecA.getEncrypt2Base64(data));


        AESSecure codecB = (AESSecure) SecureFactory.getSecure(SecureType.AES, secretKey);
        System.out.println("decryptData hex AES:" + codecB.getDecrypt2Hex(codecA.getEncrypt2Hex(data).getBytes()));
        System.out.println("decryptData base64 AES:" + codecB.getDecrypt2Base64("T5leeW3QFl82ZxIo/j1KVnNt3wAf6FFETFudjl+LnJg=".getBytes()));

    }

    @Test
    //使用hex或base64编码前，需要先确定公钥和私钥的编码  可以通过enctype.HEX或enctype.BASE64设置
    public void rsaTest() {
        System.out.println("=========== RSA ============");
        byte[] data = INPUT_STR.getBytes();


        RSAPublicSecure codecB = (RSAPublicSecure) SecureFactory.getSecure(SecureType.RSA_PUBLIC, publicKeyString);
        //必须添加Enc类型，否则会报invalid key format
        codecB.setKeyEncType(EncType.BASE64);
        System.out.println("publicKey:" + codecB.getPublicKey());
        System.out.println("encrypt hex RSA:" + codecB.getEncrypt2Hex(data));
        System.out.println("encrypt base64 RSA:" + codecB.getEncrypt2Base64(data));

        RSAPrivateSecure codecA = (RSAPrivateSecure) SecureFactory.getSecure(SecureType.RSA_PRIVATE, privateKeyString);
        //codecA.encType = EncType.BASE64;
        //必须添加Enc类型，否则会报invalid key format
        codecA.setKeyEncType(EncType.BASE64);
        String privateKey = codecA.getPrivateKey();
        System.out.println("privateKey:" + privateKey);
        System.out.println("decrypt hex RSA:" + codecA.getDecrypt2Hex(codecB.getEncrypt2Hex(data).getBytes()));
        System.out.println("decrypt base64 RSA:" + codecA.getDecrypt2Base64(codecB.getEncrypt2Base64(data).getBytes()));
    }

    @Test
    public void testBase64() throws IOException {
        //dGVzdCBzZWN1cmU=
        System.out.println(CoderUtil.encodeBase64(INPUT_STR.getBytes()));
        System.out.println(new String(CoderUtil.encodeBase64(INPUT_STR.getBytes())));

        System.out.println(new String(CoderUtil.decodeBase64("dGVzdCBzZWN1cmU=")));
        System.out.println(new String(CoderUtil.decodeBase64("dGVzdCBzZWN1cmU=")));
    }

}
