package org.international.encryption.common;

/**
 * Created by chenerzhu on 2018/8/2.
 */
public enum SecureType {
    MD5("MD5"),
    RSA("RSA"),
    RSA_PRIVATE("RSA_PRIVATE"),
    RSA_PUBLIC("RSA_PUBLIC"),
    DES("DES"),
    AES("AES"),
    DES3("DESede"),
    SHA("SHA"),
    HmacSHA256("HmacSHA256");

    private String type;

    SecureType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

}
