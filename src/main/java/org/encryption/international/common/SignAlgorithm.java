package org.encryption.international.common;

/**
 * 签名算法
 *
 * @author chenerzhu
 * @author lilicong
 * @date 2018/8/2
 * @since 0.0.1-SNAPSHOT
 */
public enum SignAlgorithm {
    MD5WithRSA("MD5WithRSA"),
    SHA1WithRSA("SHA1WithRSA"),
    SHA224WithRSA("SHA224WithRSA"),
    SHA256WithRSA("SHA256WithRSA"),
    SHA384WithRSA("SHA384WithRSA"),
    SHA512WithRSA("SHA512WithRSA");
    private String type;

    SignAlgorithm(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
