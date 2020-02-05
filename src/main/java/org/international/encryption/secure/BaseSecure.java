package org.international.encryption.secure;


import org.international.encryption.common.EncType;
import org.international.encryption.util.CoderUtil;

import java.util.regex.Pattern;

/**
 * 编解码基类
 */
public abstract class BaseSecure {

    public static final String DEFAULT_CHARSET = "UTF-8";

    protected String secretKey;
    private EncType keyEncType;//密钥编码
    private EncType contentEncType;//内容编码

    Pattern pattern = Pattern.compile("\\s*|\t|\r|\n"); //去掉空格、换行

    public BaseSecure() {
    }

    /**
     * 加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public abstract byte[] encrypt(byte[] data) throws Exception;

    /**
     * 解密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public abstract byte[] decrypt(byte[] data) throws Exception;

    public String encode(byte[] data, EncType encType) {
        String d;
        if(encType==null){
            return new String(data);
        }
        switch (encType) {
            case HEX:
                d= CoderUtil.encodeByteToHex(data);
                break;
            case BASE64:
                d= CoderUtil.encodeBase64(data);
                break;
            case DEFAULT:
                d=new String(data);
                break;
            default:
                d=new String(data);
        }
        return pattern.matcher(d).replaceAll("");
    }

    public byte[] decode(String data, EncType encType) throws Exception {
        byte[] d;
        if(encType==null){
            return data.getBytes();
        }
        switch (encType) {
            case HEX:
                d= CoderUtil.decodeHex2Byte(new String(data));
                break;
            case BASE64:
                d= CoderUtil.decodeBase64(data);
                break;
            case DEFAULT:
                d=data.getBytes();
                break;
            default:
                d=data.getBytes();
        }
        return d;
    }
    public String getEncrypt(byte[] data, EncType encType){
        String str;
        switch (encType) {
            case HEX:
                str= getEncrypt2Hex(data);
                break;
            case BASE64:
                str= getEncrypt2Base64(data);
                break;
            case DEFAULT:
                str=new String(data);
                break;
            default:
                str=new String(data);
        }

        return pattern.matcher(str).replaceAll("");
    }

    public String getDecrypt(byte[] data, EncType encType){
        String str;
        switch (encType) {
            case HEX:
                str= getDecrypt2Hex(data);
                break;
            case BASE64:
                str= getDecrypt2Base64(data);
                break;
            case DEFAULT:
                str=new String(data);
                break;
            default:
                str=new String(data);
        }
        return pattern.matcher(str).replaceAll("");
    }

    /**
     * 十六进制字符串
     *
     * @param data
     * @return
     * @throws Exception
     */
    public String getEncrypt2Hex(byte[] data) {
        byte[] digestData = new byte[0];
        try {
            digestData = encrypt(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pattern.matcher(CoderUtil.encodeByteToHex(digestData)).replaceAll("");

    }

    /**
     * base64
     *
     * @param data
     * @return
     * @throws Exception
     */
    public String getEncrypt2Base64(byte[] data) {
        byte[] digestData = new byte[0];
        try {
            digestData = encrypt(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pattern.matcher(new String(CoderUtil.encodeBase64(digestData))).replaceAll("");
    }

    /**
     * 十六进制字符串
     *
     * @param data
     * @return
     * @throws Exception
     */
    public String getDecrypt2Hex(byte[] data) {
        byte[] digestData = new byte[0];
        try {
            digestData = decrypt(CoderUtil.decodeHex2Byte(new String(data)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pattern.matcher(new String(digestData)).replaceAll("");
    }

    /**
     * base64
     *
     * @param data
     * @return
     * @throws Exception
     */
    public String getDecrypt2Base64(byte[] data) {
        byte[] digestData = new byte[0];
        try {
            digestData = decrypt(CoderUtil.decodeBase64(new String(data)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pattern.matcher(new String(digestData)).replaceAll("");
    }

    public String getSecretKey() {
        return secretKey;
    }

    public EncType  getKeyEncType() {
        return keyEncType;
    }

    public void setKeyEncType(EncType keyEncType) {
        this.keyEncType = keyEncType;
    }

    public EncType getContentEncType() {
        return contentEncType;
    }

    public void setContentEncType(EncType contentEncType) {
        this.contentEncType = contentEncType;
    }
}
