package com.ly.springboot_test.controller;

import net.sf.json.JSONObject;

/**
 * @author tiancj
 * Date 2018/3/27 10:31
 */
public class CommonResp {

    /** 成功 **/
    public static final String SUCCESS_CODE = "000000";
    public static final String SUCCESS_MESSAGE = "Success";

    /** 登录异常 **/
    public static final String LOGIN_EXCEPTION_CODE = "E00000";

    /** 版本过低异常 **/
    public static final String LOW_VERSION_EXCEPTION_CODE = "E10001";

    /** 系统异常 **/
    public static final String GLOBAL_EXCEPTION_CODE = "E99999";

    public static JSONObject wrapJson(Object json){
        JSONObject result = new JSONObject();
        result.put("code",SUCCESS_CODE);
        result.put("message",SUCCESS_MESSAGE);
        result.put("data",json);
        return result;
    }

    public static JSONObject failJson(Object json){
        JSONObject result = new JSONObject();
        result.put("code",LOW_VERSION_EXCEPTION_CODE);
        result.put("message","版本过低，请下载新版本");
        result.put("data",json);
        return result;
    }
}
