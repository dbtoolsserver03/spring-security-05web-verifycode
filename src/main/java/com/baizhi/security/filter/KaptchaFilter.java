package com.baizhi.security.filter;


import java.io.IOException;

import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.baizhi.security.exception.KaptchaNotMatchException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//自定义验证码的 filter
public class KaptchaFilter extends OncePerRequestFilter {


	private static final String FORM_KAPTCHA_KEY = "kaptcha";

    private String kaptchaParameter = FORM_KAPTCHA_KEY;

    public String getKaptchaParameter() {
        return kaptchaParameter;
    }

    public void setKaptchaParameter(String kaptchaParameter) {
        this.kaptchaParameter = kaptchaParameter;
    }

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		
		// 必须是登录的post请求才能进行验证，其他的直接放行
        if(request.getRequestURI().endsWith("doLogin")) {
        	
            //1.从请求中获取验证码
            String verifyCode = request.getParameter(getKaptchaParameter());
            //2.与 session 中验证码进行比较
            String sessionVerifyCode = (String) request.getSession().getAttribute("kaptcha");
            if (!ObjectUtils.isEmpty(verifyCode) && !ObjectUtils.isEmpty(sessionVerifyCode) &&
                    verifyCode.equalsIgnoreCase(sessionVerifyCode)) {

            } else {
            	 throw new KaptchaNotMatchException("验证码不匹配!");
            }
           
        } 
        		
     	//通过校验，就放行
        filterChain.doFilter(request,response);
        		
//        if (!request.getMethod().equals("POST")) {
//            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
//        }

        
	
		
	}
}
