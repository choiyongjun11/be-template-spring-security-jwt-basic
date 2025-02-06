package com.springboot.auth.handler;

import com.google.gson.Gson;
import com.springboot.auth.utils.ErrorResponder;
import com.springboot.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MemberAuthenticationEntryPoint implements AuthenticationEntryPoint { //토큰이 잘못 됐을 때

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Exception exception = (Exception) request.getAttribute("exception");
//
//        Gson gson = new Gson();
//        ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED);
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        response.setStatus(HttpStatus.UNAUTHORIZED.value());
//        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));

        ErrorResponder.sendErrorResponse(response, HttpStatus.UNAUTHORIZED);
    }
}
