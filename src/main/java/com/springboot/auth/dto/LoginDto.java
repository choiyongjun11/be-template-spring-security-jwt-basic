package com.springboot.auth.dto;

import lombok.Getter;

@Getter
//변경안할거이여서 @Setter 없어도 됨.
public class LoginDto {
    private String username;
    private String password;
}
