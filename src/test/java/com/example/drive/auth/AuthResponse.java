package com.example.drive.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String email;
    private String message;
    private String error;

    public static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.OAuth2ClientMutator builder() {
    }
}