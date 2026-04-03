package org.example.springsecurity.dto.response;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private String username;
    private String email;
    /**
     * Danh sách roles ngăn cách bởi dấu phẩy, VD: "ROLE_USER, ROLE_ADMIN"
     */
    private String roles;
    private long expiresIn; // ms
}

