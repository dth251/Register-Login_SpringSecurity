package org.example.springsecurity.controller;


import lombok.RequiredArgsConstructor;
import org.example.springsecurity.dto.response.ApiResponse;
import org.example.springsecurity.entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class UserController {

    /**
     * GET /api/user/profile
     * Truy cập được bởi ROLE_USER và ROLE_ADMIN
     */
    @GetMapping("/api/user/profile")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getProfile(
            @AuthenticationPrincipal User user) {

        // Lấy danh sách tên role từ Set<Role>
        var roleNames = user.getRoles().stream()
                .map(r -> r.getName().name())
                .collect(Collectors.toSet());

        Map<String, Object> profile = Map.of(
                "id",        user.getId(),
                "username",  user.getUsername(),
                "email",     user.getEmail(),
                "roles",     roleNames,
                "createdAt", user.getCreatedAt() != null ? user.getCreatedAt().toString() : ""
        );
        return ResponseEntity.ok(ApiResponse.success("Lấy thông tin thành công", profile));
    }

    /**
     * GET /api/user/dashboard
     * Endpoint dành cho USER (cả ADMIN cũng có thể truy cập)
     */
    @GetMapping("/api/user/dashboard")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<ApiResponse<String>> userDashboard(
            @AuthenticationPrincipal User user) {
        String msg = "Xin chào " + user.getUsername()
                + "! Roles của bạn: " + user.getRoleNames();
        return ResponseEntity.ok(ApiResponse.success(msg));
    }

    /**
     * GET /api/admin/dashboard
     * CHỈ ADMIN mới truy cập được
     */
    @GetMapping("/api/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> adminDashboard(
            @AuthenticationPrincipal User user) {
        String msg = "Xin chào Admin " + user.getUsername()
                + "! Roles: " + user.getRoleNames();
        return ResponseEntity.ok(ApiResponse.success(msg));
    }

    /**
     * GET /api/admin/users
     * Lấy danh sách users — chỉ ADMIN
     */
    @GetMapping("/api/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> getAllUsers() {
        return ResponseEntity.ok(
                ApiResponse.success("Chỉ ADMIN mới thấy được endpoint này"));
    }
}
