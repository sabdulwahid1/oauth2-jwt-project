package com.example.oauth20;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class Controller {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    
    @Value("${app.cookie.secure}")
    private boolean secureCookie;
    
    public Controller(UserService userService, JwtUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    // 🔐 LOGIN SUCCESS → SET COOKIES
    @GetMapping("/loginSuccess")
    public void loginSuccess(OAuth2AuthenticationToken authentication,
                             HttpServletResponse response) throws Exception {

    	System.out.println("AUTH OBJECT: " + authentication);
    	
        if (authentication == null) {
            response.sendRedirect("http://localhost:3000");
            return;
        }

        Map<String, Object> attributes = authentication.getPrincipal().getAttributes();

        User user = userService.saveOrUpdateUser(attributes);

        String accessToken = jwtUtil.generateToken(user.getEmail(), user.getRole());
        String refreshToken = refreshTokenService.create(user.getEmail()).getToken();

        ResponseCookie accessCookie = ResponseCookie.from("accessToken", accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(60 * 15)
                .sameSite("None")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(7 * 24 * 60 * 60)
                .sameSite("None")
                .build();

        response.addHeader("Set-Cookie", accessCookie.toString());
        response.addHeader("Set-Cookie", refreshCookie.toString());

        response.sendRedirect("http://localhost:3000/dashboard");
    }

    // 🔁 REFRESH ACCESS TOKEN FROM COOKIE
    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {

        String refreshToken = extractCookie(request, "refreshToken");

        if (refreshToken == null) {
            return ResponseEntity.status(401).body("No refresh token");
        }

        try {
            RefreshToken rt = refreshTokenService.validate(refreshToken);

            User user = userService.getByEmail(rt.getEmail());

            String newAccessToken = jwtUtil.generateToken(user.getEmail(), user.getRole());

            ResponseCookie newAccessCookie = ResponseCookie.from("accessToken", newAccessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(60 * 15)
                    .sameSite("None")
                    .build();

            response.addHeader("Set-Cookie", newAccessCookie.toString());

            return ResponseEntity.ok("Token refreshed"); // 🔥 IMPORTANT

        } catch (Exception e) {
            return ResponseEntity.status(401).body("Refresh failed");
        }
    }

    // 🚪 LOGOUT
    @DeleteMapping("/auth/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {

        String refreshToken = null;
        

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }
        }

        if (refreshToken != null) {
            refreshTokenService.delete(refreshToken);
        }

        // ❌ DELETE COOKIES
        ResponseCookie deleteAccess = ResponseCookie.from("accessToken", "")
                .httpOnly(true)
                .secure(secureCookie)
                .path("/")
                .maxAge(0)
                .sameSite(secureCookie ? "None" : "Lax")
                .build();

        ResponseCookie deleteRefresh = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .sameSite("Lax")
                .build();

        response.addHeader("Set-Cookie", deleteAccess.toString());
        response.addHeader("Set-Cookie", deleteRefresh.toString());

        return "Logged out successfully";
    }

    // 👤 USER ENDPOINT
    @GetMapping("/user")
    public String user() {
        return "User endpoint";
    }

    // 🔥 ADMIN ENDPOINT
    @GetMapping("/admin")
    public String admin() {
        return "Admin endpoint";
    }

    // 🔧 PROMOTE USER TO ADMIN
    @PutMapping("/admin/promote")
    public String makeAdmin(@RequestParam String email) {

        User user = userService.getByEmail(email);

        user.setRole("ADMIN");

        userService.save(user);

        return "User promoted to ADMIN";
    }

    // TEST
    @GetMapping("/hello")
    public String hello() {
        return "hello world";
    }
    
    @GetMapping("/")
    public String home() {
        return "Backend is running";
    }

    // DEBUG ROLE
    @GetMapping("/debug")
    public String debug(org.springframework.security.core.Authentication auth) {
        return auth.getAuthorities().toString();
    }
    
    private String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;

        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}