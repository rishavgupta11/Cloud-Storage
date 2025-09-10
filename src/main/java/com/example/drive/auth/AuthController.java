package com.example.drive.auth;

import com.example.drive.config.JwtService;
import com.example.drive.user.User;
import com.example.drive.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        logger.info("Registration attempt for email: {}", request.getEmail());

        try {
            // Check if user already exists
            if (userRepository.findByEmail(request.getEmail()).isPresent()) {
                logger.warn("Email already exists: {}", request.getEmail());
                Map<String, String> error = new HashMap<>();
                error.put("error", "Email already registered");
                return ResponseEntity.badRequest().body(error);
            }

            // Create new user
            User user = User.builder()
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role("ROLE_USER")
                    .build();

            userRepository.save(user);
            logger.info("User registered successfully: {}", request.getEmail());

            // Return success message without tokens (user must login separately)
            Map<String, String> response = new HashMap<>();
            response.put("message", "Account created successfully! Please login to continue.");
            response.put("email", request.getEmail());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Registration failed: ", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Registration failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request) {
        logger.info("Login attempt for email: {}", request.getEmail());

        try {
            // Authenticate user
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found after authentication"));

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(user.getEmail());
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());

            Map<String, String> response = new HashMap<>();
            response.put("accessToken", accessToken);
            response.put("refreshToken", refreshToken);
            response.put("email", user.getEmail());
            response.put("message", "Login successful");

            logger.info("User logged in successfully: {}", request.getEmail());
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            logger.warn("Login failed - invalid credentials for email: {}", request.getEmail());
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid credentials");
            error.put("message", "Email or password is incorrect");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        } catch (AuthenticationException e) {
            logger.error("Authentication failed: ", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        } catch (Exception e) {
            logger.error("Login error: ", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Login failed");
            error.put("message", "An unexpected error occurred");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody TokenRefreshRequest request) {
        logger.info("Token refresh attempt");

        try {
            String refreshToken = request.getRefreshToken();

            // Validate refresh token format
            if (!jwtService.isTokenValidFormat(refreshToken)) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "Invalid refresh token format");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
            }

            String email = jwtService.extractUsername(refreshToken);
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Create UserDetails from User entity
            if (jwtService.isTokenValid(refreshToken, user)) {
                String newAccessToken = jwtService.generateAccessToken(user.getEmail());
                String newRefreshToken = jwtService.generateRefreshToken(user.getEmail());

                Map<String, String> response = new HashMap<>();
                response.put("accessToken", newAccessToken);
                response.put("refreshToken", newRefreshToken);
                response.put("email", email);
                response.put("message", "Token refreshed successfully");

                logger.info("Token refreshed successfully for user: {}", email);
                return ResponseEntity.ok(response);
            } else {
                Map<String, String> error = new HashMap<>();
                error.put("error", "Invalid or expired refresh token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
            }

        } catch (Exception e) {
            logger.error("Token refresh failed: ", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Token refresh failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        // In a stateless JWT setup, logout is typically handled client-side
        Map<String, String> response = new HashMap<>();
        response.put("message", "Logged out successfully");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                String email = jwtService.extractUsername(token);
                User user = userRepository.findByEmail(email).orElse(null);

                if (user != null && jwtService.isTokenValid(token, user)) {
                    Map<String, String> response = new HashMap<>();
                    response.put("message", "Token is valid");
                    response.put("email", email);
                    return ResponseEntity.ok(response);
                }
            }

            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Token validation failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    // Test endpoint for debugging
    @GetMapping("/test")
    public ResponseEntity<?> test() {
        logger.info("Test endpoint called");
        Map<String, String> response = new HashMap<>();
        response.put("message", "Auth controller is working!");
        response.put("timestamp", String.valueOf(System.currentTimeMillis()));
        return ResponseEntity.ok(response);
    }
}