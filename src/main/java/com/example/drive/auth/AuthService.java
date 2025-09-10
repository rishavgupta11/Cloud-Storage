package com.example.drive.auth;

import com.example.drive.config.JwtService;
import com.example.drive.user.User;
import com.example.drive.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // ------------------------
    // 1. Register
    // ------------------------
    public AuthResponse register(RegisterRequest request) {
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("ROLE_USER")
                .build();

        userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // ------------------------
    // 2. Login
    // ------------------------
    public AuthResponse login(AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // ------------------------
    // 3. Refresh Token
    // ------------------------
    public AuthResponse refreshToken(TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();
        String userEmail = jwtService.extractUsername(refreshToken);

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (jwtService.isTokenValid(refreshToken, user)) {
            String newAccessToken = jwtService.generateToken(user);
            return AuthResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(refreshToken)
                    .build();
        } else {
            throw new RuntimeException("Invalid refresh token");
        }
    }

    // ------------------------
    // 4. Logout
    // ------------------------
    public void logout(String email) {
        // Optional: implement token blacklist
        System.out.println("User logged out: " + email);
    }
}
