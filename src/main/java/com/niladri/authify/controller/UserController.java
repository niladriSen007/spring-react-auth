package com.niladri.authify.controller;

import com.niladri.authify.models.User;
import com.niladri.authify.service.AppUserDetailsService;
import com.niladri.authify.service.EmailService;
import com.niladri.authify.service.JwtService;
import com.niladri.authify.service.UserService;
import com.niladri.authify.to.AuthRequest;
import com.niladri.authify.to.AuthResponse;
import com.niladri.authify.to.ProfileRequest;
import com.niladri.authify.to.ProfileResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final AppUserDetailsService appUserDetailsService;
    private final JwtService jwtService;
    private final EmailService emailService;

    @PostMapping("/register")
    public ResponseEntity<ProfileResponse> createUser(@RequestBody ProfileRequest profileRequest) {
        return ResponseEntity.ok(userService.createUserProfile(profileRequest));
    }

    @GetMapping("/user/hello")
    public String helloUser() {
        return "Hello, User!";
    }

    @GetMapping("/admin/hello")
    public String helloAdmin() {
        return "Hello, Admin!";
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody AuthRequest authRequest) {
        try {
            Authentication authentication = authenticateUser(authRequest.email(), authRequest.password());
            if (authentication.isAuthenticated()) {
                log.info("Logging in user");
                UserDetails userDetails = appUserDetailsService.loadUserByUsername(authRequest.email());
                emailService.sendEmail(userDetails.getUsername().toString());
                return ResponseEntity.ok().body(userDetails);
            } else {
                log.info("User not authenticated while Login");
                throw new UsernameNotFoundException("Invalid user request!");
            }
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(e.getLocalizedMessage());
        }
    }

    @GetMapping("/profile")
//    public ResponseEntity<ProfileResponse> getProfile(@CurrentSecurityContext Authentication authentication) {
    public ResponseEntity<ProfileResponse> getProfile(@CurrentSecurityContext SecurityContext securityContext) {
        log.info("User email from security context: {}", securityContext.getAuthentication().getName());
        log.info("Context: {}", securityContext.getAuthentication().getName());
        String email = securityContext.getAuthentication().getName();
        return ResponseEntity.ok(userService.getUserProfile(email));
    }

    @GetMapping("/is-authenticated")
    public ResponseEntity<String> isAuthenticated(@CurrentSecurityContext SecurityContext securityContext) {
        String email = securityContext.getAuthentication().getName();
        log.info("Checking authentication for user: {}", email);
        if(email == null || email.isEmpty()) {
            return ResponseEntity.status(401).body("User is not authenticated.");
        }
        return ResponseEntity.ok("User " + email + " is authenticated.");
    }

    @PostMapping("/generateToken")
    public ResponseEntity<AuthResponse> authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        log.info("Generating token");
        try {
            log.info(authRequest.password() + " " + authRequest.email());
            Authentication authentication = authenticateUser(authRequest.email(), authRequest.password());
            if (authentication.isAuthenticated()) {
                log.info("User authenticated");
                String jwtToken = jwtService.generateToken(authRequest.email());
                ResponseCookie cookie = ResponseCookie.from("jwtToken", jwtToken)
                        .httpOnly(true)
                        .path("/")
                        .maxAge(Duration.ofDays(1)) // 1 day
                        .sameSite("Strict")
                        .build();
                return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                        .body(new AuthResponse(authRequest.email(), jwtToken));
            } else {
                log.info("User not authenticated");
                throw new UsernameNotFoundException("Invalid user request!");
            }
        } catch (Exception e) {
            log.error("Error during token generation: {}", e.getMessage());
            throw new BadCredentialsException("Invalid credentials!");
        }
    }

    private Authentication authenticateUser(String email, String password) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
    }
}
