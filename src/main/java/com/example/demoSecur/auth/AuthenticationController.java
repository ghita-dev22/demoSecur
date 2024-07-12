package com.example.demoSecur.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.demoSecur.auth.AuthencationResponse;
import com.example.demoSecur.auth.RegisterRequest;
import com.example.demoSecur.auth.AuthenticationRequest;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    @PostMapping("/register")
    public ResponseEntity<AuthencationResponse>register(
        @RequestBody RegisterRequest request){
        return ResponseEntity.ok(service.register(request));

    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthencationResponse>register(
            @RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(service.authenticate(request));


    }
}
