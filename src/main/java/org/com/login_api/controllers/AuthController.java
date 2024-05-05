package org.com.login_api.controllers;

import lombok.RequiredArgsConstructor;
import org.com.login_api.domain.user.User;
import org.com.login_api.dtos.LoginRequestDTO;
import org.com.login_api.dtos.RegisterRequestDTO;
import org.com.login_api.dtos.ResponseDTO;
import org.com.login_api.infra.security.TokenService;
import org.com.login_api.repositories.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor //faz o autowired para todos os atributos/dependencias
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO data) {
        User user = userRepository.findByEmail(data.email()).orElseThrow(() -> new RuntimeException("User not found"));
        if (passwordEncoder.matches(user.getPassword(), data.password())) {
            String token = tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(token, user.getName()));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO data) {
        Optional<User> user = userRepository.findByEmail(data.email());

        if (user.isEmpty()) {
            User newUser = new User();
            String hashPassword = passwordEncoder.encode(data.password());
            newUser.setPassword(hashPassword);
            newUser.setEmail(data.email());
            newUser.setName(data.name());
            String token = tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(token, newUser.getName()));
        }
        return ResponseEntity.badRequest().build();
    }

}
