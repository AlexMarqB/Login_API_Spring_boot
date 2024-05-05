package org.com.login_api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.com.login_api.domain.user.User;
import org.com.login_api.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
//filtro que será executado antes do request sequer chegar no controller
public class SecurityFilter extends OncePerRequestFilter  {
    @Autowired
    TokenService tokenService;
    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = recoverToken(request); //pega o token
        var login = tokenService.validateToken(token); //valida o token - retorna o email do user ou null

        if(login != null) {
            User user = userRepository.findByEmail(login).orElseThrow(() -> new RuntimeException("User not found"));  //encontra o user
            var authorities = Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")); //crias as roles do user
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities); //objeto de auth com
            SecurityContextHolder.getContext().setAuthentication(authentication); //contexto de segurança do spring security, é alimentado conforme o spring security for executado
        }
        filterChain.doFilter(request, response); //mandamos executar este filtro
    }

    //recebe o request, busca o token no header/path/body ...
    private String recoverToken(HttpServletRequest request) {
        var authHeader = request.getHeader("Auth");
        if(authHeader == null) return null;
        //O token vem: "Bearer dasghkdaskhdgada"
        return authHeader.replace("Bearer ", "");
    }
}
