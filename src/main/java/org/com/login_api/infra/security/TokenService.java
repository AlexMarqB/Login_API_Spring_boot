package org.com.login_api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.com.login_api.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

//iremos configuar a geração de token
@Service
public class TokenService {
    //recupera um value do application.properties
    @Value("${api.security.token.secret}")
    private String secret;
    private Algorithm algorithm = Algorithm.HMAC256(secret);

    public String generateToken(User user) {

        try {
            //exige uma secret key. Pegar uma informação e criptografa podendo descriptografar depois
            //gerar token
            String token = JWT.create()
                    .withIssuer("login-api") //identifica qual api gerou o serviço
                    .withSubject(user.getEmail()) //salvamos o email do user no token
                    .withExpiresAt(generateExpirationDate())
                    .sign(algorithm);
            return token;
        }
        catch (JWTCreationException  exception) {
            throw new RuntimeException("Error while auth");
        }
    }

    public String validateToken(String token){
        try {
            return JWT.require(algorithm)
                    .withIssuer("login-api")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException exception) {return null;}
    }

    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusDays(5).toInstant(ZoneOffset.of("-3"));
    }
}
