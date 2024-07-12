package com.example.demoSecur.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY="e4b50231e9c7bfce5d22931b1f5f868bd8381f316b91c41b2c257d7d8bdf89732c6bf29d031b34beaeb4d6cd0c4ff9a764af25b9c246112200efb2f4903c9620043ad0b888492a38223bf046b228043ddf5671de5566eb4b5ea5c03d2cd9197e15bf299800943465b1fde37a795200fb7a25d58b203821f042e1072f3c0c2c9b090641d4f439426aec240df440bd06f9334b621690bf012a38e17bb9c605be4a9b8e0ffc76529d83936d1473cb1c96449edcf6b2c86e385b1c2cf69f3c747068c9f25d5181668cab590e6dfd314c5c0764cf90a388b36a4e178134686c90daff13649f95906a21201a8186fb5d4549354ddccd28e2789b7b018a8e3cc17a6998";
    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }
    public<T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims =extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken( new HashMap<>(),userDetails);
    }
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username =extractUsername(token);
        return (username.equals(userDetails.getUsername()))&& !isTokenExpired(token);

    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInkey(), SignatureAlgorithm.HS256)
                .compact();
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .setSigningKey(getSignInkey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInkey() {
        byte[]keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
