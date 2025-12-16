package io.github.coldmans.rollingjwt.core;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class RollingJwt {
    private final RollingJwtProperties properties;

    // 현재 키와 직전 키
    private SecretKey currentKey;
    private SecretKey previousKey;

    // 다음 로테이션 예정 시간
    private long nextRotationTime;

    public RollingJwt(RollingJwtProperties properties){
        this.properties = properties;
        rotateKey();
    }

    /**
     * 토큰 생성 (Create Token)
     */
    public String create(String subject, Map<String, Object> extraClaims){
        checkRotation();

        Date now = new Date();
        Date validity = new Date(now.getTime() + properties.getAccessTokenValidity().toMillis());

        var builder = Jwts.builder()
                .subject(subject)
                .issuedAt(now)
                .expiration(validity)
                .signWith(currentKey);

        if(extraClaims != null && !extraClaims.isEmpty()){
            builder.claims(extraClaims);
        }
        return builder.compact();

    }

    /**
     * 토큰 검증 (Verify Token)
     * @return subject (userId)
     * @throws JwtException 검증 실패 시
     */
    public String verify(String token){
        checkRotation();

        try{
            return parseClaims(token, currentKey).getSubject();
        } catch (JwtException e){
            if(previousKey != null){
                try{
                    return parseClaims(token, previousKey).getSubject();
                } catch(JwtException ignored){

                }
            }
            throw e;
        }
    }

    // 내부 도우미 메서드: 토큰 파싱
    private Claims parseClaims(String token, SecretKey key){
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // 키 로테이션 체크
    private synchronized void checkRotation(){
        if(System.currentTimeMillis() > nextRotationTime){
            rotateKey();
        }
    }

    // 실제 키 교체 로직
    private void rotateKey(){
        this.previousKey = this.currentKey;
        this.currentKey = generateNewKey();

        // 다음 로테이션 시간 설정
        this.nextRotationTime = System.currentTimeMillis() + properties.getRotationInterval().toMillis();
        System.out.println("[RollingJWt] Key Rotated, next time: " + new Date(nextRotationTime));
    }

    private SecretKey generateNewKey(){
        String randomString = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        return Keys.hmacShaKeyFor(randomString.getBytes(StandardCharsets.UTF_8));
    }
}
