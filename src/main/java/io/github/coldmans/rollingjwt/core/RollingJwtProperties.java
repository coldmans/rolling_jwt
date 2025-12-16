package io.github.coldmans.rollingjwt.core;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "rolling-jwt")
public class RollingJwtProperties {
    /**
     * 엑세스 토큰의 만료 시간
     * 기본값 : 30분
     */
    private Duration accessTokenValidity = Duration.ofMinutes(30);

    /**
     * 키 로테이션 주기. 이 시간이 지나면 새로운 서명키가 생성됨
     * 기본값: 1시간
     */
    private Duration rotationInterval = Duration.ofHours(1);

    /**
     * 키가 교체된 후, 이전 키를 유효하게 인정해주는 유예 기간
     * 키가 바뀌자마자 모든 사용자가 로그아웃되는 것을 방지
     * 기본값: 5분
     */
    private Duration gracePeriod = Duration.ofMinutes(5);

    public Duration getAccessTokenValidity() {
        return accessTokenValidity;
    }

    public void setAccessTokenValidity(Duration accessTokenValidity) {
        this.accessTokenValidity = accessTokenValidity;
    }

    public Duration getRotationInterval() {
        return rotationInterval;
    }

    public void setRotationInterval(Duration rotationInterval) {
        this.rotationInterval = rotationInterval;
    }

    public Duration getGracePeriod() {
        return gracePeriod;
    }

    public void setGracePeriod(Duration gracePeriod) {
        this.gracePeriod = gracePeriod;
    }

}
