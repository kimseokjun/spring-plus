package org.example.expert.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter implements Filter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        log.info("JwtFilter invoked, url={}", httpRequest.getRequestURI());

        String url = httpRequest.getRequestURI();


        if (url.startsWith("/auth")) {
            System.out.println("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
            chain.doFilter(request, response); // 그냥 통과시킴
            return;
        }

        String bearerJwt = httpRequest.getHeader("Authorization");

        if (bearerJwt == null) {
            // 토큰이 없는 경우 400을 반환합니다.
            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "JWT 토큰이 필요합니다.");
            return;
        }

        String jwt = jwtUtil.substringToken(bearerJwt);

        try {
            // JWT 유효성 검사와 claims 추출
            Claims claims = jwtUtil.extractClaims(jwt);
            if (claims == null) {
                httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "잘못된 JWT 토큰입니다.");
                return;
            }
            setAuthentication(claims);


            chain.doFilter(request, response);
        } catch (SecurityException | MalformedJwtException e) {
            log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.", e);
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "유효하지 않는 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token, 만료된 JWT token 입니다.", e);
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", e);
            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "지원되지 않는 JWT 토큰입니다.");
        } catch (Exception e) {
            log.error("Internal server error", e);
            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

    // JWT Claims에서 사용자 정보를 추출하여 Spring Security의 인증 정보 설정
    private void setAuthentication(Claims claims) {
        // JWT의 subject claim에서 사용자 ID 추출 (subject는 JWT 표준 claim)
        Long userId = Long.valueOf(claims.getSubject());
        // 커스텀 claim에서 이메일 정보 추출
        String email = claims.get("email", String.class);

        String nickname = claims.get("nickname", String.class);

        // 커스텀 claim에서 사용자 권한 정보를 추출하여 enum으로 변환
        UserRole userRole = UserRole.of(claims.get("userRole", String.class));

        // 추출한 정보로 인증된 사용자 객체 생성
        AuthUser authUser = new AuthUser(userId, email, nickname, userRole);
        // Spring Security가 인식할 수 있는 Authentication 객체 생성
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + userRole.name());
        List<SimpleGrantedAuthority> authorities = List.of(authority);

        Authentication authenticationToken = new UsernamePasswordAuthenticationToken(authUser, null, authorities);

        // SecurityContext에 인증 정보 저장 - 이후 @AuthenticationPrincipal로 접근 가능
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

    private void sendErrorResponse(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/json;charset=UTF-8");
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", status.name());
        errorResponse.put("code", status.value());
        errorResponse.put("message", message);
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
