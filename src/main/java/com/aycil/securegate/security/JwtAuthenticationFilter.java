package com.aycil.securegate.security;

import com.aycil.securegate.model.UserAccount;
import com.aycil.securegate.repository.UserAccountRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserAccountRepository userAccountRepository;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            UserAccountRepository userAccountRepository
    ) {
        this.jwtService = jwtService;
        this.userAccountRepository = userAccountRepository;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        try {
            String username = jwtService.extractUsername(token);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                Optional<UserAccount> userOpt = userAccountRepository.findByUsername(username);
                if (userOpt.isPresent()) {
                    UserAccount user = userOpt.get();
                    if (!user.isAccountLocked() && jwtService.isTokenValid(token, username)) {
                        Claims claims = jwtService.extractAllClaims(token);
                        @SuppressWarnings("unchecked")
                        List<String> roles = claims.get("roles", List.class);

                        List<SimpleGrantedAuthority> authorities = (roles == null ? List.<String>of() : roles)
                                .stream()
                                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                                .toList();

                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(username, null, authorities);
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            }
        } catch (Exception ignored) {
            // Geçersiz veya süresi dolmuş tokenlarda authentication set edilmez
        }

        filterChain.doFilter(request, response);
    }
}
