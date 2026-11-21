package io.github.guinovaisz.gatekeeper.security;

import java.io.IOException;
import java.time.Duration;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.web.filter.OncePerRequestFilter;

public class ProtocolThrottleFilter extends OncePerRequestFilter {
    private final Throttle throttle;
    public ProtocolThrottleFilter(Throttle throttle){this.throttle=throttle;}
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        if(request.getRequestURI().equals("/oauth2/token") && !throttle.allow("token-source",request.getRemoteAddr(),60,Duration.ofMinutes(1))) {
            response.setStatus(429);response.setContentType("application/json");response.getWriter().write("{\"error\":\"temporarily_unavailable\"}");return;
        }
        chain.doFilter(request,response);
    }
}
