package io.github.guinovaisz.gatekeeper.security;

import java.io.IOException;
import java.util.UUID;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.core.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import io.github.guinovaisz.gatekeeper.identity.*;

/** Prevent persisted stale authorities from surviving a credential/security state change. */
public class LiveIdentityFilter extends OncePerRequestFilter {
    private final IdentityRepository identities;
    public LiveIdentityFilter(IdentityRepository identities){this.identities=identities;}
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        Authentication auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth!=null && auth.isAuthenticated() && !(auth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
            HttpSession session=request.getSession(false);
            Identity identity;
            try {identity=identities.find(UUID.fromString(auth.getName())).orElse(null);} catch(IllegalArgumentException e){identity=null;}
            if(identity==null || !identity.state().equals("ACTIVE") || session==null || !(session.getAttribute("credentialVersion") instanceof Long version) || version!=identity.credentialVersion()) {
                SecurityContextHolder.clearContext();if(session!=null)session.invalidate();response.setStatus(401);return;
            }
        }
        chain.doFilter(request,response);
    }
}
