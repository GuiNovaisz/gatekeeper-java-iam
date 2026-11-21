package io.github.guinovaisz.gatekeeper.security;

import org.springframework.http.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(AuthenticationException.class) ResponseEntity<?> authentication() {return error(401,"Authentication rejected");}
    @ExceptionHandler({IllegalArgumentException.class,MethodArgumentNotValidException.class,org.springframework.http.converter.HttpMessageNotReadableException.class}) ResponseEntity<?> invalid() {return error(400,"Request rejected");}
    @ExceptionHandler(ResponseStatusException.class) ResponseEntity<?> status(ResponseStatusException e) {return error(e.getStatusCode().value(),"Request rejected");}
    @ExceptionHandler(org.springframework.dao.DataAccessException.class) ResponseEntity<?> database() {return error(503,"Service unavailable");}
    private ResponseEntity<?> error(int status,String title) {return ResponseEntity.status(status).body(java.util.Map.of("status",status,"title",title));}
}
