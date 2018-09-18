package base.icopy.site.web.rest;

import base.icopy.site.security.jwt.JWTFilter;
import base.icopy.site.security.jwt.TokenProvider;
import base.icopy.site.web.rest.vm.LoginVM;

import com.codahale.metrics.annotation.Timed;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
public class UserJWTController {

    private final TokenProvider tokenProvider;

    private final AuthenticationManager authenticationManager;

    public UserJWTController(TokenProvider tokenProvider, AuthenticationManager authenticationManager) {
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/authenticate")
    @Timed
    public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginVM loginVM) {

        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(loginVM.getUsername(), loginVM.getPassword());

        Authentication authentication = this.authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        boolean rememberMe = (loginVM.isRememberMe() == null) ? false : loginVM.isRememberMe();
       List<String> auths= authentication.getAuthorities().stream().map(au->((GrantedAuthority) au).getAuthority()).collect(Collectors.toList());
        String jwt = tokenProvider.createToken(authentication, rememberMe);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        return new ResponseEntity<>(new JWTToken(jwt,auths,"ok"), httpHeaders, HttpStatus.OK);
    }

    /**
     * Object to return as body in JWT Authentication.
     */
    static class JWTToken {

        private String idToken;
        private List<String> auths;
        private String status;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        public JWTToken(String idToken, List<String> auths,String status) {
            this.idToken = idToken;
            this.auths = auths;
            this.status=status;
        }
        @JsonProperty("currentAuthority")
        List<String> getAuths(){
            return auths;
        }

        @JsonProperty("id_token")
        String getIdToken() {
            return idToken;
        }

        @JsonProperty("status")
        String getStatus() {
            return status;
        }
        void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
