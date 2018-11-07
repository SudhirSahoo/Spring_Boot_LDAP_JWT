package com.innovativeintelli.ldapauthenticationjwttoken.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.innovativeintelli.ldapauthenticationjwttoken.payload.JwtAuthenticationResponse;
import com.innovativeintelli.ldapauthenticationjwttoken.payload.LoginRequest;
import com.innovativeintelli.ldapauthenticationjwttoken.payload.ValidateTokenRequest;
import com.innovativeintelli.ldapauthenticationjwttoken.security.ApiResponse;
import com.innovativeintelli.ldapauthenticationjwttoken.security.JwtTokenProvider;
import com.innovativeintelli.ldapauthenticationjwttoken.util.MessageConstants;

@RestController
//@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    
    @Autowired
    JwtTokenProvider tokenProvider;

    @SuppressWarnings({ "unchecked", "rawtypes" })
	@PostMapping("/token")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
    	if(loginRequest.getUserName().isEmpty() || loginRequest.getPassword().isEmpty()) {
    		 return new ResponseEntity(new ApiResponse(false, MessageConstants.USERNAME_OR_PASSWORD_INVALID),
                     HttpStatus.BAD_REQUEST);
    	}
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUserName(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println("AuthController: " + authentication.getName());
        System.out.println("AuthController: " + authentication.getPrincipal());
        System.out.println("AuthController: " + authentication.getAuthorities());
        String jwt = tokenProvider.generateToken(authentication);
        System.out.println("AuthController: Token:" + jwt);

        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
	@PostMapping("/validatetoken")
    public ResponseEntity<?> getTokenByCredentials(@Valid @RequestBody ValidateTokenRequest validateToken) {
    	 String username = null;
    	 String jwt =validateToken.getToken();
         if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                username = tokenProvider.getUserNameFromJWT(jwt);
	          //If required we can have one more check here to load the user from LDAP server
             return ResponseEntity.ok(new ApiResponse(Boolean.TRUE,MessageConstants.VALID_TOKEN + username));
           }else {
        	   return new ResponseEntity(new ApiResponse(false, MessageConstants.INVALID_TOKEN),
                       HttpStatus.BAD_REQUEST);
           }
         
    }


}