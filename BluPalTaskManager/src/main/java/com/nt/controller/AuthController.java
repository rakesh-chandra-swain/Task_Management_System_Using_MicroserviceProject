package com.nt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.authentication.BadCredentialsException;
import com.nt.config.JwtProvider;
import com.nt.model.User;
import com.nt.repository.UserRepository;
import com.nt.request.LoginRequest;
import com.nt.response.AuthResponse;
import com.nt.service.CustomUserServiceImplementation;

@RestController
@RequestMapping("/auth")
public class AuthController {
	
	@Autowired
	private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private CustomUserServiceImplementation customUserServiceImplementation;
    @Autowired
    private JwtProvider jwtProvider;
    
    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> createUserHandler(@RequestBody User user) throws Exception{
    	String email=user.getEmail();
    	String password=user.getPassword();
    	String fullname=user.getFullName();
    	String role=user.getRole();
    	
    	User isEmailExsist=userRepository.findByEmail(email);
    	
    	if(isEmailExsist!=null) {
    		throw new Exception("Email is Already Used With Another Account");
    	}
		//create new user
    	User createUser=new User();
    	createUser.setEmail(email);
    	createUser.setFullName(fullname);
    	createUser.setRole(role);
    	createUser.setPassword(passwordEncoder.encode(password));
    	
    	User saveUser=userRepository.save(createUser);
    	
    	Authentication authentication = new UsernamePasswordAuthenticationToken(email, password);
    	SecurityContextHolder.getContext().setAuthentication(authentication);
    	
    	String token=jwtProvider.generateToken(authentication);
    	
    	AuthResponse authResponse=new AuthResponse();
    	authResponse.setJwt(token);
    	authResponse.setMessage("Register Success");
    	authResponse.setStatus(true);
    	
    	return new ResponseEntity<AuthResponse>(authResponse,HttpStatus.OK);
    }
    
    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> signin(@RequestBody LoginRequest loginRequest) throws Exception{
    	
    	String username=loginRequest.getEmail();
    	String password=loginRequest.getPassword();

    	System.out.println(username+"------"+password);
    	
    	Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
    	SecurityContextHolder.getContext().setAuthentication(authentication);
    	
    	String token=jwtProvider.generateToken(authentication);
    	AuthResponse authResponse=new AuthResponse();
    	
    	authResponse.setMessage("Login Success");
    	authResponse.setJwt(token);
    	authResponse.setStatus(true);
    	
    	return new ResponseEntity<AuthResponse>(authResponse,HttpStatus.OK);
    }
    private Authentication authenticate(String username, String password) {
        UserDetails userDetails = customUserServiceImplementation.loadUserByUsername(username);

        System.out.println("Sign in - userDetails: " + userDetails);

        if (userDetails == null) {
            System.out.println("Sign in - userDetails is null");
            throw new BadCredentialsException("Invalid username or password");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            System.out.println("Sign in - password mismatch for user: " + username);
            throw new BadCredentialsException("Invalid username or password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

}
