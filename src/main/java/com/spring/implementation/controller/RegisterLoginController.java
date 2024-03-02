package com.spring.implementation.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import com.spring.implementation.DTO.UserDTO;
import com.spring.implementation.DTO.UserLoginDTO;
import com.spring.implementation.model.PasswordResetToken;
import com.spring.implementation.model.User;
import com.spring.implementation.repository.TokenRepository;
import com.spring.implementation.repository.UserRepository;
import com.spring.implementation.service.UserDetailsServiceImpl;

@Controller
public class RegisterLoginController {

	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Autowired
	UserRepository userRepository;
	@Autowired
	TokenRepository tokenRepository;
	
	private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


	@PostMapping("/forgotPassword")
	public String forgotPasswordProcess(@ModelAttribute UserDTO userDTO) {
		String output = "";
		User user = userRepository.findByEmail(userDTO.getEmail());
		if (user != null) {
			output = userDetailsService.sendEmail(user);
		}
		if (output.equals("success")) {
			return "success";
		}
		return "error";
	}

	@GetMapping("/resetPassword/{token}")
	public String resetPasswordForm(@PathVariable String token, Model model) {
		PasswordResetToken reset = tokenRepository.findByToken(token);
		if (reset != null && userDetailsService.hasExipred(reset.getExpiryDateTime())) {
			model.addAttribute("email", reset.getUser().getEmail());
			return "resetPassword";
		}
		return "forget password error token";
	}
	
	@PostMapping("/resetPassword")
	public String passwordResetProcess(@ModelAttribute UserDTO userDTO) {
		User user = userRepository.findByEmail(userDTO.getEmail());
		if(user != null) {
			user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
			userRepository.save(user);
		}
		return "retour à login";
	}

}
