package com.nt.service;

import java.util.List;

import com.nt.model.User;

public interface UserService {
	
	public User getUserProfile(String jwt);
	public List<User> getAllUser();
}
