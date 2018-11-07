package com.innovativeintelli.ldapauthenticationjwttoken.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.innovativeintelli.ldapauthenticationjwttoken.model.Student;

@RestController
public class UserController {

	
	@RequestMapping(value="/index", method = RequestMethod.GET, produces = "application/json")
	@PreAuthorize("hasAuthority('USER'")
    public Student index() {
    	Student student = new Student();
    	student.setStudentId(101);
    	student.setFirsName("Sudhir");
    	
    	return student;
    }
	
}