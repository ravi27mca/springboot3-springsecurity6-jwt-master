package com.truongbn.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/resource")
@RequiredArgsConstructor
public class AuthorizationController {
	@GetMapping
	public ResponseEntity<String> sayHello() {
		log.info("AuthorizationController:::sayHello:::start here");
		return ResponseEntity.ok("Here is your resource");
	}
}
