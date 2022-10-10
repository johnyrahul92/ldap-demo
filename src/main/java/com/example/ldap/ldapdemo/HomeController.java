package com.example.ldap.ldapdemo;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
  
  @Secured("ROLE_DEVELOPERS")
  @PostMapping("/test1")
  public @ResponseBody ResponseEntity<String> post() {
    return new ResponseEntity<String>("POST Response", HttpStatus.OK);
  }

  @GetMapping("/test2")
  public String test2() {

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    System.out.println(authentication.getPrincipal());
    return "Welcome to test2!";
  }

}