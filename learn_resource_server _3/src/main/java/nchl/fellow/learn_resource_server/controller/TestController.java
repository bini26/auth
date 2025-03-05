package nchl.fellow.learn_resource_server.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/test")
    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    //@RolesAllowed("User")
    public String test(){

        return "testing controller for any role";
    }


    @GetMapping("/demo")
    @RolesAllowed("ADMIN")
    @PreAuthorize("hasAuthority('EDIT')")
    public Authentication demo(Authentication a) {
        return a;
    }


    @GetMapping("/test1")
    @PreAuthorize("hasAuthority('Read')")
    public String testing(){
return " testing for the read authority";
    }

    @GetMapping("/test2")
    @PreAuthorize("hasAnyAuthority('Read','WRITE','DELETE','EDIT')")
    public String test1(){
        return " testing for any authority";
    }

}
