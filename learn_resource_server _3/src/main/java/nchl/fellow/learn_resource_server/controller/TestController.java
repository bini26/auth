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
    @PreAuthorize("hasRole('ADMIN')")
    //@RolesAllowed("User")
    public String test(){
        return "test controller";
    }


    @GetMapping("/demo")
    public Authentication demo(Authentication a) {
        return a;
    }


    @GetMapping("/test1")
    @PreAuthorize("hasAuthority('Read')")
    public String testing(){
return " testing for the read authority";
    }

}
