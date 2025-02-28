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





//for opaque token the post request is
//POST  http://localhost:8001/oauth2/token
//client_id:client
//grant_type:client_credentials
//header   Authorization: Basic Y2xpZW50OnNlY3JldA==


/*
* for jwt token the post request is
* http://localhost:8001/oauth2/token
* client_id:client
redirect_uri:https://www.manning.com/authorized
grant_type:authorization_code
code:VfY2fhCJiyJ7uP4A3Z27xrk-HFhRfhp08X0K4Kmf_lCe034KaGqgzhmH3gsNLdmNmcpllnqXrG9uhFqcSQnVs2Q66BN8kqTx3KIjscFlicQaN68UZpVxhP4ATjTSRVLT
code_verifier:qPsH306-ZDDaOE8DFzVn05TkN3ZZoVmI_6x4LsVglQI
client_secret:secret
*
*header   Authorization:Basic Y2xpZW50OnNlY3JldA==
* */