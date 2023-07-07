package tech.dobler.basic_security.exceptions;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class UserDeactivatedException extends UsernameNotFoundException {
    public UserDeactivatedException(String msg) {
        super(msg);
    }
}
