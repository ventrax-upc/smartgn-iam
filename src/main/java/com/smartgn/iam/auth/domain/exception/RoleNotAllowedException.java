package com.smartgn.iam.auth.domain.exception;

import com.smartgn.iam.auth.domain.model.Role;

public class RoleNotAllowedException extends RuntimeException {

    public RoleNotAllowedException(Role role) {
        super("The role " + role + " is not allowed for this operation");
    }
}
