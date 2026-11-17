#ifndef ACCESS_H
#define ACCESS_H

/*
 * Role-based access control.
 * Each role has a fixed set of features it may use, stored in a small
 * table (role x feature). Checking a permission is one table lookup: O(1).
 */

typedef enum {
    ROLE_ADMIN = 0,
    ROLE_USER,
    ROLE_GUEST,
    ROLE_COUNT
} Role;

typedef enum {
    RES_VIEW_PROFILE = 0,
    RES_CHANGE_PASSWORD,
    RES_VIEW_REPORT,
    RES_RUN_SIMULATION,
    RES_READ_LOG,
    RES_MANAGE_USERS,
    RES_COUNT
} Resource;

/* 1 if the role may use the feature, 0 otherwise. */
int access_allowed(Role role, Resource res);

const char *role_name(Role role);
const char *resource_name(Resource res);

#endif
