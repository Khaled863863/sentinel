#include "access.h"

/* The access table: rows are roles, columns are features. */
static const unsigned char PERMISSIONS[ROLE_COUNT][RES_COUNT] = {
    /* profile  password  report  simulation  log  manage users */
    {  1,       1,        1,      1,          1,   1 }, /* admin */
    {  1,       1,        1,      1,          0,   0 }, /* user  */
    {  1,       0,        0,      0,          0,   0 }, /* guest */
};

static const char *const ROLE_NAMES[ROLE_COUNT] = { "Admin", "User", "Guest" };

static const char *const RESOURCE_NAMES[RES_COUNT] = {
    "View my profile",
    "Change my password",
    "View security report",
    "Attack simulation",
    "Read the audit log",
    "Manage users",
};

int access_allowed(Role role, Resource res)
{
    if ((int)role < 0 || role >= ROLE_COUNT || (int)res < 0 || res >= RES_COUNT) {
        return 0; /* anything unknown is denied by default */
    }
    return PERMISSIONS[role][res];
}

const char *role_name(Role role)
{
    if ((int)role < 0 || role >= ROLE_COUNT) {
        return "Unknown";
    }
    return ROLE_NAMES[role];
}

const char *resource_name(Resource res)
{
    if ((int)res < 0 || res >= RES_COUNT) {
        return "Unknown";
    }
    return RESOURCE_NAMES[res];
}
