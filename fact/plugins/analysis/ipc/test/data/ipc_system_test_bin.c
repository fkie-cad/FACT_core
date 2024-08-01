#include <stdlib.h>

void call_site(char *command) {
    // consider possible callsites
    system(command);
}

char *called_func() {
    // callsite
    call_site("id");
    return "whoami";
}

void recursive(char *command, int i) {
    if (i == 1) {
        recursive(command, 0);
    } else {
        system(command);
    }
}

int main() {
    // standard case
    system("ls -l");
    // trace into called functions
    system(called_func());
    // callsite
    call_site("pwd");
    // recursive call
    recursive("echo hello", 1);
    return 0;
}