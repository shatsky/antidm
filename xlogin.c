/* SPDX-License-Identifier: GPL-3.0-or-later */

//#include <stdlib.h> // realloc
#include <unistd.h> // readlink, pipe, fork, close, execve, read, getppid
#include <string.h> // strcmp
#include <stdio.h> // scanf
#include <signal.h> // signal, kill
#include <wait.h> // wait
#include <dirent.h>
#include <sys/stat.h>

#include <limits.h> // PATH_MAX

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <pwd.h> // passwd, getpwnam

#define r 0
#define w 1
#define true 1

int main(int argc, char **argv) {
    char *config_path;
    for (int i=0; i<argc; i++)
    {
        if (strcmp(argv[i], "-c") == 0)
            if (i+1<argc)
                config_path = argv[++i];
    }
    char xterm_command[LINE_MAX];
    char xsession_path[PATH_MAX];
    char line[LINE_MAX];
    FILE *config_fp = fopen(config_path, "r");
    if (config_fp == NULL) {
        printf("Failed to open config\n");
        exit(EXIT_FAILURE);
    }
    while (fgets(line, sizeof line, config_fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (strncmp("XtermCommand=", line, strlen("XtermCommand=")) == 0)
            strcpy(xterm_command, line+strlen("XtermCommand="));
        else if (strncmp("XsessionPath=", line, strlen("XsessionPath=")) == 0)
            strcpy(xsession_path, line+strlen("XsessionPath="));
    }
    fclose(config_fp);
    // check stdin to detect if we are running in terminal
    int bytes_read;
    char stdin_path[PATH_MAX];
    bytes_read = readlink("/proc/self/fd/0", stdin_path, sizeof(stdin_path)-1);
    stdin_path[bytes_read] = '\0';
    if (strcmp(stdin_path, "/dev/null") == 0) {
        printf("Terminal not detected\n");
        // bootstrap
        // query X for screen size
        // create pipe
        int pipe_fd[2];
        while (true) {
            pipe(pipe_fd);
            // fork xterm with self cmdline as its command
            int terminal_pid = fork();
            if (terminal_pid == 0) {
                close(pipe_fd[r]);
                for (int i=0; i<argc; i++) {
                    strcat(xterm_command, " ");
                    strcat(xterm_command, argv[i]);
                }
                extern char** environ;
                execle("/bin/sh", "sh", "-l", "-c", xterm_command, (char *) NULL, environ);
                perror("exec");
                break;
            }
            close(pipe_fd[w]);
            // wait for pipe to close
            printf("Waiting for the pipe to close\n");
            char c;
            while (read(pipe_fd[r], &c, 1) > 0) {}
            close(pipe_fd[r]);
        }
    } else {
        char user[32];
        pam_handle_t *pamh=NULL;
        int retval;
        while (true) {
            // ask for user credentials
            printf("Login: ");
            scanf("%s", user);
            // password input is handled by PAM
            //char *pass; pass = getpass("Password: ");
            static struct pam_conv conv = {
                misc_conv,
                NULL
            };
            if (pam_start("login", user, &conv, &pamh) == PAM_SUCCESS &&
                pam_authenticate(pamh, 0) == PAM_SUCCESS &&
                pam_acct_mgmt(pamh, 0) == PAM_SUCCESS)
                break;
            // misc_conv seems to call exit() so xterm will be restarted with a fresh login prompt
            printf("Something wrong\n");
        }
        printf("Logged in\n");
        //char xsession_path[PATH_MAX] = "/nix/store/603i5d61vv99wb18fynxbjsq7clhxia0-desktops/share/xsessions/";
        char *xsession_filename = &xsession_path[strlen(xsession_path)];
        int xsession_dir_path_len = strlen(xsession_path);
        // build and present sessions list
        DIR *dir = opendir(xsession_path);
        struct dirent *entry;
        struct stat path_stat;
        printf("Reading xsessions directory...\n");
        while ((entry = readdir(dir)) != NULL) {
            strcat(xsession_filename, entry->d_name);
            stat(xsession_path, &path_stat);
            if (!S_ISREG(path_stat.st_mode))
                continue;
            int xsession_filename_len = strlen(xsession_filename);
            if (xsession_filename_len <= 8 || strcmp(&(xsession_filename[xsession_filename_len-8]), ".desktop") != 0)
                continue;
            printf("%s\n", xsession_path);
            //xsession_path[xsession_dir_path_len] = '\0';
            xsession_filename[0] = '\0';
        }
        closedir(dir);
        // ask for session choice
        char session_name[256-8];
        while (true) {
            printf("Session: ");
            scanf("%s", xsession_filename);
            strcat(xsession_filename, ".desktop");
            FILE* session_fp = fopen(xsession_path, "r");
            if (session_fp == NULL) {
                printf("Failed to open session config\n");
                continue;
            }
            while (fgets(line, sizeof line, session_fp)) {
                if (strncmp("Exec=", line, 5) == 0) {
                    // how does pam_open_session really work?
                    printf("Starting session %s\n", xsession_path);
                    if (pam_open_session(pamh, 0) != PAM_SUCCESS) {
                        printf("pam_open_session failed\n");
                        exit(EXIT_FAILURE);
                    }
                    int session_pid = fork();
                    if (session_pid == 0) {
                        // detach from terminal
                        close(0); close(1); close(2);
                        // get and set user uid and gid
                        struct passwd *pwd = getpwnam(user);
                        setuid(pwd->pw_uid);
                        setuid(pwd->pw_gid);
                        chdir(pwd->pw_dir);
                        //extern char** environ;
                        pam_misc_setenv(pamh, "USER", user, 1);
                        pam_misc_setenv(pamh, "HOME", pwd->pw_dir, 1);
                        pam_misc_setenv(pamh, "SHELL", pwd->pw_shell, 1);
                        pam_putenv(pamh, getenv("DISPLAY")-8); // 8 is sizeof "DISPLAY=" which I know is there
                        // correctly splitting cmdline with quotes into args is non-trivial task, shell handles it well
                        execle("/bin/sh", "sh", "-l", "-c", line+5, (char *) NULL, pam_getenvlist(pamh));
                        printf("Failed to exec\n");
                    } else {
                        printf("Detaching from terminal\n");
                        // detach from terminal
                        // install custom handler to survive SIGHUP
                        signal(SIGHUP, SIG_IGN);
                        //kill(getppid(), SIGTERM);
                        // why kill if we can close pts?
                        // xterm handles this same as child exit
                        // this way it will be possible to see messages in terminal by simply adding -hold xterm argument
                        // but the session inherits pts fds too, doesn't it?
                        // can this break it or prevent xterm from exiting?
                        close(0); close(1); close(2);
                        printf("Waiting for session process to exit\n");
                        waitpid(session_pid, NULL, 0);
                        printf("Closing session and exiting\n");
                        pam_close_session(pamh, 0);
                        exit(EXIT_SUCCESS);
                    }
                }
            printf("Failed to find Exec line in session config\n");
            }
        }
    }
}
