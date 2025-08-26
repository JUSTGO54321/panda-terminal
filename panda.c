#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>

#define MAXLINE 1024
#define MAXJOBS 32
#define SEARCHBYJOB 0
#define SEARCHBYPID 1

typedef struct {
    char job[20];
    pid_t pid;
    char pidString[MAXLINE];
    int active;
    int suspended;
    char processName[MAXLINE - 60];
} Job;

int jobCounter = 0;
Job jobs[MAXJOBS + 1];
volatile sig_atomic_t fg_pid = -1;
volatile sig_atomic_t fgpidexit = 0;
sigset_t mask_all, prev_all;

void handle_sigquit(int signal) {
    if (fg_pid > 0) {
        kill(-fg_pid, SIGQUIT);
    } else {
        for (int i = 1; i <= MAXJOBS; i++) {
            if (jobs[i].active) {
                kill(-jobs[i].pid, SIGQUIT);
            }
        }
        exit(0);
    }
}

void handle_sigint(int signal) {
    if (fg_pid > 0) {
        kill(-fg_pid, SIGKILL);
    }
}

void printSigChildOutput(Job job, char terminationType[MAXLINE], char coreDumped[MAXLINE]) {
    char msg[3 * MAXLINE] = "[";
    strcat(msg, job.job);
    strcat(msg, "] (");
    strcat(msg, job.pidString);
    strcat(msg, ")  ");
    strcat(msg, terminationType);
    strcat(msg, " ");
    strcat(msg, coreDumped);
    strcat(msg, " ");
    strcat(msg, job.processName);
    strcat(msg, "\n");
    write(STDOUT_FILENO, msg, strlen(msg));
}

void handle_sigchild(int signal) {
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        if (pid == fg_pid) {
            fgpidexit = 1;
        }
        for (int i = 1; i <= MAXJOBS; i++) {
            if (jobs[i].pid == pid && jobs[i].active) {
                if (WIFEXITED(status)) {
                    jobs[i].active = 0;
                    printSigChildOutput(jobs[i], "finished", "");
                    break;
                } else if (WIFSIGNALED(status)) {
                    jobs[i].active = 0;
                    printSigChildOutput(jobs[i], "killed", WCOREDUMP(status) ? "(core dumped) " : "");
                    break;
                } else if (WIFSTOPPED(status)) {
                    printSigChildOutput(jobs[i], "suspended", "");
                    fgpidexit = 1;
                    jobs[i].suspended = 1;
                    break;
                }
            }
        }
    }
}

static char **convertArgs(const char **toks) {
    int count = 0;
    while (toks[count] != NULL) count++;
    char **args = malloc((count + 1) * sizeof(char *));
    for (size_t i = 0; i < count; i++) {
        args[i] = strdup(toks[i]); 
    }
    args[count] = NULL;
    return args;
} 

int getFreeJobIndex() {
    for (int i = 1; i <= MAXJOBS; i++) {
        if (jobs[i].active == 0) {
            return i;
        }
    }
    return -1;
}

Job addJob(pid_t pid, const char *cmd, int index) {
    char jobId[MAXLINE];
    snprintf(jobId, MAXLINE, "%i", ++jobCounter);
    char pidString[MAXLINE];
    snprintf(pidString, MAXLINE, "%i", pid);
    strncpy(jobs[index].job, jobId, sizeof(jobs[index].job));
    jobs[index].pid = pid;
    strncpy(jobs[index].pidString, pidString, sizeof(jobs[index].pidString));
    jobs[index].active = 1;
    jobs[index].suspended = 0;
    strncpy(jobs[index].processName, cmd, sizeof(jobs[index].processName));
    return jobs[index];
}

int isValidArg(int searchType, const char *searchValue, char *cmd) {
    int isGoodArg = 1;
    if (searchType == SEARCHBYJOB) {
        for (int i = 1; searchValue[i]; i++) {
            if (!isdigit(searchValue[i]) || atoi(searchValue + 1) == 0) {
                isGoodArg = 0;
                break;
            }
        }
    } else if (searchType == SEARCHBYPID) {
        for (int i = 0; searchValue[i]; i++) {
            if (!isdigit(searchValue[i])) {
                isGoodArg = 0;
                break;
            }
        }
    }
    if (!isGoodArg) {
        char msg[MAXLINE];
        snprintf(msg, MAXLINE, "ERROR: bad argument for %s: %s\n", cmd, searchValue);
        write(STDERR_FILENO, msg, strlen(msg));
    }
    return isGoodArg;
}

void fg(int searchType, const char *searchValue) {
    int pid = -1;
    if (searchType == SEARCHBYJOB) {
        if (!isValidArg(searchType, searchValue, "fg")) {
            return;
        }
        int jobId = atoi(searchValue + 1);
        for (int i = 1; i <= MAXJOBS; i++) {
            if (jobs[i].active && jobId == atoi(jobs[i].job)) {
                pid = jobs[i].pid;
                break;
            }
        }
        if (pid == -1) {
            char msg[MAXLINE];
            snprintf(msg, MAXLINE, "ERROR: no job %s\n", searchValue + 1);
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }
    } else if (searchType == SEARCHBYPID) {
        if (!isValidArg(searchType, searchValue, "fg")) {
            return;
        }
        for (int i = 1; i <= MAXJOBS; i++) {
            int pidInt = atoi(searchValue);
            if (jobs[i].active && pidInt == jobs[i].pid){
                pid = pidInt;
            }
        }
        if (pid == -1) {
            char msg[MAXLINE];
            snprintf(msg, MAXLINE, "ERROR: no PID %s\n", searchValue);
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }
    }
    signal(SIGTTOU, SIG_IGN);
    fg_pid = pid;
    tcsetpgrp(STDIN_FILENO, pid);
    for (int i = 1; i <= MAXJOBS; i++) {
        if (jobs[i].active && jobs[i].pid == pid && jobs[i].suspended) {
            kill(-pid, SIGCONT);
            jobs[i].suspended = 0;
            printSigChildOutput(jobs[i], "continued", "");
            break;
        }
    }
    
    while (fgpidexit == 0) {
        usleep(50);
    }
    tcsetpgrp(STDIN_FILENO, getpid());
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    fg_pid = -1;
    fgpidexit = 0;
    sigprocmask(SIG_SETMASK, &prev_all, NULL);
}

void bg_func(int searchType, const char *searchValue) {
    Job *job = NULL;
    if (searchType == SEARCHBYJOB) {
        if (!isValidArg(searchType, searchValue, "bg")) {
            return;
        }
        int jobId = atoi(searchValue + 1);
        for (int i = 1; i <= MAXJOBS; i++) {
            if (jobs[i].active && jobId == atoi(jobs[i].job)) {
                job = &jobs[i];
                break;
            }
        }
        if (job == NULL) {
            char msg[MAXLINE];
            snprintf(msg, MAXLINE, "ERROR: no job %s\n", searchValue + 1);
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }
    } else if (searchType == SEARCHBYPID) {
        if (!isValidArg(searchType, searchValue, "bg")) {
            return;
        }
        int pid = atoi(searchValue);
        for (int i = 1; i <= MAXJOBS; i++) {
            if (jobs[i].active && pid == jobs[i].pid){
                job = &jobs[i];
                break;
            }
        }
        if (job == NULL) {
            char msg[MAXLINE];
            snprintf(msg, MAXLINE, "ERROR: no PID %s\n", searchValue);
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }
    }
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    if (job->suspended) {
        kill(-job->pid, SIGCONT);
        job->suspended = 0;
        printSigChildOutput(*job, "continued", "");
    }
    sigprocmask(SIG_SETMASK, &prev_all, NULL);
}

// toks: a single command parsed from parse_and_eval
void eval(const char **toks, bool bg) { // bg is true iff command ended with &
    assert(toks);

    if (*toks == NULL) return;
    if (strcmp(toks[0], "quit") == 0) {
        if (toks[1] != NULL) {
            const char *msg = "ERROR: quit takes no arguments\n";
            write(STDERR_FILENO, msg, strlen(msg));
        } else {
            exit(0);
        }
    } else if (strcmp(toks[0], "jobs") == 0) {
        if (toks[1] != NULL) {
            const char *msg = "ERROR: jobs takes no arguments\n";
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }
        for (int i = 1; i <= MAXJOBS; i++) {
            if (jobs[i].active && !jobs[i].suspended) {
                char msg[MAXLINE + 1];
                snprintf(msg, MAXLINE, "[%s] (%i)  running  %s\n", jobs[i].job, jobs[i].pid, jobs[i].processName);
                write(STDOUT_FILENO, msg, strlen(msg));
            } else if (jobs[i].active && jobs[i].suspended) {
                char msg[MAXLINE + 1];
                snprintf(msg, MAXLINE, "[%s] (%i)  suspended  %s\n", jobs[i].job, jobs[i].pid, jobs[i].processName);
                write(STDOUT_FILENO, msg, strlen(msg));
            }
        }
    } else if (strcmp(toks[0], "nuke") == 0) { 
        if (toks[1] == NULL) { // kill all processes
            for (int i = 1; i <= MAXJOBS; i++) {
                if (jobs[i].active) {
                    kill(-jobs[i].pid, SIGKILL);
                }
            }
        } else { // kill based on jobId or PID
            int i = 1;
            while (toks[i] != NULL) {
                int isBadArg = 0;
                int foundJob = 0;
                if (toks[i][0] == '%') { // kill based on jobId
                    for (int j = 1; toks[i][j]; j++) {
                        if (!isdigit(toks[i][j]) || atoi(toks[i] + 1) == 0) {
                            isBadArg = 1;
                            char msg[MAXLINE];
                            snprintf(msg, MAXLINE, "ERROR: bad argument for nuke: %s\n", toks[i]);
                            write(STDERR_FILENO, msg, strlen(msg));
                            break;
                        }
                    }
                    if (isBadArg == 0) {
                        for (int j = 1; j <= MAXJOBS; j++) {
                            if (jobs[j].active && atoi(jobs[j].job) == atoi(toks[i] + 1)) {
                                foundJob = 1;
                                kill(-jobs[j].pid, SIGKILL);
                                break;
                            }
                        }
                        if (foundJob == 0) {
                            char msg[MAXLINE];
                            snprintf(msg, MAXLINE, "ERROR: no job %s\n", toks[i] + 1);
                            write(STDERR_FILENO, msg, strlen(msg));
                        }
                    }
                } else { // kill based on PID
                    for (int j = 0; toks[i][j]; j++) {
                        if (!isdigit(toks[i][j])) {
                            isBadArg = 1;
                            char msg[MAXLINE];
                            snprintf(msg, MAXLINE, "ERROR: bad argument for nuke: %s\n", toks[i]);
                            write(STDERR_FILENO, msg, strlen(msg));
                            break;
                        }
                    }
                    if (isBadArg == 0) {
                        for (int j = 1; j <= MAXJOBS; j++) {
                            if (jobs[j].active && jobs[j].pid == atoi(toks[i])) {
                                foundJob = 1;
                                kill(-jobs[j].pid, SIGKILL);
                                break;
                            }
                        }
                        if (foundJob == 0) {
                            char msg[MAXLINE];
                            snprintf(msg, MAXLINE, "ERROR: no PID %s\n", toks[i]);
                            write(STDERR_FILENO, msg, strlen(msg));
                        }
                    }
                }
                i++;
            }
        }
    } else if (strcmp(toks[0], "fg") == 0) {
        if (toks[1] == NULL || toks[2] != NULL) {
            const char *msg = "ERROR: fg needs exactly one argument\n";
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }
        if (toks[1][0] == '%') {
            fg(SEARCHBYJOB, toks[1]);
        } else {
            fg(SEARCHBYPID, toks[1]);
        }
    } else if (strcmp(toks[0], "bg") == 0) {
        if (toks[1] == NULL) {
            const char *msg = "ERROR: bg needs some arguments\n";
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }
        int i = 1;
        while (toks[i]) {
            if (toks[i][0] == '%') {
                bg_func(SEARCHBYJOB, toks[i]);
            } else {
                bg_func(SEARCHBYPID, toks[i]);
            }
            i++;
        }
    } else {
        // too many jobs error
        sigset_t mask, prev;
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, &prev);
        int jobIndex = getFreeJobIndex();
        if (jobIndex == -1) {
            char *msg = "ERROR: too many jobs\n";
            write(STDERR_FILENO, msg, strlen(msg));
            sigprocmask(SIG_SETMASK, &prev, NULL);
            return;
        }
        pid_t pid = fork(); // returns child's PID to parent and 0 to child
    
        if (pid == 0) { // execute process
            setpgid(0, 0);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            // signal(SIGTSTP, SIG_DFL);
            if (execvp(toks[0], convertArgs(toks)) == -1){
                char msg[MAXLINE+1];
                snprintf(msg, MAXLINE, "ERROR: cannot run %s\n", toks[0]);
                write(STDERR_FILENO, msg, strlen(msg));
                exit(1);
            }
            exit(0);
        } else { // add jobs and do bg or fg
            Job job = addJob(pid, toks[0], jobIndex);
            setpgid(pid, pid);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            
            if (!bg) {
                signal(SIGTTOU, SIG_IGN);
                fg_pid = pid;
                tcsetpgrp(STDIN_FILENO, pid);
                while(fgpidexit == 0) {
                    usleep(50);
                }
                tcsetpgrp(STDIN_FILENO, getpid());
                sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
                fg_pid = -1;
                fgpidexit = 0;
                sigprocmask(SIG_SETMASK, &prev_all, NULL);
            } else {
                char msg[MAXLINE + 1];
                snprintf(msg, MAXLINE, "[%s] (%i)  running  %s\n", job.job, job.pid, toks[0]);
                write(STDOUT_FILENO, msg, strlen(msg));
            }

        }
    }
}

void parse_and_eval(char *s) {
    assert(s);
    const char *toks[MAXLINE+1];
    
    while (*s != '\0') {
        bool end = false;
        bool bg = false;
        int t = 0;

        while (*s != '\0' && !end) {
            while (*s == '\n' || *s == '\t' || *s == ' ') ++s;
            if (*s != ';' && *s != '&' && *s != '\0') toks[t++] = s;
            while (strchr("&;\n\t ", *s) == NULL) ++s;
            switch (*s) {
            case '&':
                bg = true;
                end = true;
                break;
            case ';':
                end = true;
                break;
            }
            if (*s) *s++ = '\0';
        }
        toks[t] = NULL;
        eval(toks, bg);
    }
}

void prompt() {
    const char *prompt = "panda> ";
    ssize_t nbytes = write(STDOUT_FILENO, prompt, strlen(prompt));
}

int repl() {

    struct sigaction sa_child;
    sa_child.sa_handler = handle_sigchild;
    sa_child.sa_flags = SA_RESTART;
    sigemptyset(&sa_child.sa_mask);
    sigaction(SIGCHLD, &sa_child, NULL);

    struct sigaction sa_int;
    sa_int.sa_handler = handle_sigint;
    sa_int.sa_flags = SA_RESTART;
    sigemptyset(&sa_int.sa_mask);
    sigaction(SIGINT, &sa_int, NULL);

    struct sigaction sa_quit;
    sa_quit.sa_handler = handle_sigquit;
    sa_quit.sa_flags = SA_RESTART;
    sigemptyset(&sa_quit.sa_mask);
    sigaction(SIGQUIT, &sa_quit, NULL);

    char *buf = NULL;
    size_t len = 0;
    while (prompt(), getline(&buf, &len, stdin) != -1) {
        parse_and_eval(buf);
    }

    if (buf != NULL) free(buf);
    if (ferror(stdin)) {
        perror("ERROR");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    sigfillset(&mask_all);
    return repl();
}
