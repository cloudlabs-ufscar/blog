#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

void write_remote_vm(pid_t pid, unsigned long remote_addr, const void *data, size_t size) {
    struct iovec local = {
        .iov_base = (void *)data,
        .iov_len = size
    };
    struct iovec remote = {
        .iov_base = (void *)remote_addr,
        .iov_len = size
    };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == -1) {
        perror("process_vm_writev");
        exit(1);
    }
}

void read_remote_vm(pid_t pid, unsigned long remote_addr, void *data, size_t size) {
    struct iovec local = {
        .iov_base = data,
        .iov_len = size
    };
    struct iovec remote = {
        .iov_base = (void *)remote_addr,
        .iov_len = size
    };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n == -1) {
        perror("process_vm_readv");
        exit(1);
    }
}

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("./target", "target", NULL);
        perror("execl");
        exit(1);
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            fprintf(stderr, "filho saiu prematuramente\n");
            return 1;
        }

        struct user_regs_struct regs;

        // Lê registradores
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        // Aloca buffer no stack do filho
        regs.rsp -= 0x100;
        unsigned long buf_addr = regs.rsp;

        const char *conteudo = ".....";
        write_remote_vm(pid, buf_addr, conteudo, strlen(conteudo) + 1);

        regs.rdi = 10;
        regs.rsi = buf_addr;
        regs.rsp -= 8;              // fake retorno
        ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0);
        regs.rip = FUNC_ADDR;       // endereço da função

        // Seta registradores modificados
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        ptrace(PTRACE_CONT, pid, NULL, NULL);
        waitpid(pid, &status, 0);

        // Ler resultado modificado
        char resultado[128] = {0};
        read_remote_vm(pid, buf_addr, resultado, sizeof(resultado));

        printf("[*] Buffer remoto modificado: \"%s\"\n", resultado);
    }

    return 0;
}
