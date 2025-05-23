#include <stdio.h>

int soma(int x, char *y) {
    *y = 'A';
    return 42;
}

int main() {
    char c = 'B';

    int i = soma(10, &c);
    printf("%c\n", c);
}
