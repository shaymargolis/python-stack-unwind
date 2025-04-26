void c(void) {
    char buff[0x200] = {0};
    printf("C %d\n", getpid());
    sleep(10);
}

void b(void) {
    char buff[0x50] = {0};
    c();
}

void a(void) {
    char buff[0x100] = {0};
    b();
}

int main(int argc, char const *argv[])
{
    a();
    return 0;
}