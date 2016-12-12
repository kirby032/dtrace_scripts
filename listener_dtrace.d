#!/usr/sbin/dtrace -s

BEGIN
{
    printf("Tracking pid %d\n", $1);
}

syscall::close:entry /pid == $1/
{
    self->fd = arg0
}

syscall::close:return /pid == $1 && self->fd/
{
    my_fd = self->fd;
    rip_0 = (uint64_t)uregs[R_RIP];

    rbp_1 = *(uint64_t*)(copyin(uregs[R_RBP],8));
    rip_1 = *(uint64_t*)(copyin(uregs[R_RBP] + 8,8));

    rbp_2 = *(uint64_t*)copyin(rbp_1,8);
    rip_2 = *(uint64_t*)copyin(rbp_1 + 8,8);

    rbp_3 = *(uint64_t*)copyin(rbp_2,8);
    rip_3 = *(uint64_t*)copyin(rbp_2 + 8,8);
}

pid$1::SetNonblock:entry
{
    self->nonBlockFd = arg0;
}

pid$1::SetNonblock:return /self->nonBlockFd && self->nonBlockFd != my_fd && arg1 != 0/
{
    printf("\n");

    printf("SetNonblock failed but the fd didn't match the most recent close() call\n");
    printf("Dumping stack to the close call anyway\n");

    printf("close fd = %d and SetNonblock fd = %d\n", my_fd, self->nonBlockFd);
    printf("#0\t0x%x\n", (uint64_t)rip_0);
    printf("#1\t0x%x\n", (uint64_t)rip_1);
    printf("#2\t0x%x\n", (uint64_t)rip_2);
    printf("#3\t0x%x\n", (uint64_t)rip_3);

    ustack();
}

pid$1::SetNonblock:return /self->nonBlockFd && self->nonBlockFd == my_fd && arg1 != 0/
{
    printf("\n");

    printf("SetNonblock failed\n");
    printf("Dumping stack to the close call\n");

    printf("close fd = %d and SetNonblock fd = %d\n", my_fd, self->nonBlockFd);
    printf("SetNonblock errno: %d\n", errno);
    printf("#0\t0x%x\n", (uint64_t)rip_0);
    printf("#1\t0x%x\n", (uint64_t)rip_1);
    printf("#2\t0x%x\n", (uint64_t)rip_2);
    printf("#3\t0x%x\n", (uint64_t)rip_3);

    ustack();
}

pid$1::ApplySocketOptions:entry
{
    self->applySocketFd = arg0;
}

pid$1::ApplySocketOptions:return /self->applySocketFd && self->applySocketFd != my_fd && arg1 != 0/
{
    printf("\n");

    printf("ApplySocketOptions failed but the fd didn't match the most recent close() call\n");
    printf("Dumping stack to the close call anyway\n");

    printf("close fd = %d and ApplySocketOptions fd = %d\n", my_fd, self->applySocketFd);
    printf("#0\t0x%x\n", (uint64_t)rip_0);
    printf("#1\t0x%x\n", (uint64_t)rip_1);
    printf("#2\t0x%x\n", (uint64_t)rip_2);
    printf("#3\t0x%x\n", (uint64_t)rip_3);

    ustack();
}

pid$1::ApplySocketOptions:return /self->applySocketFd && self->applySocketFd == my_fd && arg1 != 0/
{
    printf("\n");

    printf("ApplySocketOptions failed\n");
    printf("Dumping stack to the close call\n");

    printf("close fd = %d and ApplySocketOptions fd = %d\n", my_fd, self->applySocketFd);
    printf("ApplySocketOptions errno: %d\n", errno);
    printf("#0\t0x%x\n", (uint64_t)rip_0);
    printf("#1\t0x%x\n", (uint64_t)rip_1);
    printf("#2\t0x%x\n", (uint64_t)rip_2);
    printf("#3\t0x%x\n", (uint64_t)rip_3);

    ustack();
}

syscall::close:return /pid == $1 && arg1 != 0 && errno == EBADF/
{
    printf("\n");
    printf("Close returned EBADF: fd = %d\n", self->fd);
    ustack();
}

