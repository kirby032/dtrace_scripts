#!/usr/sbin/dtrace -s

BEGIN
{
    printf("Tracking pid %d\n", $1);
}

/*
pid$1:libc.so.7:clnt_vc_create:entry
{
    @clients[ustack()] = count();
}
*/

struct stackinfo
{
    void* rip0;
    void* rip1;
    void* rip2;
    void* rip3;
};

struct stackinfo i[void*];

pid$1::LwPromiseCreate:entry
{
    self->pointer = arg0;
    printf("self->pointer 0x%p\n\n", arg0);
}

pid$1::LwPromiseCreate:return /arg1 == 0/
{
    this->myVal = *(void**)copyin(self->pointer, 8);
    printf("Allocated pointer:0x%p,  0x%p\n\n", self->pointer, this->myVal);

    i[(void*)this->myVal].rip0 = (void*)uregs[R_RIP];

    this->rbp_1 = *(uint64_t*)(copyin(uregs[R_RBP],8));
    i[(void*)this->myVal].rip1 = *(void**)(copyin(uregs[R_RBP] + 8,8));

    this->rbp_2 = *(uint64_t*)copyin(this->rbp_1,8);
    i[(void*)this->myVal].rip2 = *(void**)copyin(this->rbp_1 + 8,8);

    this->rbp_3 = *(uint64_t*)copyin(this->rbp_2,8);
    i[(void*)this->myVal].rip3 = *(void**)copyin(this->rbp_2 + 8,8);

    /*
    printf("0x%p, 0x%p, 0x%p, 0x%p\n",
        i[(void*)arg1].rip0,
        i[(void*)arg1].rip1,
        i[(void*)arg1].rip2,
        i[(void*)arg1].rip3);
        */

    @clients[i[(void*)this->myVal].rip0,i[(void*)this->myVal].rip1,i[(void*)this->myVal].rip2,i[(void*)this->myVal].rip3] = sum(1);
}

pid$1::LwPromiseFree:entry /arg0 != 0/
{
    @clients[i[(void*)arg0].rip0,i[(void*)arg0].rip1,i[(void*)arg0].rip2,i[(void*)arg0].rip3] = sum(-1);

    printf("Freed 0x%p\n\n", arg0);
    ustack();
}

pid$1::LwPromiseCreate:return
{
    self->pointer = arg0;
}

END
{
    printa("0x%p\n0x%p\n0x%p\n0x%p\n%@d\n\n", @clients);
    trunc(@clients);
}


/*
pid$1:libc.so.7:clnt_dg_create:entry
{
    @[ustack()] = count();
}

pid$1:libc.so.7:clnt_vc_create:entry
{
    @[ustack()] = count();
}*/
