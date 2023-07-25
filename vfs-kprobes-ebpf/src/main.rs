#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;


use aya_bpf::{
    macros::{kprobe,map}, 
    programs::ProbeContext,
    helpers::{bpf_get_current_comm, bpf_ktime_get_ns, bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes},
    maps::{HashMap, PerfEventArray},
    //cty::c_void,
};

use aya_log_ebpf::info;

use vmlinux::{
    file,
    path,
    dentry,
    __kernel_size_t,
    inode,
};

mod mod_file;
use mod_file::*;





const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;
const S_IFDIR: u16 = 0o0040000;
const S_IFLNK: u16 = 0o0120000;

#[derive(PartialEq, Eq)]
pub enum AccessType {
    Read,
    Write,
    Unlink,
    Rmdir,
    Mkdir,
    Symlink,
    Create,
    Rename,
}


#[inline(always)]
pub fn trace_entry(ctx: ProbeContext, access_type: AccessType, dentry: &dentry, inode: &inode, bytes: __kernel_size_t, pid_tgid: u64) {
    
    let comm: [i8; 16] = comm_to_i8_array(bpf_get_current_comm().unwrap());

    
    if comm != [111, 119, 108, 121, 115, 104, 105, 101, 108, 100, 95, 114, 97, 110, 115, 0] {
        
        let ns = unsafe { bpf_ktime_get_ns() };
        let pid_tgid: u64 = bpf_get_current_pid_tgid();

        let i_mode = inode.i_mode;

        if (((i_mode) & S_IFMT) == S_IFDIR) || (((i_mode) & S_IFMT) == S_IFREG) || (((i_mode) & S_IFMT) == S_IFLNK) {
            let access = match access_type {
                AccessType::Write => Access::Write(bytes as usize),
                AccessType::Read => Access::Read(bytes as usize),
                AccessType::Unlink => Access::Unlink(0usize),
                AccessType::Rmdir => Access::Rmdir(0usize),
                AccessType::Symlink => Access::Symlink(0usize),
                AccessType::Mkdir => Access::Mkdir(0usize),
                AccessType::Create => Access::Create(0usize),
                AccessType::Rename => Access::Rename(0usize),
            };

            let fileaccess = FileAccess {
                ns,
                ino: inode.i_ino,
                fsize: inode.i_size,
                entropy: 0f64,
                pid: pid_tgid,
                access: access,
                comm: comm,
            };
            
            dentry_to_path(ctx,dentry,ns,1,&fileaccess, pid_tgid);
        }
    }
}



// KPROBES
// vfs_read vfs_write vfs_unlink vfs_rmdir vfs_symlink vfs_mkdir vfs_create vfs_rename

// VFS_READ
#[kprobe(name = "vfs_read")]
pub fn vfs_read(ctx: ProbeContext) -> u32 {
    match try_vfs_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_read(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_read called");

    let file: &file = unsafe { ctx.arg::<*const file>(0).ok_or(1).unwrap().as_ref().unwrap() };
    let path: path = file.f_path;
    let dentry: &dentry = unsafe {path.dentry.as_ref().unwrap()};
    let bytes : __kernel_size_t = ctx.arg(2).ok_or(1).unwrap();
    let inode: &inode = unsafe {dentry.d_inode.as_ref().unwrap()};
    
    let pid_tgid: u64 = bpf_get_current_pid_tgid();
    
    trace_entry(ctx, AccessType::Read, &dentry, &inode, bytes, pid_tgid);

    Ok(0)
}


// VFS_WRITE
#[kprobe(name = "vfs_write")]
pub fn vfs_write(ctx: ProbeContext) -> u32 {
    match try_vfs_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_write(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_write called");

    let file: &file = unsafe { ctx.arg::<*const file>(0).ok_or(1).unwrap().as_ref().unwrap() };
    let path: path = file.f_path;
    let dentry: &dentry = unsafe {path.dentry.as_ref().unwrap()};
    let bytes : __kernel_size_t = ctx.arg(2).ok_or(1).unwrap();
    let inode: &inode = unsafe {dentry.d_inode.as_ref().unwrap()};

    let pid_tgid: u64 = bpf_get_current_pid_tgid();

    unsafe {
        if filepaths_map.get(&pid_tgid).is_none() {
            info!(&ctx, "test");
            filepaths_map.insert(&pid_tgid, &[0u8;1024], 0).unwrap();
        }
    }
    

    trace_entry(ctx, AccessType::Write, &dentry, &inode, bytes, pid_tgid);
    
    Ok(0)
}


// VFS_UNLLINK
#[kprobe(name = "vfs_unlink")]
pub fn vfs_unlink(ctx: ProbeContext) -> u32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_unlink called");
    Ok(0)
}


// VFS_RMDIR
#[kprobe(name = "vfs_rmdir")]
pub fn vfs_rmdir(ctx: ProbeContext) -> u32 {
    match try_vfs_rmdir(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_rmdir(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_rmdir called");
    Ok(0)
}


// VFS_SYMLINK
#[kprobe(name = "vfs_symlink")]
pub fn vfs_symlink(ctx: ProbeContext) -> u32 {
    match try_vfs_symlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_symlink(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_symlink called");
    Ok(0)
}


// VFS_MKDIR
#[kprobe(name = "vfs_mkdir")]
pub fn vfs_mkdir(ctx: ProbeContext) -> u32 {
    match try_vfs_mkdir(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_mkdir(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_mkdir called");
    Ok(0)
}


// VFS_CREATE
#[kprobe(name = "vfs_create")]
pub fn vfs_create(ctx: ProbeContext) -> u32 {
    match try_vfs_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_create(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_create called");
    Ok(0)
}


// VFS_RENAME
#[kprobe(name = "vfs_rename")]
pub fn vfs_rename(ctx: ProbeContext) -> u32 {
    match try_vfs_rename(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_rename(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_rename called");
    Ok(0)
}


// MAPS

#[map]
pub static mut filepaths_map: HashMap<u64, [u8; 1024]> = HashMap::with_max_entries(64, 0);

#[map] // Not sure about PerfEventArray to instead of PerfMap from redbpf
pub static mut fileaccesses: PerfEventArray<[u8; 1024]> = PerfEventArray::with_max_entries(1024, 0);




#[inline]
pub fn dentry_to_path(ctx:ProbeContext, dentry: &dentry, ns: u64, order: u8, fileaccess: &FileAccess, pid_tgid: u64) {
    
    let mut i = 0usize;
    let mut de = dentry;

    // I added pid_tgid in try_vfs_... because it triggers the eBPF verifier when called in dentry_to_path.
    //let pid_tgid: u64 = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32; // Not used

    unsafe {

        
        if filepaths_map.get(&pid_tgid).is_none() {
            filepaths_map.insert(&pid_tgid, &[0u8;1024], 0).unwrap();
        }

         
        let u8_array = fileaccess.to_u8_array();

        let mut buf = filepaths_map.get_ptr_mut(&pid_tgid).unwrap();

        let mut offset = 0i64;

        let ret = unsafe {
            bpf_probe_read_kernel_buf(
                u8_array.as_ptr(),
                &mut (*buf)[offset as usize..offset as usize + FILE_ACCESS_SIZE],
                )
        };


        offset += FILE_ACCESS_SIZE as i64;

        // Add the slash before each directory entry except the first
        if offset != 0 {
            let tmp = offset-1;
            (*buf)[tmp as usize] = b'/';
        }

        loop {
            let i_name = de.d_name.name;

            if offset < 0 {
                break;
            }


            let name_len = unsafe {
                bpf_probe_read_kernel_str_bytes(
                    i_name,
                    &mut (*buf)[offset as usize..offset as usize + 32],
                )
                .unwrap()
                .len() as i64
            };

            // Add the slash before each directory entry except the first
            if offset != 0 {
                let tmp = offset-1;
                (*buf)[tmp as usize] = b'/';
            }

            offset += name_len;

            i += 1;
            let parent = de.d_parent;
            if parent.is_null() || i == PATH_LIST_LEN {
                break;
            } else {
                de = unsafe { &(*parent) };
            }
        }

        
        unsafe {
            fileaccesses.output(&ctx, &(*buf), 0);
            filepaths_map.remove(&ns);
        }

    }
}





#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}