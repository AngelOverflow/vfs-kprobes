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
helpers::{
bpf_get_current_comm,
bpf_ktime_get_ns,
bpf_get_current_pid_tgid,
bpf_probe_read_kernel_buf,
bpf_probe_read_kernel_str_bytes,
bpf_probe_read_kernel,
},
maps::{HashMap, PerfEventArray},
check_bounds_signed,
};

use aya_log_ebpf::info;

use vmlinux::{
    file,
    path,
    dentry,
    __kernel_size_t,
    inode,
    qstr,
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
pub fn trace_entry(ctx: ProbeContext, access_type: AccessType, dentry: *const dentry, inode: *const inode, bytes: __kernel_size_t) -> Result<i64, i64> {
    let comm: [i8; 16] = comm_to_i8_array(bpf_get_current_comm().unwrap());


    if comm != [111, 119, 108, 121, 115, 104, 105, 101, 108, 100, 95, 114, 97, 110, 115, 0] {
        let ns: u64 = unsafe { bpf_ktime_get_ns() };
        let pid_tgid: u64 = bpf_get_current_pid_tgid();
        let i_mode: u16 = unsafe {bpf_probe_read_kernel(&(*inode).i_mode).map_err(|e: i64| e)?};


        if (((i_mode) & S_IFMT) == S_IFDIR) || (((i_mode) & S_IFMT) == S_IFREG) || (((i_mode) & S_IFMT) == S_IFLNK) {
            let access: Access = match access_type {
                AccessType::Write => Access::Write(bytes as usize),
                AccessType::Read => Access::Read(bytes as usize),
                AccessType::Unlink => Access::Unlink(0usize),
                AccessType::Rmdir => Access::Rmdir(0usize),
                AccessType::Symlink => Access::Symlink(0usize),
                AccessType::Mkdir => Access::Mkdir(0usize),
                AccessType::Create => Access::Create(0usize),
                AccessType::Rename => Access::Rename(0usize),
            };
            let fileaccess: FileAccess = FileAccess {
                ns,
                ino: unsafe{bpf_probe_read_kernel(&(*inode).i_ino).map_err(|e: i64| e)?},
                fsize: unsafe{bpf_probe_read_kernel(&(*inode).i_size).map_err(|e: i64| e)?},
                entropy: 0f64, // must be implemented
                pid: pid_tgid,
                access: access,
                comm: comm,
            };

            return dentry_to_path(ctx,dentry,ns,1,&fileaccess) // returns Result
        }
    }
    Ok(0i64)
}



// KPROBES
// vfs_read vfs_write vfs_unlink vfs_rmdir vfs_symlink vfs_mkdir vfs_create vfs_rename

/*
List of struct fields I need :
    dentry : d_name, d_parent
    inode : i_mode, i_ino, i_size
*/

// VFS_READ
#[kprobe(name = "vfs_read")]
pub fn vfs_read(ctx: ProbeContext) -> i64 {
    match try_vfs_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}


fn try_vfs_read(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_read called");

    let file: *const file = ctx.arg::<*const file>(0).ok_or(1i64)?;
    let path: *const path = &unsafe {bpf_probe_read_kernel(&(*file).f_path).map_err(|e: i64| e)? };
    let dentry: *const dentry = unsafe { bpf_probe_read_kernel(&(*path).dentry).map_err(|e: i64| e)? };
    let bytes: u64 = ctx.arg::<__kernel_size_t>(2).ok_or(1i64)?;
    let inode: *const inode = unsafe {bpf_probe_read_kernel(&(*dentry).d_inode).map_err(|e: i64| e)?};
    trace_entry(ctx, AccessType::Read, dentry, inode, bytes)
}


// VFS_WRITE
#[kprobe(name = "vfs_write")]
pub fn vfs_write(ctx: ProbeContext) -> i64 {
    match try_vfs_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}


fn try_vfs_write(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_write called");

    let file: *const file = ctx.arg::<*const file>(0).ok_or(1i64)?;
    let path: *const path = &unsafe {bpf_probe_read_kernel(&(*file).f_path).map_err(|e: i64| e)? };
    let dentry: *const dentry = unsafe { bpf_probe_read_kernel(&(*path).dentry).map_err(|e: i64| e)? };
    let bytes: u64 = ctx.arg::<__kernel_size_t>(2).ok_or(1i64)?;
    let inode: *const inode = unsafe {bpf_probe_read_kernel(&(*dentry).d_inode).map_err(|e: i64| e)?};
    trace_entry(ctx, AccessType::Read, dentry, inode, bytes)
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
pub static mut FILEPATHS_MAP: HashMap<u64, [u8; 1024]> = HashMap::with_max_entries(64, 0);


#[map]
pub static mut FILEACCESSES: PerfEventArray<[u8; 1024]> = PerfEventArray::with_max_entries(1024, 0);






#[inline]
pub fn dentry_to_path(ctx:ProbeContext, dentry: *const dentry, ns: u64, _order: u8, fileaccess: &FileAccess) -> Result<i64, i64> {
    // order needs to be implemented

    let mut i: usize = 0usize;
    let mut de: *const dentry = dentry;


    let pid_tgid:u64 = fileaccess.pid;


    unsafe {

        if FILEPATHS_MAP.get(&pid_tgid).is_none() {
            FILEPATHS_MAP.insert(&pid_tgid, &[0u8;1024], 0).unwrap();
        }


        let u8_array: [u8; FILE_ACCESS_SIZE] = fileaccess.to_u8_array();


        let buf: &mut [u8; 1024] = {
            let ptr: *mut [u8; 1024] = FILEPATHS_MAP.get_ptr_mut(&pid_tgid).ok_or(0)?;
            &mut *ptr
        };


        let mut offset: i64 = 0i64;
        let ret: Result<(), i64> = unsafe {
            bpf_probe_read_kernel_buf(
            u8_array.as_ptr(),
            &mut buf[offset as usize..offset as usize + FILE_ACCESS_SIZE],
            )
        };


        // Handle potential errors
        if let Err(err) = ret {
            return Err(err);
        }


        offset += FILE_ACCESS_SIZE as i64;


        // Add the slash before each directory entry except the first
        if offset != 0 {
            let tmp: usize = offset as usize - 1;
            // To not trigger the verifier :
            if check_bounds_signed(tmp as i64, 0, 1024) {
                buf[tmp] = b'/';
                offset+=1;
            }
        }

        loop {

            let d_name: qstr = unsafe {bpf_probe_read_kernel(&(*de).d_name).map_err(|e: i64| e)?};
            let i_name: *const u8 = d_name.name;

            if offset < 0 {
                break;
            }
            
            let name_len= unsafe {
                bpf_probe_read_kernel_str_bytes(
                    i_name,
                    &mut buf[offset as usize..offset as usize + 32usize],
                    )
                    .unwrap()
                    .len()
            };


            // Add the slash before each directory entry except the first
            if offset != 0 {
                let tmp: usize = offset as usize - 1;
                // To not trigger the verifier :
                if check_bounds_signed(tmp as i64, 0, 1024) {
                    buf[tmp] = b'/';
                    offset+=1;
                }                      
            }


            offset += name_len as i64;


            i += 1;


            let parent: *const dentry = unsafe {bpf_probe_read_kernel(&(*de).d_parent).map_err(|e: i64| e)?};
            if parent.is_null() || i == PATH_LIST_LEN {
                break;
            } else {
                de = parent;
            }
        }
        
        unsafe {
            FILEACCESSES.output(&ctx, buf, 0);
            FILEPATHS_MAP.remove(&ns)?;
        }

    }
    Ok(0i64)
}


fn entropy(ptr: *const u8, len: usize) -> f64 {
    let mut freqs = [0; 32];
    unsafe {
        for i in 0..len {
            let byte = *ptr.offset(i as isize);
            let idx = (byte >> 3) as usize;
            let shift = (byte & 0x07) as usize;
            freqs[idx] |= 1 << shift;
        }
    }
    let mut entropy = 0.0;
    let len = len as f64;
    for i in 0..256 {
        let byte = i as u8;
        let idx = (byte >> 3) as usize;
        let shift = (byte & 0x07) as usize;
        let count = (freqs[idx] >> shift) & 1;
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p ; // (p.log2());
        }
    }
    entropy
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}