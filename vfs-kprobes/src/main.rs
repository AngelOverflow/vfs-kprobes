use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/vfs-kprobes"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/vfs-kprobes"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    
    
    // KPROBES
    // vfs_read vfs_write vfs_unlink vfs_rmdir vfs_symlink vfs_mkdir vfs_create vfs_rename

    let program_vfs_read: &mut KProbe = bpf.program_mut("vfs_read").unwrap().try_into()?;
    program_vfs_read.load()?;
    program_vfs_read.attach("vfs_read", 0)?;

    let program_vfs_write: &mut KProbe = bpf.program_mut("vfs_write").unwrap().try_into()?;
    program_vfs_write.load()?;
    program_vfs_write.attach("vfs_write", 0)?;

    let program_vfs_unlink: &mut KProbe = bpf.program_mut("vfs_unlink").unwrap().try_into()?;
    program_vfs_unlink.load()?;
    program_vfs_unlink.attach("vfs_unlink", 0)?;

    let program_vfs_rmdir: &mut KProbe = bpf.program_mut("vfs_rmdir").unwrap().try_into()?;
    program_vfs_rmdir.load()?;
    program_vfs_rmdir.attach("vfs_rmdir", 0)?;

    let program_vfs_symlink: &mut KProbe = bpf.program_mut("vfs_symlink").unwrap().try_into()?;
    program_vfs_symlink.load()?;
    program_vfs_symlink.attach("vfs_symlink", 0)?;

    let program_vfs_mkdir: &mut KProbe = bpf.program_mut("vfs_mkdir").unwrap().try_into()?;
    program_vfs_mkdir.load()?;
    program_vfs_mkdir.attach("vfs_mkdir", 0)?;

    let program_vfs_create: &mut KProbe = bpf.program_mut("vfs_create").unwrap().try_into()?;
    program_vfs_create.load()?;
    program_vfs_create.attach("vfs_create", 0)?;

    let program_vfs_rename: &mut KProbe = bpf.program_mut("vfs_rename").unwrap().try_into()?;
    program_vfs_rename.load()?;
    program_vfs_rename.attach("vfs_rename", 0)?;


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}