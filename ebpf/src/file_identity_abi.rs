//! Runtime file-object layout shared by the loader and kernel programs.

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileIdentityOffsets {
    /// Zero disables every read. Set only after the complete layout validates.
    pub enabled: u32,
    pub task_files: u32,
    pub files_fdt: u32,
    pub fdtable_max_fds: u32,
    pub fdtable_fd: u32,
    pub file_inode: u32,
    pub dentry_inode: u32,
    pub inode_ino: u32,
    pub inode_sb: u32,
    pub super_block_dev: u32,
    pub renamedata_old_dentry: u32,
}
