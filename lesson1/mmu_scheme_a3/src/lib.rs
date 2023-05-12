#![no_std]
#![feature(asm_const)]
#![feature(strict_provenance)]
use riscv::register::satp;

pub const KERNEL_BASE: usize = 0xffff_ffff_c000_0000;

const PHYS_VIRT_OFFSET: usize = 0xffff_ffc0_0000_0000;

pub type PageTable = [usize; 512];

// Entry per Page: PageSize / PtrSize
const EPP: usize = 512;
const PAGE_SIZE: usize = 1 << 12;

#[link_section = ".data.boot_page_table"]
static mut BOOT_PT_ROOT: [usize; 512] = [0; 512];

const VPN_MASK: usize = (1 << 9) - 1;

/// SV39:
/// - idx: VPN[idx], i.g., 2,1,0.
pub fn get_vpn(va: usize, idx: usize) -> usize {
    // println!("va:   {:#064b}", va);
    let mask = VPN_MASK << (idx * 9 + 12);
    // println!("mask: {:#064b}", mask);
    let vpn = va & mask;
    vpn >> (idx * 9 + 12)
}

/// SV39:
/// - 1GiB, 2MiB, 4KiB
///  SV39:
/// - 512GiB, 1GiB, 2MiB, 4KiB
pub unsafe fn _boot_map<F1, F2>(
    table: &mut PageTable,
    max_level: usize,
    level: usize,
    va: usize,
    pa: usize,
    len: usize,
    prot: usize,
    alloc_page: &mut F1,
    phys_to_virt: &F2,
) -> Result<(), ()>
where
    F1: FnMut() -> *mut PageTable,
    F2: Fn(usize) -> *mut PageTable,
{
    // TODO: Assert len > 0
    let mut start = va;
    // TODO: 4K Align
    let end = va.checked_add(len).unwrap_or(usize::MAX);

    // PAGE_SIZE(1 << 12) * (1 << 9)^(MMU_LEVELS - level - 1)
    let current_page_size = PAGE_SIZE << ((max_level - level - 1) * 9);
    // println!("page_size: {} MiB", current_page_size / 1024 / 1024);

    let is_leaf = len == current_page_size;

    for i in (start..end).step_by(current_page_size) {
        let vpn = get_vpn(start, max_level - level - 1);
        if is_leaf {
            // init leaf page
            // println!("table[{:#x}]: {:#x}", vpn, pa | prot);
            table[vpn] = pa | prot;
        } else {
            if table[vpn] & 0x01 == 0x01 {
                let next_level_addr = table[vpn];
                let next_level = phys_to_virt(next_level_addr);
                // println!(
                //     "update table[{:#x}]: {:#x} ({:#x}) (non-leaf)",
                //     vpn,
                //     next_level.addr(),
                //     table[vpn]
                // );
                _boot_map(
                    &mut *next_level,
                    max_level,
                    level + 1,
                    start,
                    pa,
                    current_page_size / EPP,
                    prot,
                    alloc_page,
                    phys_to_virt,
                )?;
            } else {
                let next_level = alloc_page();
                let next_level_ptr = next_level.addr() >> 12;
                table[vpn] = next_level_ptr << 10 | 0x01;
                // println!(
                //     "add table[{:#x}]: {:#x} ({:#x}) (non-leaf)",
                //     vpn,
                //     next_level.addr(),
                //     table[vpn]
                // );
                _boot_map(
                    &mut *next_level,
                    max_level,
                    level + 1,
                    start,
                    pa,
                    current_page_size / EPP,
                    prot,
                    alloc_page,
                    phys_to_virt,
                )?;
            }
        }
        start = start.checked_add(current_page_size).unwrap_or(usize::MAX);
    }

    Ok(())
}

#[link_section = ".data.boot_page_table"]
static mut pages: [PageTable; 5] = [[0; 512]; 5];
static mut next_page_id: usize = 0;

fn phys_to_virt(pa: usize) -> *mut PageTable {
    unsafe {
        for (i, _) in pages.iter().enumerate() {
            let raw = pages.as_ptr().add(i);
            if (raw.addr() >> 12) << 10 == (pa >> 10) << 10 {
                return raw as *mut PageTable;
            }
        }
        unreachable!("not found")
    }
}

fn alloc_page() -> *mut PageTable {
    let page = unsafe { pages.as_ptr().add(next_page_id) };
    unsafe {
        // println!("alloc page, current idx: {}", next_page_id);
        next_page_id += 1;
    };

    page as *mut PageTable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_page() {
        let p0 = alloc_page();
        let p1 = alloc_page();
        assert_ne!(p0.addr(), p1.addr());
    }

    #[test]
    fn test_phys_to_virt() {
        let page = alloc_page();
        let pa = (page.addr() >> 12) << 10;

        assert_eq!(page.addr(), phys_to_virt(pa).addr())
    }

    #[test]
    fn test() {
        assert_eq!(4096 * 512 * 512, 0xc000_0000 - 0x8000_0000usize);
        assert_eq!(4096 * 512 * 512, usize::MAX - 0xffff_ffff_c000_0000);
    }

    #[test]
    fn test_boot_map_sv39() {
        for (va, vpn) in [
            (0x0000_0000_8000_0000usize, 2usize),
            (0xffff_ffc0_8000_0000, 0x102),
            (0xffff_ffff_c000_0000, 0x1ff),
        ] {
            let mut root: PageTable = [0; 512];
            unsafe {
                _boot_map(
                    &mut root,
                    3,
                    0,
                    va,
                    0x80000 << 10,
                    4096 * 512 * 512,
                    0xef,
                    &mut alloc_page,
                    &phys_to_virt,
                )
                .unwrap();
            }

            assert_eq!(root[vpn], (0x80000 << 10) | 0xef);
            unsafe {
                assert_eq!(next_page_id, 0);
            }
        }
    }

    #[test]
    fn test_boot_map_sv48() {
        let mut root: PageTable = [0; 512];
        for (va, vpn) in [
            (0x0000_0000_8000_0000usize, 0usize),
            (0xffff_ffc0_8000_0000, 0x1ff),
            (0xffff_ffff_c000_0000, 0x1ff),
        ] {
            unsafe {
                _boot_map(
                    &mut root,
                    4,
                    0,
                    va,
                    0x80000 << 10,
                    4096 * 512 * 512,
                    0xef,
                    &mut alloc_page,
                    &phys_to_virt,
                )
                .unwrap();
            }

            assert_ne!(root[vpn], 0);
        }
    }

    #[test]
    fn test_current_page_size() {
        assert_eq!(PAGE_SIZE << (3 * 9), PAGE_SIZE * 512 * 512 * 512);
        assert_eq!(PAGE_SIZE << (2 * 9), PAGE_SIZE * 512 * 512);
    }

    #[test]
    fn test_get_vpn() {
        // SV39
        // level 0
        assert_eq!(get_vpn(0x8000_0000, 2), 2);
        assert_eq!(get_vpn(0xffff_ffc0_8000_0000, 2), 0x102);
        assert_eq!(get_vpn(0xffff_ffff_c000_0000, 2), 0x1ff);

        // SV48
        // level 0
        assert_eq!(get_vpn(0x8000_0000, 3), 0);
        assert_eq!(get_vpn(0xffff_ffc0_8000_0000, 3), 0x1ff);
        assert_eq!(get_vpn(0xffff_ffff_c000_0000, 3), 0x1ff);
        // level 1 is same as Sv39 level 0
    }
}

#[cfg(any(feature = "sv39"))]
pub unsafe fn pre_mmu() {
    for va in [
        0x0000_0000_8000_0000usize,
        0xffff_ffc0_8000_0000,
        0xffff_ffff_c000_0000,
    ] {
        unsafe {
            _boot_map(
                &mut BOOT_PT_ROOT,
                3,
                0,
                va,
                0x80000 << 10,
                4096 * 512 * 512,
                0xef,
                &mut alloc_page,
                &phys_to_virt,
            )
            .unwrap();
        }
    }
}

#[cfg(any(feature = "sv39"))]
pub unsafe fn enable_mmu() {
    let page_table_root = BOOT_PT_ROOT.as_ptr() as usize;
    satp::set(satp::Mode::Sv39, 0, page_table_root >> 12);
    riscv::asm::sfence_vma_all();
}

#[cfg(any(feature = "sv48"))]
pub unsafe fn pre_mmu() {
    for va in [
        0x0000_0000_8000_0000usize,
        0xffff_ffc0_8000_0000,
        0xffff_ffff_c000_0000,
    ] {
        unsafe {
            _boot_map(
                &mut BOOT_PT_ROOT,
                4,
                0,
                va,
                0x80000 << 10,
                4096 * 512 * 512,
                0xef,
                &mut alloc_page,
                &phys_to_virt,
            )
            .unwrap();
        }
    }
}

#[cfg(any(feature = "sv48"))]
pub unsafe fn enable_mmu() {
    let page_table_root = BOOT_PT_ROOT.as_ptr() as usize;
    satp::set(satp::Mode::Sv48, 0, page_table_root >> 12);
    riscv::asm::sfence_vma_all();
}

pub unsafe fn post_mmu() {
    core::arch::asm!("
        li      t0, {phys_virt_offset}  // fix up virtual high address
        add     sp, sp, t0
        add     ra, ra, t0
        ret     ",
        phys_virt_offset = const PHYS_VIRT_OFFSET,
    )
}
