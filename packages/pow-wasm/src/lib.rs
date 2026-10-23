//! Equi-X (Tor の PoW) を Wasm に出すだけの薄い層。
//! wasm-bindgen を使わず、線形メモリの上のバッファを C ABI で受け渡す。

use equix::{EquiX, SolutionByteArray};

static mut BUF: [u8; 4096] = [0u8; 4096];

/// 受け渡し用バッファの先頭アドレス
#[no_mangle]
pub extern "C" fn buf_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(BUF) as *mut u8
}

/// BUF[0..len] を challenge として解き、解を BUF[len..] に 16 バイトずつ書く。返り値は解の数 (失敗は 0xffffffff)
#[no_mangle]
pub extern "C" fn solve(len: u32) -> u32 {
    let len = len as usize;
    if len > 1024 { return u32::MAX; }
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let challenge = buf[..len].to_vec();
    let eq = match EquiX::new(&challenge) { Ok(e) => e, Err(_) => return u32::MAX };
    let sols = eq.solve();
    let mut n = 0u32;
    for (i, s) in sols.iter().enumerate() {
        let off = len + i * 16;
        if off + 16 > buf.len() { break; }
        let bytes: SolutionByteArray = s.to_bytes();
        buf[off..off + 16].copy_from_slice(&bytes);
        n += 1;
    }
    n
}

/// BUF[0..len] が challenge、BUF[len..len+16] が解。正しければ 1
#[no_mangle]
pub extern "C" fn verify(len: u32) -> u32 {
    let len = len as usize;
    if len > 1024 { return 0; }
    let buf = unsafe { &*core::ptr::addr_of!(BUF) };
    let mut sol = [0u8; 16];
    sol.copy_from_slice(&buf[len..len + 16]);
    match equix::verify_bytes(&buf[..len], &sol) { Ok(()) => 1, Err(_) => 0 }
}
