//! Spike: attach to a real QEMU display socket on Windows (protocol version 3), take the
//! section handles QEMU duplicated into this process, map the control block, and import each
//! scanout region into D3D12 as a heap with no CPU copy. Then prove the import by writing a
//! pattern through this process's mapping and reading it back through a GPU copy.
//!
//! usage: qemu-attach SOCKET [--warp]

use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use uds_windows::UnixStream;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D12::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

fn say(k: &str, v: impl std::fmt::Display) {
    println!("{k}={v}");
}
fn u32at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn u64at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

struct Region { id: u32, kind: u32, backend: u32, size: u64, handle: u64 }

fn msg_len(kind: u16) -> Option<usize> {
    match kind { 0x81 => Some(64), 0x82 => Some(56), 0x83 | 0x84 => Some(16), 0x85 => Some(8), _ => None }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let warp = args.iter().any(|a| a == "--warp");
    if let Err(e) = run(&args[1], warp) {
        say("FATAL", e);
        std::process::exit(1);
    }
}

fn run(sock: &str, warp: bool) -> Result<()> {
    let mut s = UnixStream::connect(sock).map_err(|e| Error::new(E_FAIL, format!("connect: {e}")))?;
    say("connected", sock);
    let mut hello = [0u8; 48];
    hello[0..2].copy_from_slice(&1u16.to_le_bytes());
    hello[8..12].copy_from_slice(&3u32.to_le_bytes());
    hello[12..16].copy_from_slice(&4u32.to_le_bytes()); // wants wake-ups; no Vulkan import
    hello[16..20].copy_from_slice(&unsafe { GetCurrentProcessId() }.to_le_bytes());
    s.write_all(&hello).map_err(|e| Error::new(E_FAIL, format!("hello: {e}")))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();

    let mut control_handle = 0u64;
    let mut welcome_backend = 0;
    let mut regions: Vec<Region> = Vec::new();
    loop {
        let mut h = [0u8; 8];
        match s.read_exact(&mut h) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => { say("read", format!("ended: {e}")); break; }
        }
        let ty = u16::from_le_bytes([h[0], h[1]]);
        let Some(len) = msg_len(ty) else { return Err(Error::new(E_FAIL, format!("unknown message {ty:#x}"))) };
        let mut m = vec![0u8; len];
        m[..8].copy_from_slice(&h);
        s.read_exact(&mut m[8..]).map_err(|e| Error::new(E_FAIL, format!("body: {e}")))?;
        match ty {
            0x81 => {
                control_handle = u64at(&m, 56);
                welcome_backend = u32at(&m, 12);
                say("welcome", format!("version={} backend={} nheads={} control_backend={} control_handle={:#x}",
                    u32at(&m, 8), u32at(&m, 12), u32at(&m, 16), u32at(&m, 20), control_handle));
            }
            0x82 => {
                let r = Region { id: u32at(&m, 8), kind: u32at(&m, 12), backend: u32at(&m, 16), size: u64at(&m, 24), handle: u64at(&m, 48) };
                say("region", format!("id={} kind={} backend={} size={} handle={:#x}", r.id, r.kind, r.backend, r.size, r.handle));
                regions.push(r);
            }
            _ => say("message", format!("{ty:#x}")),
        }
    }
    say("welcome_backend", welcome_backend);
    if control_handle == 0 { return Err(Error::new(E_FAIL, "no control block")); }

    unsafe {
        // control block: region 0
        let ctl = MapViewOfFile(HANDLE(control_handle as usize as *mut _), FILE_MAP_READ, 0, 0, 65536);
        if ctl.Value.is_null() { return Err(Error::from_thread()); }
        let cb = std::slice::from_raw_parts(ctl.Value as *const u8, 65536);
        say("control_magic", format!("{:#010x}", u32at(cb, 0)));
        let nheads = u32at(cb, 8);
        say("control_nheads", nheads);
        say("control_qemu_pid", u32at(cb, 20));
        for h in 0..nheads.min(8) as usize {
            let o = 4096 + 4096 * h;
            say(&format!("head{h}"), format!("active={} family={} {}x{} content_gen={}",
                u32at(cb, o), u32at(cb, o + 4), u32at(cb, o + 16), u32at(cb, o + 20), u64at(cb, o + 32)));
        }

        // D3D12
        let factory: IDXGIFactory4 = CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0))?;
        let adapter: IDXGIAdapter = if warp { factory.EnumWarpAdapter::<IDXGIAdapter>()? } else { factory.EnumAdapters(0)? };
        say("adapter", String::from_utf16_lossy(&adapter.GetDesc()?.Description).trim_end_matches('\0'));
        let mut dev: Option<ID3D12Device> = None;
        D3D12CreateDevice(&adapter, D3D_FEATURE_LEVEL_11_0, &mut dev)?;
        let dev = dev.unwrap();
        let dev3: ID3D12Device3 = dev.cast()?;
        let queue: ID3D12CommandQueue = dev.CreateCommandQueue(&D3D12_COMMAND_QUEUE_DESC { Type: D3D12_COMMAND_LIST_TYPE_DIRECT, ..Default::default() })?;
        let alloc: ID3D12CommandAllocator = dev.CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT)?;
        let list: ID3D12GraphicsCommandList = dev.CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, &alloc, None)?;
        list.Close()?;
        let fence: ID3D12Fence = dev.CreateFence(0, D3D12_FENCE_FLAG_NONE)?;
        let event = CreateEventW(None, false, false, PCWSTR::null())?;
        let mut fv = 0u64;

        for r in regions.iter().filter(|r| (1..=3).contains(&r.kind)) {
            let hnd = HANDLE(r.handle as usize as *mut _);
            let tag = format!("region{}", r.id);
            if r.backend != 4 { say(&tag, format!("backend {} is not SHM_WIN32, skipped", r.backend)); continue; }
            let view = MapViewOfFile(hnd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            if view.Value.is_null() { say(&tag, format!("MapViewOfFile FAILED {}", Error::from_thread())); continue; }
            let size = r.size as usize;
            let mem = std::slice::from_raw_parts_mut(view.Value as *mut u8, size);
            for (i, b) in mem.iter_mut().take(1 << 20).enumerate() { *b = (i as u8).wrapping_mul(31).wrapping_add(7); }
            let heap: ID3D12Heap = match dev3.OpenExistingHeapFromFileMapping(hnd) {
                Ok(h) => h,
                Err(e) => { say(&format!("{tag}_open_heap"), format!("FAILED {e}")); continue; }
            };
            say(&format!("{tag}_open_heap"), format!("ok size={}", heap.GetDesc().SizeInBytes));
            let desc = D3D12_RESOURCE_DESC {
                Dimension: D3D12_RESOURCE_DIMENSION_BUFFER, Alignment: 0, Width: r.size, Height: 1, DepthOrArraySize: 1,
                MipLevels: 1, Format: DXGI_FORMAT_UNKNOWN, SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                Layout: D3D12_TEXTURE_LAYOUT_ROW_MAJOR, Flags: D3D12_RESOURCE_FLAG_ALLOW_CROSS_ADAPTER };
            let mut buf: Option<ID3D12Resource> = None;
            if let Err(e) = dev.CreatePlacedResource(&heap, 0, &desc, D3D12_RESOURCE_STATE_COMMON, None, &mut buf) {
                say(&format!("{tag}_placed_buffer"), format!("FAILED {e}")); continue;
            }
            let buf = buf.unwrap();
            let rb_desc = D3D12_RESOURCE_DESC { Flags: D3D12_RESOURCE_FLAG_NONE, ..desc };
            let mut rb: Option<ID3D12Resource> = None;
            dev.CreateCommittedResource(&D3D12_HEAP_PROPERTIES { Type: D3D12_HEAP_TYPE_READBACK, ..Default::default() },
                D3D12_HEAP_FLAG_NONE, &rb_desc, D3D12_RESOURCE_STATE_COPY_DEST, None, &mut rb)?;
            let rb = rb.unwrap();
            alloc.Reset()?;
            list.Reset(&alloc, None)?;
            list.CopyBufferRegion(&rb, 0, &buf, 0, 1 << 20);
            list.Close()?;
            let l: ID3D12CommandList = list.cast()?;
            queue.ExecuteCommandLists(&[Some(l)]);
            fv += 1;
            queue.Signal(&fence, fv)?;
            fence.SetEventOnCompletion(fv, event)?;
            WaitForSingleObject(event, 10_000);
            let mut p: *mut std::ffi::c_void = std::ptr::null_mut();
            rb.Map(0, None, Some(&mut p))?;
            let got = std::slice::from_raw_parts(p as *const u8, 1 << 20);
            let bad = got.iter().zip(mem.iter()).filter(|(a, b)| a != b).count();
            rb.Unmap(0, None);
            say(&format!("{tag}_gpu_readback_mismatching_bytes_of_1MiB"), bad);
            let _ = ManuallyDrop::new(0);
        }
    }
    Ok(())
}
