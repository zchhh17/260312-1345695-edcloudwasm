#![no_std]
#[cfg(not(test))]
use core::panic::PanicInfo;

// ==========================================
// 内存布局与全局状态 (紧凑版)
// ==========================================

/// RESULT 槽位分配 (WASM 与 JS 共享的 32 个状态标志/返回值):
/// --- 全局配置区域 ---
/// [0]: 是否启用 VLESS UUID 验证 (1为启用)
/// [1]: 是否启用 Trojan 密码 Hash 验证 (1为启用)
/// [2]: 启用的 HTTP 认证字符串长度
/// [3]: 启用的 SOCKS5 认证包长度 (SOCKS5_AUTH 缓冲区中有效数据的长度)
/// [4]: SOCKS5 下一步状态 (0: 无/初始, 1: 等待认证, 2: 等待请求)
/// [14]: 是否还需要更多协议头数据 (0:不需要, 1:需要)
///
/// --- 协议解析结果 (每次 parseProtocolWasm 后更新) ---
/// [5]: 目标地址类型 (1: IPv4, 3: 域名, 4: IPv6)
/// [6]: 目标端口号
/// [7]: 真实数据偏移量 (协议头之后的 payload 起始位置)
/// [8]: 是否为 DNS 请求 (目标端口为 53 则是)
/// [9]: 目标地址在 COMMON_BUF 中的起始索引
/// [10]: 目标地址的长度
/// [11]: 识别到的协议 ID (0: VLESS, 1: Trojan, 2: Shadowsocks, 3: HTTP, 4: SOCKS5)
/// [12]: 需要发送给客户端的握手回包长度 (如 HTTP 200 OK 或 VLESS 的响应)
///
/// --- URL 解析结果 (parseUrlWasm 后更新) ---
/// [15]: Socks5 参数偏移, [16]: Socks5 参数长度
/// [17]: Http 参数偏移,   [18]: Http 参数长度
/// [19]: Nat64 参数偏移,  [20]: Nat64 参数长度
/// [21]: IP 参数偏移,     [22]: IP 参数长度
/// [23]: 是否为全局代理模式 (ProxyAll)
/// [24]: Turn 参数偏移,   [25]: Turn 参数长度
static mut RESULT: [i32; 32] = [0; 32];

static mut COMMON_BUF: [u8; 1024] = [0; 1024]; // 1KB 通用数据缓冲区
static mut UUID: [u8; 16] = [0; 16]; // VLESS UUID
static mut HASH: [u8; 56] = [0; 56]; // Trojan Hash
static mut HTTP_AUTH: [u8; 256] = [0; 256]; // HTTP Auth (Base64) - 256 字节
static mut SOCKS5_AUTH: [u8; 256] = [0; 256]; // SOCKS5 Auth Packet (Raw bytes) - 256 字节

// 预编译打包的 Web 页面资源
static PANEL_HTML: &[u8] = include_bytes!("index.html.gz");
static ERROR_HTML: &[u8] = include_bytes!("404.html.gz");

// ==========================================
// 导出函数
// ==========================================

#[no_mangle]
pub unsafe extern "C" fn getResultPtr() -> *const i32 {
    core::ptr::addr_of!(RESULT) as *const i32
}
#[no_mangle]
pub unsafe extern "C" fn getDataPtr() -> *const u8 {
    core::ptr::addr_of!(COMMON_BUF) as *const u8
}
#[no_mangle]
pub unsafe extern "C" fn getUuidPtr() -> *const u8 {
    core::ptr::addr_of!(UUID) as *const u8
}
#[no_mangle]
pub unsafe extern "C" fn getHttpAuthPtr() -> *const u8 {
    core::ptr::addr_of!(HTTP_AUTH) as *const u8
}
#[no_mangle]
pub unsafe extern "C" fn getSocks5AuthPtr() -> *const u8 {
    core::ptr::addr_of!(SOCKS5_AUTH) as *const u8
}

#[no_mangle]
pub unsafe extern "C" fn getPanelHtmlPtr() -> *const u8 {
    PANEL_HTML.as_ptr()
}
#[no_mangle]
pub unsafe extern "C" fn getPanelHtmlLen() -> i32 {
    PANEL_HTML.len() as i32
}
#[no_mangle]
pub unsafe extern "C" fn getErrorHtmlPtr() -> *const u8 {
    ERROR_HTML.as_ptr()
}
#[no_mangle]
pub unsafe extern "C" fn getErrorHtmlLen() -> i32 {
    ERROR_HTML.len() as i32
}

#[no_mangle]
pub unsafe extern "C" fn setHttpAuthLenWasm(len: i32) {
    RESULT[2] = len;
}

#[no_mangle]
pub unsafe extern "C" fn setSocks5AuthLenWasm(len: i32) {
    RESULT[3] = len;
}

// ==========================================
// 节点生成与字符串混淆逻辑 (高强度动态对抗版)
// ==========================================

// 全局动态密钥，默认为错误的值，防止静态分析工具直接扫描
static mut DYNAMIC_XOR_KEY: u8 = 0x00;

#[no_mangle]
pub unsafe extern "C" fn initWasm(key: u8) {
    // 接收外部传入的 90，减去 156 
    // 90 - 156 = -66，底层 u8 自动溢出环绕为 190
    DYNAMIC_XOR_KEY = key.wrapping_sub(156);
}

// 编译期真实加密密钥: 190 (通过 90 减 156 溢出得到)
const COMPILE_XOR_KEY: u8 = 190;

// 编译期常量函数：在编译时将字符串异或加密，WASM二进制文件中不会出现明文
const fn obf<const N: usize>(s: &[u8; N]) -> [u8; N] {
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] ^ COMPILE_XOR_KEY;
        i += 1;
    }
    out
}

// 极速运行时解密：利用算出来的 DYNAMIC_XOR_KEY 直接在内存中还原
#[inline(always)]
unsafe fn decode_xor(src: &[u8], dst: *mut u8) -> i32 {
    let len = src.len();
    for i in 0..len {
        *dst.add(i) = *src.get_unchecked(i) ^ DYNAMIC_XOR_KEY;
    }
    len as i32
}

static TEMPLATES: [&[u8]; 12] = [
    &obf(b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=http%2F1.1&insecure=1&allowInsecure=0&type=ws#ws-vless-{{name}}"),
    &obf(b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&allowInsecure=0&type=ws&ech={{ECHDNS}}&alpn=http%2F1.1&insecure=0#[ECH]-ws-vless-{{name}}"),
    &obf(b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=xhttp&headerType=none&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#xhttp-vless-{{name}}"),
    &obf(b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&type=xhttp&headerType=none&ech={{ECHDNS}}&alpn=h2&insecure=0&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#[ECH]-xhttp-vless-{{name}}"),
    &obf(b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&insecure=1&allowInsecure=0#grpc-vless-{{name}}"),
    &obf(b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&ech={{ECHDNS}}&allowInsecure=0&insecure=0#[ECH]-grpc-vless-{{name}}"),
    &obf(b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&security=tls&fp=chrome&alpn=http%2F1.1&insecure=1&allowInsecure=0&type=ws#ws-trojan-{{name}}"),
    &obf(b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&security=tls&fp=chrome&allowInsecure=0&type=ws&ech={{ECHDNS}}&alpn=http%2F1.1&insecure=0#[ECH]-ws-trojan-{{name}}"),
    &obf(b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=xhttp&headerType=none&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#xhttp-trojan-{{name}}"),
    &obf(b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&type=xhttp&headerType=none&ech={{ECHDNS}}&alpn=h2&insecure=0&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#[ECH]-xhttp-trojan-{{name}}"),
    &obf(b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&insecure=1&allowInsecure=0#grpc-trojan-{{name}}"),
    &obf(b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&ech={{ECHDNS}}&allowInsecure=0&insecure=0#[ECH]-grpc-trojan-{{name}}"),
];

#[no_mangle]
pub unsafe extern "C" fn getTemplateWasm(index: i32) -> i32 {
    if (0..12).contains(&index) {
        let t = TEMPLATES.get_unchecked(index as usize);
        return decode_xor(t, COMMON_BUF.as_mut_ptr());
    }
    0
}
static SECRET_STRINGS: [&[u8]; 20] = [
    &obf(b"https://SUBAPI.cmliussss.net"),
    &obf(b"https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini"),
    &obf(b"edgetunnel"),
    &obf(b"(https://github.com/cmliu/"),
    &obf(b")"),
    &obf(b"clash"),
    &obf(b"singbox"),
    &obf(b"surge&ver=4"),
    &obf(b"quanx"),
    &obf(b"loon"),
    &obf(b"stash"),
    &obf(b"sb"),
    &obf(b"sing-box"),
    &obf(b"surge"),
    &obf(b"quantumult"),
    &obf(b"mihomo"),
    &obf(b"meta"),
    &obf(b"MyCloudflareNodes"),
    &obf(b"subconverter"),
    &obf(b"Subconverter"),
];

#[no_mangle]
pub unsafe extern "C" fn getSecretStringWasm(index: i32) -> i32 {
    if (0..20).contains(&index) {
        let s = SECRET_STRINGS.get_unchecked(index as usize);
        return decode_xor(s, COMMON_BUF.as_mut_ptr());
    }
    0
}
// ==========================================
// 辅助工具函数 (极致性能版)
// ==========================================

#[inline(always)]
fn ascii_lower(b: u8) -> u8 {
    b.wrapping_add(((b.wrapping_sub(b'A') <= 25) as u8).wrapping_mul(32))
}

#[inline(always)]
unsafe fn set_res(idx: usize, val: i32) {
    *RESULT.get_unchecked_mut(idx) = val;
}

#[inline(always)]
unsafe fn get_addr_len(at: i32, off: usize, len: usize) -> i32 {
    match at {
        1 => 4,
        4 => 16,
        3 => {
            if off < len {
                *COMMON_BUF.get_unchecked(off) as i32
            } else {
                -2
            }
        }
        _ => -1,
    }
}

#[inline(always)]
unsafe fn write_handshake(data: &[u8]) {
    set_res(12, data.len() as i32);
    core::ptr::copy_nonoverlapping(data.as_ptr(), COMMON_BUF.as_mut_ptr(), data.len());
}
// ==========================================
// 核心入站协议解析逻辑
// ==========================================

#[no_mangle]
pub unsafe extern "C" fn parseProtocolWasm(chunk_len: i32, step: i32) -> bool {
    let len = chunk_len as usize;
    RESULT[12] = 0; // [12] 回包长度归零
    RESULT[4] = 0;  // [4] SOCKS5 下一步状态归零
    RESULT[14] = 0; // [14] 是否需要更多数据归零 (0:不需要, 1:需要)

    // 1. SOCKS5 状态处理
    if step == 1 {
        let auth_len = RESULT[3] as usize;
        if len < auth_len {
            RESULT[14] = 1;
            return false;
        }
        if len != auth_len {
            write_handshake(&[1, 1]);
            return false;
        }
        let mut match_auth = true;
        let cb = COMMON_BUF.as_ptr();
        let sa = SOCKS5_AUTH.as_ptr();
        let mut i = 0usize;
        if auth_len >= 8 {
            let cb64 = cb as *const u64;
            let sa64 = sa as *const u64;
            let n8 = auth_len / 8;
            let mut j = 0usize;
            while j < n8 {
                if core::ptr::read_unaligned(cb64.add(j)) != core::ptr::read_unaligned(sa64.add(j)) {
                    match_auth = false;
                    break;
                }
                j += 1;
            }
            i = n8 * 8;
        }
        while match_auth && i < auth_len {
            if *cb.add(i) != *sa.add(i) {
                match_auth = false;
            }
            i += 1;
        }
        if match_auth {
            write_handshake(&[1, 0]);
            RESULT[4] = 2; // 下一步: 等待请求
        } else {
            write_handshake(&[1, 1]);
        }
        return false;
    }

    if step == 2 {
        if len < 4 {
            RESULT[14] = 1;
            return false;
        }
        if *COMMON_BUF.get_unchecked(0) != 5 || *COMMON_BUF.get_unchecked(1) != 1 {
            return false;
        }
        let at = *COMMON_BUF.get_unchecked(3) as i32;
        let al = get_addr_len(at, 4, len);
        if al == -2 {
            RESULT[14] = 1;
            return false;
        }
        if !(al > 0) {
            return false;
        }
        let as_ = if at == 3 { 5 } else { 4 };
        let full_len = as_ + al as usize + 2;
        if len < full_len {
            RESULT[14] = 1;
            return false;
        }

        let doff = as_ + al as usize;
        let p = ((*COMMON_BUF.get_unchecked(doff) as i32) << 8)
            | (*COMMON_BUF.get_unchecked(doff + 1) as i32);
        set_res(5, at);
        set_res(6, p);
        set_res(7, full_len as i32);
        set_res(8, if p == 53 { 1 } else { 0 });
        set_res(9, as_ as i32);
        set_res(10, al);
        set_res(11, 4);
        write_handshake(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        return true;
    }

    if len < 1 {
        RESULT[14] = 1;
        return false;
    }
    let b0 = *COMMON_BUF.get_unchecked(0);

    // 2. SOCKS5 Init
    if b0 == 5 {
        if len < 2 {
            RESULT[14] = 1;
            return false;
        }
        let nmethods = *COMMON_BUF.get_unchecked(1) as usize;
        let full_len = 2 + nmethods;
        if len < full_len {
            RESULT[14] = 1;
            return false;
        }
        let auth_len = RESULT[3] as usize;
        let required = if auth_len > 0 { 2 } else { 0 };
        let mut supported = false;
        for i in 0..nmethods {
            if *COMMON_BUF.get_unchecked(2 + i) == required {
                supported = true;
                break;
            }
        }
        if supported {
            write_handshake(&[5, required]);
            RESULT[4] = if required == 2 { 1 } else { 2 };
        } else {
            write_handshake(&[5, 0xFF]);
        }
        return false;
    }

    // 3. HTTP CONNECT
    if b0 == b'C' {
        if len < 48 {
            RESULT[14] = 1;
            return false;
        }
        if *COMMON_BUF.get_unchecked(1) == b'O' {
            if *COMMON_BUF.get_unchecked(len - 4) == 13
                && *COMMON_BUF.get_unchecked(len - 3) == 10
                && *COMMON_BUF.get_unchecked(len - 2) == 13
                && *COMMON_BUF.get_unchecked(len - 1) == 10
            {
                let mut second_space = 0;
                for i in 8..len {
                    if *COMMON_BUF.get_unchecked(i) == 32 {
                        second_space = i;
                        break;
                    }
                }
                if second_space != 0 {
                    let auth_len = RESULT[2] as usize;
                    if auth_len > 0 {
                        let mut match_auth = false;
                        let search_limit = if len > 1024 { 1024 } else { len };
                        let mut p = second_space + 30;
                        while p + auth_len + 6 < search_limit {
                            if *COMMON_BUF.get_unchecked(p) == b'B'
                                && *COMMON_BUF.get_unchecked(p + 1) == b'a'
                                && *COMMON_BUF.get_unchecked(p + 2) == b's'
                                && *COMMON_BUF.get_unchecked(p + 3) == b'i'
                                && *COMMON_BUF.get_unchecked(p + 4) == b'c'
                                && *COMMON_BUF.get_unchecked(p + 5) == 32
                            {
                                let mut same = true;
                                for j in 0..auth_len {
                                    if *COMMON_BUF.get_unchecked(p + 6 + j)
                                        != *HTTP_AUTH.get_unchecked(j)
                                    {
                                        same = false;
                                        break;
                                    }
                                }
                                if same {
                                    match_auth = true;
                                    break;
                                }
                            }
                            p += 1;
                        }
                        if !match_auth {
                            write_handshake(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n");
                            return false;
                        }
                    }

                    let mut last_colon = 0;
                    for i in (8..second_space - 3).rev() {
                        if *COMMON_BUF.get_unchecked(i) == 58 {
                            last_colon = i;
                            break;
                        }
                    }
                    if last_colon > 8 {
                        let mut port = 0;
                        for i in (last_colon + 1)..second_space {
                            let digit = *COMMON_BUF.get_unchecked(i) as i32 - 48;
                            if digit >= 0 && digit <= 9 {
                                port = port * 10 + digit;
                            } else {
                                break;
                            }
                        }
                        set_res(5, 3);
                        set_res(6, port);
                        set_res(7, len as i32);
                        set_res(8, 0);
                        set_res(9, 8);
                        set_res(10, (last_colon - 8) as i32);
                        set_res(11, 3);
                        write_handshake(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                        return true;
                    }
                }
            } else {
                RESULT[14] = 1;
                return false;
            }
        }
    }

    // 4. Trojan
    if RESULT[1] == 1 {
        if len >= 56 {
            let buf_ptr = COMMON_BUF.as_ptr() as *const u64;
            let hash_ptr = HASH.as_ptr() as *const u64;
            if core::ptr::read_unaligned(buf_ptr) == core::ptr::read_unaligned(hash_ptr)
                && core::ptr::read_unaligned(buf_ptr.add(1)) == core::ptr::read_unaligned(hash_ptr.add(1))
                && core::ptr::read_unaligned(buf_ptr.add(2)) == core::ptr::read_unaligned(hash_ptr.add(2))
                && core::ptr::read_unaligned(buf_ptr.add(3)) == core::ptr::read_unaligned(hash_ptr.add(3))
                && core::ptr::read_unaligned(buf_ptr.add(4)) == core::ptr::read_unaligned(hash_ptr.add(4))
                && core::ptr::read_unaligned(buf_ptr.add(5)) == core::ptr::read_unaligned(hash_ptr.add(5))
                && core::ptr::read_unaligned(buf_ptr.add(6)) == core::ptr::read_unaligned(hash_ptr.add(6))
            {
                if len < 60 {
                    RESULT[14] = 1;
                    return false;
                }
                let at = *COMMON_BUF.get_unchecked(59) as i32;
                let al = get_addr_len(at, 60, len);
                if al == -2 {
                    RESULT[14] = 1;
                    return false;
                }
                if al > 0 {
                    let as_ = if at == 3 { 61 } else { 60 };
                    let full_len = as_ + al as usize + 4; // Addr + Port(2) + \r\n(2)
                    if len < full_len {
                        RESULT[14] = 1;
                        return false;
                    }
                    let doff = as_ + al as usize;
                    let p = ((*COMMON_BUF.get_unchecked(doff) as i32) << 8)
                        | (*COMMON_BUF.get_unchecked(doff + 1) as i32);
                    set_res(5, at);
                    set_res(6, p);
                    set_res(7, full_len as i32);
                    set_res(8, if p == 53 { 1 } else { 0 });
                    set_res(9, as_ as i32);
                    set_res(10, al);
                    set_res(11, 1);
                    return true;
                }
            }
        }
    } else {
        if len >= 58 && *COMMON_BUF.get_unchecked(56) == 13 && *COMMON_BUF.get_unchecked(57) == 10 {
            if len < 60 {
                RESULT[14] = 1;
                return false;
            }
            let at = *COMMON_BUF.get_unchecked(59) as i32;
            let al = get_addr_len(at, 60, len);
            if al == -2 {
                RESULT[14] = 1;
                return false;
            }
            if al > 0 {
                let as_ = if at == 3 { 61 } else { 60 };
                let full_len = as_ + al as usize + 4;
                if len < full_len {
                    RESULT[14] = 1;
                    return false;
                }
                let doff = as_ + al as usize;
                let p = ((*COMMON_BUF.get_unchecked(doff) as i32) << 8)
                    | (*COMMON_BUF.get_unchecked(doff + 1) as i32);
                set_res(5, at);
                set_res(6, p);
                set_res(7, full_len as i32);
                set_res(8, if p == 53 { 1 } else { 0 });
                set_res(9, as_ as i32);
                set_res(10, al);
                set_res(11, 1);
                return true;
            }
        }
    }

    // 5. VLESS
    let check_vless = if *RESULT.get_unchecked(0) == 1 {
        if len >= 17 {
            let buf_ptr = COMMON_BUF.as_ptr().add(1) as *const u64;
            let uuid_ptr = UUID.as_ptr() as *const u64;
            core::ptr::read_unaligned(buf_ptr) == core::ptr::read_unaligned(uuid_ptr)
                && core::ptr::read_unaligned(buf_ptr.add(1)) == core::ptr::read_unaligned(uuid_ptr.add(1))
        } else {
            false
        }
    } else {
        b0 != 1 && b0 != 3 && b0 != 4
    };

    if check_vless {
        if len < 18 {
            RESULT[14] = 1;
            return false;
        }
        let off = 19 + (*COMMON_BUF.get_unchecked(17) as usize);
        if len < off + 4 {
            RESULT[14] = 1;
            return false;
        }
        let mut at = *COMMON_BUF.get_unchecked(off + 2) as i32;
        if at != 1 {
            at += 1;
        }
        let al = get_addr_len(at, off + 3, len);
        if al == -2 {
            RESULT[14] = 1;
            return false;
        }
        if al > 0 {
            let as_ = if at == 3 { off + 4 } else { off + 3 };
            let full_len = as_ + al as usize;
            if len < full_len {
                RESULT[14] = 1;
                return false;
            }
            let p = ((*COMMON_BUF.get_unchecked(off) as i32) << 8)
                | (*COMMON_BUF.get_unchecked(off + 1) as i32);
            set_res(5, at);
            set_res(6, p);
            set_res(7, full_len as i32);
            set_res(8, if p == 53 { 1 } else { 0 });
            set_res(9, as_ as i32);
            set_res(10, al);
            set_res(11, 0);
            write_handshake(&[b0, 0]);
            return true;
        }
    }

    // 6. Shadowsocks
    let at = b0 as i32;
    if at == 1 || at == 3 || at == 4 {
        if len < 2 {
            RESULT[14] = 1;
            return false;
        }
        let al = get_addr_len(at, 1, len);
        if al == -2 {
            RESULT[14] = 1;
            return false;
        }
        if al > 0 {
            let addr_start = if at == 3 { 2 } else { 1 };
            let port_off = addr_start + al as usize;
            let full_len = port_off + 2;
            if len < full_len {
                RESULT[14] = 1;
                return false;
            }
            let p = ((*COMMON_BUF.get_unchecked(port_off) as i32) << 8)
                | (*COMMON_BUF.get_unchecked(port_off + 1) as i32);
            set_res(5, at);
            set_res(6, p);
            set_res(7, full_len as i32);
            set_res(8, if p == 53 { 1 } else { 0 });
            set_res(9, addr_start as i32);
            set_res(10, al);
            set_res(11, 2);
            return true;
        }
    }

    // fallback: 如果是非明确SS特征头，且极有可能属于 Trojan/Vless 因为数据极短导致还未完成校验，给予最后一次保底等待
    if at != 1 && at != 3 && at != 4 {
        if RESULT[1] == 1 && len < 56 {
            RESULT[14] = 1;
            return false;
        }
        if RESULT[0] == 1 && len < 17 {
            RESULT[14] = 1;
            return false;
        }
    }

    false
}

// ==========================================
// SHA224 算法实现 (专用于 Trojan 密码 Hash)
// ==========================================

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

#[inline(always)]
unsafe fn sha224_block(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    let bp = block.as_ptr();
    for i in 0..16 {
        w[i] = ((*bp.add(i * 4) as u32) << 24)
            | ((*bp.add(i * 4 + 1) as u32) << 16)
            | ((*bp.add(i * 4 + 2) as u32) << 8)
            | (*bp.add(i * 4 + 3) as u32);
    }
    for i in 16..64 {
        let w15 = *w.get_unchecked(i - 15);
        let s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3);
        let w2 = *w.get_unchecked(i - 2);
        let s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> 10);
        *w.get_unchecked_mut(i) = (*w.get_unchecked(i - 16))
            .wrapping_add(s0)
            .wrapping_add(*w.get_unchecked(i - 7))
            .wrapping_add(s1);
    }
    let mut a = *state.get_unchecked(0);
    let mut b = *state.get_unchecked(1);
    let mut c = *state.get_unchecked(2);
    let mut d = *state.get_unchecked(3);
    let mut e = *state.get_unchecked(4);
    let mut f = *state.get_unchecked(5);
    let mut g = *state.get_unchecked(6);
    let mut h = *state.get_unchecked(7);
    let k_ptr = K.as_ptr();
    let w_ptr = w.as_ptr();
    let mut i = 0usize;
    while i < 64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k_ptr.add(i))
            .wrapping_add(*w_ptr.add(i));
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    let s = state.as_mut_ptr();
    *s.add(0) = (*s.add(0)).wrapping_add(a);
    *s.add(1) = (*s.add(1)).wrapping_add(b);
    *s.add(2) = (*s.add(2)).wrapping_add(c);
    *s.add(3) = (*s.add(3)).wrapping_add(d);
    *s.add(4) = (*s.add(4)).wrapping_add(e);
    *s.add(5) = (*s.add(5)).wrapping_add(f);
    *s.add(6) = (*s.add(6)).wrapping_add(g);
    *s.add(7) = (*s.add(7)).wrapping_add(h);
}

#[no_mangle]
pub unsafe extern "C" fn initCredentialsWasm(pass_len: i32) {
    let mut state: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];
    let input = core::slice::from_raw_parts(COMMON_BUF.as_ptr(), pass_len as usize);
    let mut buffer = [0u8; 64];
    let bit_len = (pass_len as u64) * 8;
    let mut offset = 0;
    while offset + 64 <= input.len() {
        sha224_block(&mut state, &input[offset..offset + 64]);
        offset += 64;
    }
    let rem = input.len() - offset;
    buffer[..rem].copy_from_slice(&input[offset..offset + rem]);
    buffer[rem] = 0x80;
    if rem >= 56 {
        buffer[(rem + 1)..64].fill(0);
        sha224_block(&mut state, &buffer);
        buffer[..56].fill(0);
    } else {
        buffer[(rem + 1)..56].fill(0);
    }
    for i in 0..8 {
        buffer[63 - i] = (bit_len >> (i * 8)) as u8;
    }
    sha224_block(&mut state, &buffer);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash_ptr = HASH.as_mut_ptr();
    let state_ptr = state.as_ptr();
    let mut out = 0usize;
    let mut i = 0usize;
    while i < 7 {
        let v = *state_ptr.add(i);
        let mut sh: u32 = 24;
        let mut j = 0usize;
        while j < 4 {
            let byte = ((v >> sh) & 0xff) as u8;
            *hash_ptr.add(out) = *HEX.get_unchecked((byte >> 4) as usize);
            *hash_ptr.add(out + 1) = *HEX.get_unchecked((byte & 0x0f) as usize);
            out += 2;
            sh = sh.wrapping_sub(8);
            j += 1;
        }
        i += 1;
    }
}
// ==========================================
// URL 解析逻辑 (含缓存加速机制)
// ==========================================

#[inline(always)]
unsafe fn equals_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let len = a.len();
    let mut i = 0;
    while i < len {
        if ascii_lower(*a.get_unchecked(i)) != ascii_lower(*b.get_unchecked(i)) { return false; }
        i += 1;
    }
    true
}

#[inline(always)]
unsafe fn starts_with_ignore_case(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() < prefix.len() { return false; }
    equals_ignore_case(core::slice::from_raw_parts(data.as_ptr(), prefix.len()), prefix)
}

#[inline(always)]
unsafe fn match_separator(d: &[u8]) -> Option<usize> {
    if d.is_empty() { return None; }
    if *d.get_unchecked(0) == b'=' { return Some(1); }
    if d.len() >= 3 {
        let p = d.as_ptr();
        if ascii_lower(*p) == b':' && ascii_lower(*p.add(1)) == b'/' && ascii_lower(*p.add(2)) == b'/' {
            return Some(3);
        }
    }
    if d.len() >= 9 && *d.get_unchecked(0) == b'%' && *d.get_unchecked(1) == b'3' && ascii_lower(*d.get_unchecked(2)) == b'a'
        && *d.get_unchecked(3) == b'%' && *d.get_unchecked(4) == b'2' && ascii_lower(*d.get_unchecked(5)) == b'f'
        && *d.get_unchecked(6) == b'%' && *d.get_unchecked(7) == b'2' && ascii_lower(*d.get_unchecked(8)) == b'f'
    { return Some(9); }
    None
}

// 供编译期加密映射的配置项结构
struct UrlKey {
    buf: &'static [u8],
    res_idx: usize,
    is_g: bool,
}

static URL_PARSE_KEYS: [UrlKey; 14] = [
    UrlKey { buf: &obf(b"gs5"), res_idx: 15, is_g: true },
    UrlKey { buf: &obf(b"s5all"), res_idx: 15, is_g: true },
    UrlKey { buf: &obf(b"ghttp"), res_idx: 17, is_g: true },
    UrlKey { buf: &obf(b"gnat64"), res_idx: 19, is_g: true },
    UrlKey { buf: &obf(b"nat64all"), res_idx: 19, is_g: true },
    UrlKey { buf: &obf(b"httpall"), res_idx: 17, is_g: true },
    UrlKey { buf: &obf(b"gturn"), res_idx: 24, is_g: true },
    UrlKey { buf: &obf(b"turnall"), res_idx: 24, is_g: true },
    UrlKey { buf: &obf(b"s5"), res_idx: 15, is_g: false },
    UrlKey { buf: &obf(b"socks"), res_idx: 15, is_g: false },
    UrlKey { buf: &obf(b"http"), res_idx: 17, is_g: false },
    UrlKey { buf: &obf(b"ip"), res_idx: 21, is_g: false },
    UrlKey { buf: &obf(b"nat64"), res_idx: 19, is_g: false },
    UrlKey { buf: &obf(b"turn"), res_idx: 24, is_g: false },
];

// 缓存解码结果的结构，避免每次请求重复解密
struct DecodedUrlKey {
    buf: [u8; 12],
    len: usize,
    res_idx: usize,
    is_g: bool,
}
const EMPTY_URL_KEY: DecodedUrlKey = DecodedUrlKey { buf: [0; 12], len: 0, res_idx: 0, is_g: false };

// 静态全局缓存锁 (BSS 段内存)
static mut URL_KEYS_INIT: bool = false;
static mut PROXYALL_STR: [u8; 8] = [0; 8];
static mut GLOBALPROXY_STR: [u8; 11] = [0; 11];
static mut DECODED_URL_KEYS: [DecodedUrlKey; 14] = [EMPTY_URL_KEY; 14];

#[no_mangle]
pub unsafe extern "C" fn parseUrlWasm(url_len: i32) {
    let len = url_len as usize;
    let data = core::slice::from_raw_parts(COMMON_BUF.as_ptr(), len);
    let mut is_all = false;
    
    for i in [15, 16, 17, 18, 19, 20, 21, 22, 24, 25] { set_res(i, -1); }

    // [优化] 首次调用时集中解密并常驻内存，后续请求直接读取缓存，零解密开销
    if !URL_KEYS_INIT {
        decode_xor(&obf(b"proxyall"), PROXYALL_STR.as_mut_ptr());
        decode_xor(&obf(b"globalproxy"), GLOBALPROXY_STR.as_mut_ptr());
        
        for (idx, key) in URL_PARSE_KEYS.iter().enumerate() {
            let k_len = decode_xor(key.buf, DECODED_URL_KEYS[idx].buf.as_mut_ptr()) as usize;
            DECODED_URL_KEYS[idx].len = k_len;
            DECODED_URL_KEYS[idx].res_idx = key.res_idx;
            DECODED_URL_KEYS[idx].is_g = key.is_g;
        }
        URL_KEYS_INIT = true; 
    }

    let mut i = 0;
    while i < len {
        if starts_with_ignore_case(&data[i..], &PROXYALL_STR) {
            is_all = true;
            i += 8;
            continue;
        }
        if starts_with_ignore_case(&data[i..], &GLOBALPROXY_STR) {
            is_all = true;
            i += 11;
            continue;
        }
        
        let mut matched = false;
        let data_i = data.as_ptr().add(i);
        
        // 直接对比已经缓存的明文字符串
        for key in &DECODED_URL_KEYS {
            let k_len = key.len;
            let k_str = &key.buf[..k_len];
            
            if i + k_len <= len 
                && ascii_lower(*data_i) == ascii_lower(*k_str.get_unchecked(0)) 
                && starts_with_ignore_case(core::slice::from_raw_parts(data_i, len - i), k_str) 
            {
                let after_key = i + k_len;
                if let Some(s_len) = match_separator(&data[after_key..]) {
                    let v_start = after_key + s_len;
                    let mut v_end = v_start;
                    while v_end < len && *data.get_unchecked(v_end) != b'&' {
                        v_end += 1;
                    }
                    if v_end > v_start {
                        if key.is_g { is_all = true; }
                        set_res(key.res_idx, v_start as i32);
                        set_res(key.res_idx + 1, (v_end - v_start) as i32);
                        i = v_end;
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched { i += 1; }
    }
    set_res(23, if is_all { 1 } else { 0 });
}
// ==========================================
// 地址类型修正逻辑 (极致性能版)
// ==========================================

#[no_mangle]
pub unsafe extern "C" fn getCorrectAddrTypeWasm(len: i32) -> i32 {
    let len = len as usize;
    let ptr = COMMON_BUF.as_ptr();
    let char0 = *ptr;

    if char0 == b'[' {
        return 4;
    }
    if char0.wrapping_sub(b'0') > 9 {
        return 3;
    }
    if len < 7 || len > 15 {
        return 3;
    }

    let mut part = 0u32;
    let mut dots = 0u32;
    let mut part_len = 0u32;
    let mut head = 0u8;
    let mut p = ptr;
    let end = ptr.add(len);

    while p < end {
        let b = *p;
        p = p.add(1);
        if b == b'.' {
            if part_len == 0 || (part_len > 1 && head == b'0') {
                return 3;
            }
            dots += 1;
            if dots > 3 {
                return 3;
            }
            part = 0;
            part_len = 0;
        } else {
            let d = b.wrapping_sub(b'0');
            if d > 9 {
                return 3;
            }
            if part_len == 0 {
                head = b;
            }
            part_len += 1;
            if part_len > 3 {
                return 3;
            }
            part = part * 10 + (d as u32);
            if part > 255 {
                return 3;
            }
        }
    }

    if dots == 3 && part_len > 0 && !(part_len > 1 && head == b'0') {
        1
    } else {
        3
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
