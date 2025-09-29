// Cloudflare Worker - VLESS 代理服务
// 环境变量: UUID, PROXYIP, SOCKS5

// 配置区域
const DEFAULT_USER_ID = '2982f122-9649-40dc-bc15-fa3ec91d8921'; // 与你的VLESS UUID匹配
const DEFAULT_PROXY_IPS = ["ProxyIP.JP.CMLiussss.net"];
// ================================================

import { connect } from 'cloudflare:sockets';

let userID, proxyIP, proxyIPs;
let enableSocks = false, parsedSocks5Address = {};
let go2Socks5s = ['*ttvnw.net', '*tapecontent.net', '*cloudatacdn.com', '*.loadshare.org'];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')]; // 屏蔽的主机名

export default {
    async fetch(request, env) {
        try {
            // 初始化UUID（优先使用环境变量，其次使用默认值）
            userID = env.UUID || env.uuid || env.PASSWORD || DEFAULT_USER_ID;
            
            // 验证UUID格式
            if (!isValidUUID(userID)) {
                return new Response('无效的UUID格式', { status: 400 });
            }

            // 处理代理IP配置
            proxyIP = env.PROXYIP || '';
            if (!proxyIP) {
                proxyIPs = DEFAULT_PROXY_IPS;
                proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            } else {
                proxyIPs = proxyIP.split(',').map(ip => ip.trim()).filter(Boolean);
            }

            // 处理SOCKS5配置
            const socks5Address = env.SOCKS5 || '';
            if (socks5Address) {
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    enableSocks = true;
                } catch (err) {
                    enableSocks = false;
                }
            }

            // 处理WebSocket升级（VLESS基于WS传输）
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader === 'websocket') {
                return handleWebSocket(request);
            }

            return new Response('仅支持WebSocket代理', { status: 400 });
        } catch (err) {
            return new Response(err.toString(), { status: 500 });
        }
    }
};

async function handleWebSocket(request) {
    const url = new URL(request.url);
    let localProxyIP = proxyIP;
    let localProxyPort = '443';

    // 从URL参数解析代理IP（可选）
    if (url.searchParams.has('proxyip')) {
        localProxyIP = url.searchParams.get('proxyip');
        enableSocks = false;
    }

    // 解析代理IP和端口
    if (localProxyIP.includes(']:')) {
        const lastColonIndex = localProxyIP.lastIndexOf(':');
        localProxyPort = localProxyIP.slice(lastColonIndex + 1);
        localProxyIP = localProxyIP.slice(0, lastColonIndex);
    } else if (!localProxyIP.includes(']:') && !localProxyIP.includes(']')) {
        const parts = localProxyIP.split(':');
        localProxyIP = parts[0];
        localProxyPort = parts[1] || '443';
    }

    // 创建WebSocket对
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    // 处理早期数据（VLESS可能通过sec-websocket-protocol传递早期数据）
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

    // 处理数据流（核心：解析VLESS协议并转发）
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk) {
            // 解析VLESS协议头部（关键修改点）
            const {
                hasError,
                message,
                addressRemote,
                portRemote,
                rawDataIndex,
                isUDP
            } = processVLESSHeader(chunk, userID);

            if (hasError) throw new Error(message);
            if (isUDP) throw new Error('暂不支持UDP代理');
            if (banHosts.includes(addressRemote)) throw new Error('主机被屏蔽');

            // 转发TCP数据
            handleTCPOutBound(
                addressRemote,
                portRemote,
                chunk.slice(rawDataIndex),
                webSocket,
                localProxyIP,
                localProxyPort
            );
        }
    })).catch(err => console.error('数据流错误:', err));

    return new Response(null, { status: 101, webSocket: client });
}

// 构建可读的WebSocket流（处理消息和早期数据）
function makeReadableWebSocketStream(webSocket, earlyDataHeader) {
    let readableStreamCancel = false;

    return new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => {
                if (!readableStreamCancel) controller.enqueue(event.data);
            });

            webSocket.addEventListener('close', () => {
                if (!readableStreamCancel) controller.close();
                safeCloseWebSocket(webSocket);
            });

            webSocket.addEventListener('error', (err) => controller.error(err));

            // 处理早期数据（VLESS可能需要）
            const { earlyData } = base64ToArrayBuffer(earlyDataHeader);
            if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            readableStreamCancel = true;
            safeCloseWebSocket(webSocket);
        }
    });
}

// 解析VLESS协议头部（核心适配逻辑）
function processVLESSHeader(buffer, userID) {
    // VLESS头部最小长度：16字节UUID + 1字节指令 + 1字节地址类型 + 最小地址长度 + 2字节端口
    if (buffer.byteLength < 20) {
        return { hasError: true, message: 'VLESS数据长度不足' };
    }

    // 1. 验证UUID（VLESS头部前16字节为UUID）
    const userIDBuffer = new Uint8Array(buffer.slice(0, 16));
    if (stringify(userIDBuffer) !== userID) {
        return { hasError: true, message: '无效的VLESS UUID' };
    }

    // 2. 解析指令（第17字节：0=CONNECT, 1=UDP_ASSOCIATE）
    const command = new Uint8Array(buffer.slice(16, 17))[0];
    const isUDP = command === 1; // VLESS中1为UDP，0为TCP

    // 3. 解析目标地址和端口（从第18字节开始）
    let addressIndex = 17;
    const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
    addressIndex++;

    let addressRemote = '';
    switch (addressType) {
        case 1: // IPv4（4字节）
            addressRemote = new Uint8Array(buffer.slice(addressIndex, addressIndex + 4)).join('.');
            addressIndex += 4;
            break;
        case 2: // 域名（1字节长度 + 域名）
            const domainLength = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex++;
            addressRemote = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + domainLength));
            addressIndex += domainLength;
            break;
        case 3: // IPv6（16字节）
            const ipv6 = [];
            const dataView = new DataView(buffer.slice(addressIndex, addressIndex + 16));
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16).padStart(4, '0'));
            }
            addressRemote = ipv6.join(':');
            addressIndex += 16;
            break;
        default:
            return { hasError: true, message: '无效的地址类型: ' + addressType };
    }

    // 4. 解析端口（2字节，大端序）
    if (addressIndex + 2 > buffer.byteLength) {
        return { hasError: true, message: '端口数据不完整' };
    }
    const portBuffer = buffer.slice(addressIndex, addressIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    addressIndex += 2;

    return {
        hasError: false,
        addressRemote,
        portRemote,
        rawDataIndex: addressIndex, // 实际数据开始位置
        isUDP
    };
}

// 处理TCP outbound连接
async function handleTCPOutBound(address, port, data, webSocket, proxyIP, proxyPort) {
    // 检查是否需要使用SOCKS5代理
    const useSocks = enableSocks && await useSocks5Pattern(address);

    // 连接目标服务器
    let tcpSocket;
    try {
        if (useSocks) {
            tcpSocket = await socks5Connect(address, port);
        } else {
            // 使用代理IP或直接连接目标
            const connectHost = proxyIP || address;
            const connectPort = proxyIP ? proxyPort : port;
            tcpSocket = connect({ hostname: connectHost, port: connectPort });
        }

        // 发送初始数据
        const writer = tcpSocket.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();

        // 转发远程数据到WebSocket
        remoteSocketToWS(tcpSocket, webSocket);
    } catch (error) {
        console.error('连接错误:', error);
        safeCloseWebSocket(webSocket);
    }
}

// 检查是否匹配SOCKS5规则
async function useSocks5Pattern(address) {
    if (go2Socks5s.includes('*') || go2Socks5s.includes('all')) return true;
    return go2Socks5s.some(pattern => {
        const regex = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`, 'i');
        return regex.test(address);
    });
}

// SOCKS5连接逻辑
async function socks5Connect(address, port) {
    const { hostname, port: socksPort, username, password } = parsedSocks5Address;
    const socket = connect({ hostname, port: socksPort });

    // 发送SOCKS5握手
    const writer = socket.writable.getWriter();
    await writer.write(new Uint8Array([5, 2, 0, 2])); // 版本5，支持无认证和用户名密码

    // 处理握手响应
    const reader = socket.readable.getReader();
    const response = await reader.read();
    if (response.done) throw new Error('SOCKS5握手失败');

    // 处理认证
    if (response.value[1] === 0x02 && username && password) {
        // 用户名密码认证
        const userBuf = new TextEncoder().encode(username);
        const passBuf = new TextEncoder().encode(password);
        const authBuffer = new Uint8Array([1, userBuf.length, ...userBuf, passBuf.length, ...passBuf]);
        await writer.write(authBuffer);
        
        const authResponse = await reader.read();
        if (authResponse.done || authResponse.value[1] !== 0) {
            throw new Error('SOCKS5认证失败');
        }
    } else if (response.value[1] !== 0) {
        throw new Error('不支持的SOCKS5认证方式');
    }

    // 发送连接请求
    const addressBuffer = new TextEncoder().encode(address);
    const requestBuffer = new Uint8Array([
        5, 1, 0, 3, addressBuffer.length, ...addressBuffer,
        port >> 8, port & 0xff
    ]);
    await writer.write(requestBuffer);

    // 验证连接响应
    const connectResponse = await reader.read();
    if (connectResponse.done || connectResponse.value[1] !== 0) {
        throw new Error('SOCKS5连接目标失败');
    }

    reader.releaseLock();
    return socket;
}

// 远程Socket数据转发到WebSocket
function remoteSocketToWS(remoteSocket, webSocket) {
    remoteSocket.readable.pipeTo(new WritableStream({
        write(chunk) {
            if (webSocket.readyState === WebSocket.OPEN) {
                webSocket.send(chunk);
            }
        },
        close() {
            safeCloseWebSocket(webSocket);
        }
    })).catch(err => console.error('远程数据转发错误:', err));
}

// 工具函数：验证UUID格式
function isValidUUID(uuid) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

// 工具函数：解析SOCKS5地址格式
function socks5AddressParser(address) {
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port = 1080;

    if (former) {
        const parts = former.split(":");
        if (parts.length !== 2) throw new Error('SOCKS5认证格式错误（应为user:pass@host:port）');
        [username, password] = parts;
    }

    if (latter.includes("]:")) {
        port = latter.split("]:")[1];
        hostname = latter.split("]:")[0] + "]";
    } else if (latter.includes(":")) {
        const parts = latter.split(":");
        hostname = parts[0];
        port = parts[1];
    } else {
        hostname = latter;
    }

    if (isNaN(port) || port < 1 || port > 65535) throw new Error('无效的SOCKS5端口');
    return { username, password, hostname, port: parseInt(port) };
}

// 工具函数：Base64转ArrayBuffer（处理早期数据）
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: undefined };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const buffer = Uint8Array.from(decode, c => c.charCodeAt(0));
        return { earlyData: buffer.buffer };
    } catch (error) {
        return { earlyData: undefined };
    }
}

// 工具函数：安全关闭WebSocket
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close(1000, '正常关闭');
        }
    } catch (error) {
        console.error('关闭WebSocket错误:', error);
    }
}

// UUID工具：Uint8Array转UUID字符串
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function stringify(arr, offset = 0) {
    // 确保输入是16字节的Uint8Array
    if (arr.length - offset < 16) {
        throw new Error('UUID二进制数据长度不足16字节');
    }
    const bytes = arr.subarray(offset, offset + 16); // 截取16字节
    const hexParts = [];
    for (let i = 0; i < 16; i++) {
        hexParts.push(bytes[i].toString(16).padStart(2, '0'));
    }
    // 拼接UUID格式（8-4-4-4-12）
    const uuid = [
        hexParts.slice(0, 4).join(''),
        hexParts.slice(4, 6).join(''),
        hexParts.slice(6, 8).join(''),
        hexParts.slice(8, 10).join(''),
        hexParts.slice(10, 16).join('')
    ].join('-').toLowerCase();

    if (!isValidUUID(uuid)) {
        throw new Error(`UUID转换失败: ${uuid}`);
    }
    return uuid;
}
