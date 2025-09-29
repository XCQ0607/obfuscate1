// Cloudflare Worker - 精简网络代理服务
// 环境变量: UUID, SECRET, DOMAIN, PROXYIP

// 配置区域 - 仅保留必要默认值
const DEFAULT_USER_ID = '2982f122-9649-40dc-bc15-fa3ec91d8921';
const DEFAULT_PROXY_IPS = ["ProxyIP.JP.CMLiussss.net"];
// ================================================

import { connect } from 'cloudflare:sockets';

let userID, clientId;
let proxyIP, proxyIPs;
let enableSocks = false, parsedSocks5Address = {};
let go2Socks5s = ['*ttvnw.net', '*tapecontent.net', '*cloudatacdn.com', '*.loadshare.org'];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')]; // 屏蔽的主机名

export default {
    async fetch(request, env) {
        try {
            // 初始化环境变量（移除默认访问密钥和主机名）
            clientId = env.UUID || env.uuid || env.PASSWORD || DEFAULT_USER_ID;
            userID = clientId;

            // 验证UUID
            if (!isValidUUID(userID)) {
                return new Response('请设置有效的UUID', { status: 400 });
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

            // 处理WebSocket升级
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

    // 从URL参数解析代理IP
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

    // 处理早期数据
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

    // 处理数据流
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk) {
            // 解析V2Ray协议头部
            const {
                hasError,
                message,
                addressRemote,
                portRemote,
                rawDataIndex,
                isUDP
            } = processV2RayHeader(chunk, userID);

            if (hasError) throw new Error(message);
            if (isUDP) throw new Error('不支持UDP代理');
            if (banHosts.includes(addressRemote)) throw new Error('主机被屏蔽');

            // 处理TCP连接
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

            // 处理早期数据
            const { earlyData } = base64ToArrayBuffer(earlyDataHeader);
            if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            readableStreamCancel = true;
            safeCloseWebSocket(webSocket);
        }
    });
}

function processV2RayHeader(buffer, userID) {
    if (buffer.byteLength < 24) {
        return { hasError: true, message: '数据长度不足' };
    }

    const version = new Uint8Array(buffer.slice(0, 1))[0];
    if (version !== 1) {
        return { hasError: true, message: '不支持的协议版本' };
    }

    // 验证用户ID
    const userIDBuffer = new Uint8Array(buffer.slice(1, 17));
    if (stringify(userIDBuffer) !== userID) {
        return { hasError: true, message: '无效的用户ID' };
    }

    // 解析选项长度和命令
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const command = new Uint8Array(buffer.slice(18 + optLength, 19 + optLength))[0];
    const isUDP = command === 2;

    // 解析端口
    const portBuffer = buffer.slice(19 + optLength, 21 + optLength);
    const portRemote = new DataView(portBuffer).getUint16(0);

    // 解析地址
    let addressIndex = 21 + optLength;
    const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
    addressIndex++;

    let addressRemote = '';
    switch (addressType) {
        case 1: // IPv4
            addressRemote = new Uint8Array(buffer.slice(addressIndex, addressIndex + 4)).join('.');
            addressIndex += 4;
            break;
        case 2: // 域名
            const domainLength = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex++;
            addressRemote = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + domainLength));
            addressIndex += domainLength;
            break;
        case 3: // IPv6
            const ipv6 = [];
            const dataView = new DataView(buffer.slice(addressIndex, addressIndex + 16));
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressRemote = ipv6.join(':');
            addressIndex += 16;
            break;
        default:
            return { hasError: true, message: '无效的地址类型' };
    }

    return {
        hasError: false,
        addressRemote,
        portRemote,
        rawDataIndex: addressIndex,
        isUDP
    };
}

async function handleTCPOutBound(address, port, data, webSocket, proxyIP, proxyPort) {
    // 检查是否需要使用SOCKS5
    const useSocks = enableSocks && await useSocks5Pattern(address);

    // 连接目标服务器
    let tcpSocket;
    try {
        if (useSocks) {
            tcpSocket = await socks5Connect(address, port);
        } else {
            // 使用代理IP或直接连接
            const connectHost = proxyIP || address;
            const connectPort = proxyIP ? proxyPort : port;
            tcpSocket = connect({ hostname: connectHost, port: connectPort });
        }

        // 发送初始数据
        const writer = tcpSocket.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();

        // 转发数据
        remoteSocketToWS(tcpSocket, webSocket);
    } catch (error) {
        console.error('连接错误:', error);
        safeCloseWebSocket(webSocket);
    }
}

async function useSocks5Pattern(address) {
    if (go2Socks5s.includes('*') || go2Socks5s.includes('all')) return true;
    return go2Socks5s.some(pattern => {
        const regex = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`, 'i');
        return regex.test(address);
    });
}

async function socks5Connect(address, port) {
    const { hostname, port: socksPort, username, password } = parsedSocks5Address;
    const socket = connect({ hostname, port: socksPort });

    // 发送SOCKS5握手
    const writer = socket.writable.getWriter();
    await writer.write(new Uint8Array([5, 2, 0, 2])); // 版本5，支持无认证和用户名密码

    // 处理握手响应
    const reader = socket.readable.getReader();
    const response = await reader.read();
    if (response.value[1] === 0x02 && username && password) {
        // 处理用户名密码认证
        const authBuffer = new TextEncoder().encode(`${username}:${password}`);
        await writer.write(new Uint8Array([1, username.length, ...new TextEncoder().encode(username), password.length, ...new TextEncoder().encode(password)]));
        const authResponse = await reader.read();
        if (authResponse.value[1] !== 0) throw new Error('SOCKS5认证失败');
    } else if (response.value[1] !== 0) {
        throw new Error('不支持的认证方式');
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
    if (connectResponse.value[1] !== 0) throw new Error('SOCKS5连接失败');

    reader.releaseLock();
    return socket;
}

function remoteSocketToWS(remoteSocket, webSocket) {
    // 远程数据转发到WebSocket
    remoteSocket.readable.pipeTo(new WritableStream({
        write(chunk) {
            if (webSocket.readyState === 1) webSocket.send(chunk);
        },
        close() {
            safeCloseWebSocket(webSocket);
        }
    })).catch(err => console.error('远程数据转发错误:', err));
}

// 工具函数
function isValidUUID(uuid) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

function socks5AddressParser(address) {
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port = 1080;

    if (former) {
        const parts = former.split(":");
        if (parts.length !== 2) throw new Error('SOCKS5认证格式错误');
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

    if (isNaN(port)) throw new Error('无效的端口');
    return { username, password, hostname, port: parseInt(port) };
}

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

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === 1 || socket.readyState === 2) socket.close();
    } catch (error) {
        console.error('关闭WebSocket错误:', error);
    }
}

// UUID工具函数
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function stringify(arr, offset = 0) {
    const uuid = [
        byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]],
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]],
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]],
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]],
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
    ].join('-');

    if (!isValidUUID(uuid)) throw new Error('无效的UUID');
    return uuid;
}
