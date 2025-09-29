// Cloudflare Worker - 简化版代理后端
import { connect } from 'cloudflare:sockets';

// ==================== 配置区域 ====================
const DEFAULT_USER_ID = '2982f122-9649-40dc-bc15-fa3ec91d8921';
const DEFAULT_PROXY_IPS = ["ProxyIP.JP.CMLiussss.net"];
// ================================================

let userID = '';
let proxyIP = '';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;
let enableHttp = false;
let go2Socks5s = ['*ttvnw.net', '*tapecontent.net', '*cloudatacdn.com', '*.loadshare.org'];

export default {
    async fetch(request, env, ctx) {
        try {
            // 初始化环境变量
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || DEFAULT_USER_ID;
            proxyIP = env.PROXYIP || env.proxyip || '';
            socks5Address = env.HTTP || env.SOCKS5 || '';

            if (!userID) {
                return new Response('Missing UUID configuration', { status: 400 });
            }

            // 处理 ProxyIP
            if (!proxyIP || proxyIP === '') {
                proxyIP = DEFAULT_PROXY_IPS.join(',');
            }
            
            if (proxyIP) {
                const proxyIPs = await parseList(proxyIP);
                proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            }

            // 处理 SOCKS5
            if (socks5Address) {
                const socks5s = await parseList(socks5Address);
                socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
                enableHttp = socks5Address.toLowerCase().includes('http://');
                socks5Address = socks5Address.split('//')[1] || socks5Address;
                
                if (env.GO2SOCKS5) go2Socks5s = await parseList(env.GO2SOCKS5);
                
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    enableSocks = true;
                } catch (err) {
                    console.log('SOCKS5 parse error:', err.toString());
                    enableSocks = false;
                }
            }

            const upgradeHeader = request.headers.get('Upgrade');
            
            // 处理代理IP端口
            let proxyPort = '443';
            if (proxyIP) {
                if (proxyIP.includes(']:')) {
                    let lastColonIndex = proxyIP.lastIndexOf(':');
                    proxyPort = proxyIP.slice(lastColonIndex + 1);
                    proxyIP = proxyIP.slice(0, lastColonIndex);
                } else {
                    const match = proxyIP.match(/^(.*?)(?::(\d+))?$/);
                    if (match) {
                        proxyIP = match[1];
                        proxyPort = match[2] || '443';
                    }
                }
            }

            // WebSocket 请求
            if (upgradeHeader && upgradeHeader === 'websocket') {
                const url = new URL(request.url);
                
                // 处理路径中的 proxyip 参数
                if (url.searchParams.has('proxyip')) {
                    proxyIP = url.searchParams.get('proxyip');
                    enableSocks = false;
                } else if (/\/proxyip=/i.test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
                    enableSocks = false;
                } else if (/\/pyip=/i.test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/pyip=')[1];
                    enableSocks = false;
                }

                // 处理路径中的 socks5 参数
                if (url.searchParams.get('socks5')) {
                    socks5Address = url.searchParams.get('socks5');
                } else if (/\/socks5=/i.test(url.pathname)) {
                    socks5Address = url.pathname.split('5=')[1];
                } else if (/\/socks:\/\//i.test(url.pathname) || /\/socks5:\/\//i.test(url.pathname) || /\/http:\/\//i.test(url.pathname)) {
                    enableHttp = url.pathname.includes('http://');
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        const lastAtIndex = socks5Address.lastIndexOf('@');
                        let userPassword = socks5Address.substring(0, lastAtIndex).replaceAll('%3D', '=');
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) {
                            userPassword = atob(userPassword);
                        }
                        socks5Address = `${userPassword}@${socks5Address.substring(lastAtIndex + 1)}`;
                    }
                    go2Socks5s = ['all in'];
                }

                if (socks5Address) {
                    try {
                        parsedSocks5Address = socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        console.log('SOCKS5 parse error:', err.toString());
                        enableSocks = false;
                    }
                }

                return await vlessOverWSHandler(request, proxyIP, proxyPort);
            } else {
                // 非 WebSocket 请求，返回 nginx 页面
                return new Response(await nginx(), {
                    status: 200,
                    headers: { 'Content-Type': 'text/html; charset=UTF-8' }
                });
            }
        } catch (err) {
            return new Response(err.toString(), { status: 500 });
        }
    }
};

async function vlessOverWSHandler(request, wsProxyIP, wsProxyPort) {
    const url = new URL(request.url);
    let localProxyIP = wsProxyIP || proxyIP;
    let localProxyPort = wsProxyPort || '443';
    
    // 处理 pyip 参数
    if (url.pathname.includes('/pyip=')) {
        const tmp_ip = url.pathname.split("=")[1];
        if (isValidIP(tmp_ip)) {
            localProxyIP = tmp_ip;
            if (localProxyIP.includes(']:')) {
                let lastColonIndex = localProxyIP.lastIndexOf(':');
                localProxyPort = localProxyIP.slice(lastColonIndex + 1);
                localProxyIP = localProxyIP.slice(0, lastColonIndex);
            } else if (!localProxyIP.includes(']:') && !localProxyIP.includes(']')) {
                [localProxyIP, localProxyPort = '443'] = localProxyIP.split(':');
            }
        }
    }

    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWapper = { value: null };
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns) {
                return await handleDNSQuery(chunk, webSocket, null, log);
            }
            
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const {
                hasError,
                message,
                addressType,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                vlessVersion = new Uint8Array([0, 0]),
                isUDP,
            } = processVlessHeader(chunk, userID);

            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'}`;
            
            if (hasError) {
                throw new Error(message);
            }
            
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                } else {
                    throw new Error('UDP proxy only supports DNS (port 53)');
                }
            }

            const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
            }

            handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, 
                rawClientData, webSocket, vlessResponseHeader, log, localProxyIP);
        },
        close() {
            log('readableWebSocketStream closed');
        },
        abort(reason) {
            log('readableWebSocketStream aborted', JSON.stringify(reason));
        }
    })).catch((err) => {
        log('readableWebSocketStream error', err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, 
    rawClientData, webSocket, vlessResponseHeader, log, wsProxyIP) {
    
    async function useSocks5Pattern(address) {
        if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
        return go2Socks5s.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false, http = false) {
        log(`connecting to ${address}:${port}`);
        const tcpSocket = socks
            ? (http ? await httpConnect(address, port, log) : await socks5Connect(addressType, address, port, log))
            : connect({ hostname: address, port: port });

        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        if (enableSocks) {
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            let useProxyIP = wsProxyIP || proxyIP;
            if (!useProxyIP || useProxyIP == '') {
                useProxyIP = DEFAULT_PROXY_IPS[Math.floor(Math.random() * DEFAULT_PROXY_IPS.length)];
            } else if (useProxyIP.includes(']:')) {
                portRemote = useProxyIP.split(']:')[1] || portRemote;
                useProxyIP = useProxyIP.split(']:')[0] + "]" || useProxyIP;
            } else if (useProxyIP.split(':').length === 2) {
                portRemote = useProxyIP.split(':')[1] || portRemote;
                useProxyIP = useProxyIP.split(':')[0] || useProxyIP;
            }
            if (useProxyIP.includes('.tp')) {
                portRemote = useProxyIP.split('.tp')[1].split('.')[0] || portRemote;
            }
            tcpSocket = await connectAndWrite(useProxyIP.toLowerCase() || addressRemote, portRemote);
        }
        
        remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) {
        useSocks = await useSocks5Pattern(addressRemote);
    }
    
    let tcpSocket;
    tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks, enableHttp);

    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

function processVlessHeader(vlessBuffer, userID) {
    if (vlessBuffer.byteLength < 24) {
        return { hasError: true, message: 'invalid data' };
    }

    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    let isValidUser = false;
    let isUDP = false;

    const userIDArray = new Uint8Array(vlessBuffer.slice(1, 17));
    const userIDString = stringify(userIDArray);
    isValidUser = userIDString === userID;

    if (!isValidUser) {
        return { hasError: true, message: 'invalid user' };
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

    if (command === 1) {
        // TCP
    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} not supported`
        };
    }

    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `invalid addressType ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: 'addressValue is empty' };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        vlessVersion: version,
        isUDP
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
    let remoteChunkCount = 0;
    let vlessHeader = vlessResponseHeader;
    let hasIncomingData = false;

    await remoteSocket.readable
        .pipeTo(new WritableStream({
            start() {},
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error('webSocket not open');
                }
                if (vlessHeader) {
                    webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                    vlessHeader = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            close() {
                log(`remoteConnection closed with hasIncomingData: ${hasIncomingData}`);
            },
            abort(reason) {
                console.error('remoteConnection aborted', reason);
            }
        }))
        .catch((error) => {
            console.error('remoteSocketToWS error', error.stack || error);
            safeCloseWebSocket(webSocket);
        });

    if (hasIncomingData === false && retry) {
        log('retry connection');
        retry();
    }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });

            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });

            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket error');
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            if (readableStreamCancel) return;
            log(`ReadableStream cancelled: ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
    try {
        const dnsServer = '8.8.4.4';
        const dnsPort = 53;
        let vlessHeader = vlessResponseHeader;

        const tcpSocket = connect({ hostname: dnsServer, port: dnsPort });
        log(`DNS query to ${dnsServer}:${dnsPort}`);
        
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();

        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (vlessHeader) {
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
            close() {
                log(`DNS connection closed`);
            },
            abort(reason) {
                console.error(`DNS connection aborted`, reason);
            }
        }));
    } catch (error) {
        console.error('DNS query error:', error.message);
    }
}

async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port });

    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    const writer = socket.writable.getWriter();
    await writer.write(socksGreeting);
    log('SOCKS5 greeting sent');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;

    if (res[0] !== 0x05) {
        log(`SOCKS5 version error: ${res[0]}`);
        return;
    }

    if (res[1] === 0x02) {
        log('SOCKS5 authentication required');
        if (!username || !password) {
            log('Missing credentials');
            return;
        }
        const authRequest = new Uint8Array([
            1,
            username.length,
            ...encoder.encode(username),
            password.length,
            ...encoder.encode(password)
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log('SOCKS5 authentication failed');
            return;
        }
    }

    let DSTADDR;
    switch (addressType) {
        case 1:
            DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
            break;
        case 2:
            DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
            break;
        case 3:
            DSTADDR = new Uint8Array([4, ...addressRemote.split(':').flatMap(x => 
                [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
            break;
        default:
            log(`Invalid address type: ${addressType}`);
            return;
    }

    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    await writer.write(socksRequest);
    log('SOCKS5 request sent');

    res = (await reader.read()).value;
    if (res[1] === 0x00) {
        log('SOCKS5 connection established');
    } else {
        log('SOCKS5 connection failed');
        return;
    }

    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

async function httpConnect(addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({ hostname, port });

    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`;
    connectRequest += `\r\n`;

    log(`HTTP CONNECT to ${addressRemote}:${portRemote} via ${hostname}:${port}`);

    try {
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        console.error('HTTP CONNECT request failed:', err);
        throw new Error(`HTTP CONNECT failed: ${err.message}`);
    }

    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                throw new Error('HTTP proxy connection interrupted');
            }

            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            respText = new TextDecoder().decode(responseBuffer);

            if (respText.includes('\r\n\r\n')) {
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                log(`HTTP proxy response: ${headers.split('\r\n')[0]}`);

                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;

                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        const dataStream = new ReadableStream({
                            start(controller) {
                                controller.enqueue(remainingData);
                            }
                        });

                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => 
                            console.error('Remaining data error:', err));
                        sock.readable = readable;
                    }
                } else {
                    throw new Error(`HTTP proxy failed: ${headers.split('\r\n')[0]}`);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`HTTP proxy response error: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
        throw new Error('HTTP proxy connection failed');
    }

    log(`HTTP proxy connected: ${addressRemote}:${portRemote}`);
    return sock;
}

function socks5AddressParser(address) {
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? 
        [address, undefined] : 
        [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    
    let username, password, hostname, port;

    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('Invalid SOCKS address format');
        }
        [username, password] = formers;
    }

    const latters = latter.split(":");
    if (latters.length > 2 && latter.includes("]:")) {
        port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
        hostname = latter.split("]:")[0] + "]";
    } else if (latters.length === 2) {
        port = Number(latters.pop().replace(/[^\d]/g, ''));
        hostname = latters.join(":");
    } else {
        port = 80;
        hostname = latter;
    }

    if (isNaN(port)) {
        throw new Error('Invalid port number');
    }

    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('Invalid IPv6 address format');
    }

    return { username, password, hostname, port };
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: undefined, error: null };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

function isValidIP(ip) {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || 
            socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + 
            byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
            byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
            byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
            byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
            byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + 
            byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + 
            byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw TypeError(`Invalid UUID: ${uuid}`);
    }
    return uuid;
}

async function parseList(content) {
    const replaced = content.replace(/[\t|"'\r\n]+/g, ',').replace(/,+/g, ',');
    let cleaned = replaced;
    if (cleaned.charAt(0) == ',') cleaned = cleaned.slice(1);
    if (cleaned.charAt(cleaned.length - 1) == ',') cleaned = cleaned.slice(0, -1);
    return cleaned.split(',').filter(item => item.trim() !== '');
}

async function nginx() {
    return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}
