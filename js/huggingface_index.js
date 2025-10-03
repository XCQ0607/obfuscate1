const os = require('os');
const http = require('http');
const net = require('net');
const { exec, execSync } = require('child_process');

function ensureModule(name) {
    try {
        require.resolve(name);
    } catch (e) {
        console.log(`Module '${name}' not found. Installing...`);
        execSync(`npm install ${name}`, { stdio: 'inherit' });
    }
}

ensureModule('axios');
ensureModule('ws');

const axios = require('axios');
const { WebSocketServer, createWebSocketStream } = require('ws');

// 环境变量配置 - 适配Huggingface部署
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const NAME = process.env.NAME || os.hostname();

// Vless配置
const UUID = process.env.UUID || '2982f122-9649-40dc-bc15-fa3ec91d8921';
const DOMAIN = process.env.DOMAIN || 'xlinux-test.hf.space'; // 用户需要设置的域名

// 性能配置
const LOG_FLAG = process.env.LOG_FLAG === 'true' || false; // 默认关闭详细日志
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS) || 100000; // 最大并发连接数
const SOCKET_TIMEOUT = parseInt(process.env.SOCKET_TIMEOUT) || 100000; // 连接超时时间

// Huggingface固定端口7860
const port = 7860;
const uuid = UUID;
const uuidNoHyphens = uuid.replace(/-/g, '');

console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
console.log("一键无交互Vless代理脚本 - Huggingface版");
console.log("当前版本：1.0.0 Huggingface适配版");
console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

let apiData = [];
let lastUpdateTime = new Date().toLocaleString();

// 统计信息
let connectionStats = {
    totalConnections: 0,
    activeConnections: 0,
    totalDataTransferred: 0,
    startTime: new Date()
};

// 内置节点列表 - 来自原始app.js
const builtinNodes = [
    // Cloudflare IP地址
    { domain: "104.16.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.17.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.18.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.19.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.20.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.21.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.22.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.24.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.25.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.26.0.0", name: `Vl-ws-tls-${NAME}` },
    { domain: "104.27.0.0", name: `Vl-ws-tls-${NAME}` },
    // 官方优选
    { domain: "cf.090227.xyz", name: "三网自适应分流官方优选" },
    { domain: "ct.090227.xyz", name: "电信官方优选" },
    { domain: "cmcc.090227.xyz", name: "移动官方优选" },
    // 官方域名优选
    { domain: "shopify.com", name: "优选官方域名-shopify" },
    { domain: "time.is", name: "优选官方域名-time" },
    { domain: "icook.hk", name: "优选官方域名-icook.hk" },
    { domain: "icook.tw", name: "优选官方域名-icook.tw" },
    { domain: "ip.sb", name: "优选官方域名-ip.sb" },
    { domain: "japan.com", name: "优选官方域名-japan" },
    { domain: "malaysia.com", name: "优选官方域名-malaysia" },
    { domain: "russia.com", name: "优选官方域名-russia" },
    { domain: "singapore.com", name: "优选官方域名-singapore" },
    { domain: "skk.moe", name: "优选官方域名-skk" },
    { domain: "www.visa.com.sg", name: "优选官方域名-visa.sg" },
    { domain: "www.visa.com.hk", name: "优选官方域名-visa.hk" },
    { domain: "www.visa.com.tw", name: "优选官方域名-visa.tw" },
    { domain: "www.visa.co.jp", name: "优选官方域名-visa.jp" },
    { domain: "www.visakorea.com", name: "优选官方域名-visa.kr" },
    { domain: "www.gco.gov.qa", name: "优选官方域名-gov.qa" },
    { domain: "www.gov.se", name: "优选官方域名-gov.se" },
    { domain: "www.gov.ua", name: "优选官方域名-gov.ua" },
    // 第三方维护
    { domain: "cfip.xxxxxxxx.tk", name: "OTC提供维护官方优选" },
    { domain: "bestcf.onecf.eu.org", name: "Mingyu提供维护官方优选" },
    { domain: "cf.zhetengsha.eu.org", name: "小一提供维护官方优选" },
    { domain: "xn--b6gac.eu.org", name: "第三方维护官方优选" },
    { domain: "yx.887141.xyz", name: "第三方维护官方优选" },
    { domain: "8.889288.xyz", name: "第三方维护官方优选" },
    { domain: "cfip.1323123.xyz", name: "第三方维护官方优选" },
    { domain: "cf.515188.xyz", name: "第三方维护官方优选" },
    { domain: "cf-st.annoy.eu.org", name: "第三方维护官方优选" },
    { domain: "cf.0sm.com", name: "第三方维护官方优选" },
    { domain: "cf.877771.xyz", name: "第三方维护官方优选" },
    { domain: "cf.345673.xyz", name: "第三方维护官方优选" },
    { domain: "bestproxy.onecf.eu.org", name: "Mingyu提供维护反代优选" },
    { domain: "proxy.xxxxxxxx.tk", name: "OTC提供维护反代优选" }
];

// API配置
const apiList = [
    {
        url: 'https://ipdb.api.030101.xyz/?type=bestcf&country=true',
        namePrefix: '优选官方API(1-'
    },
    {
        url: 'https://addressesapi.090227.xyz/CloudFlareYes',
        namePrefix: '优选官方API(2-'
    },
    {
        url: 'https://addressesapi.090227.xyz/ip.164746.xyz',
        namePrefix: '优选官方API(3-'
    },
    {
        url: 'https://ipdb.api.030101.xyz/?type=bestproxy&country=true',
        namePrefix: '优选反代API(1-'
    }
];

// 获取API数据
async function fetchApiData() {
    let allResults = [];

    try {
        for (let apiIndex = 0; apiIndex < apiList.length; apiIndex++) {
            const api = apiList[apiIndex];
            console.log(`正在请求 API: ${api.url}`);

            try {
                const response = await axios.get(api.url, { timeout: 10000 });
                const data = response.data;

                if (Array.isArray(data)) {
                    const results = data.map((item, index) => ({
                        domain: item.ip || item,
                        name: `${api.namePrefix}${index + 1})`
                    }));
                    allResults = allResults.concat(results);
                } else if (typeof data === 'string') {
                    const lines = data.split('\n').filter(line => line.trim());
                    const results = lines.map((line, index) => ({
                        domain: line.trim(),
                        name: `${api.namePrefix}${index + 1})`
                    }));
                    allResults = allResults.concat(results);
                }
            } catch (error) {
                console.error(`API ${api.url} 请求失败:`, error.message);
            }
        }

        console.log(`成功获取 ${allResults.length} 个IP地址`);
        return allResults;
    } catch (error) {
        console.error('获取API数据时出错:', error);
        return [];
    }
}

// 生成Vless配置 - 按照指定格式
function generateVlessConfig(item) {
    // 确保域名格式正确
    const cleanDomain = item.domain.replace(/#.*$/, ''); // 移除可能的注释部分

    // 不进行URL编码，直接使用原始中文名称
    const nodeName = item.name;

    // 按照指定格式构造：vless://${UUID}@${item.domain}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F#${item.name}
    const vlessUrl = `vless://${UUID}@${cleanDomain}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F#${nodeName}`;
    return vlessUrl;
}

// WebSocket处理 - 使用app.js的高效流管道方式
function handleWebSocket(ws, request) {
    const clientIP = request.headers['x-forwarded-for'] || request.headers['x-real-ip'] || request.connection.remoteAddress;
    const userAgent = request.headers['user-agent'] || 'Unknown';

    if (LOG_FLAG) {
        console.log('🔗 WebSocket连接建立:');
        console.log(`  客户端IP: ${clientIP}`);
        console.log(`  User-Agent: ${userAgent}`);
    }

    // 更新连接统计
    connectionStats.totalConnections++;
    connectionStats.activeConnections++;

    // 使用once监听第一条消息（Vless握手）
    ws.once('message', msg => {
        try {
            if (LOG_FLAG) {
                console.log(`📨 收到Vless握手消息 [${clientIP}]:`, {
                    长度: msg.length,
                    前16字节: msg.slice(0, Math.min(16, msg.length)).toString('hex')
                });
            }

            // 解析Vless协议 - 参考app.js的方式
            const [VERSION] = msg;
            const id = msg.slice(1, 17);
            const receivedUuid = id.toString('hex');

            if (LOG_FLAG) {
                console.log(`🔍 Vless协议解析 [${clientIP}]:`, {
                    版本: VERSION,
                    UUID: receivedUuid,
                    是否匹配: receivedUuid === uuidNoHyphens
                });
            }

            // 验证UUID - 使用app.js的验证方式
            if (!id.every((v, i) => v == parseInt(uuidNoHyphens.substr(i * 2, 2), 16))) {
                if (LOG_FLAG) {
                    console.log(`❌ UUID验证失败 [${clientIP}]: 期望 ${uuidNoHyphens}, 收到 ${receivedUuid}`);
                }
                ws.close(1000, 'Invalid UUID');
                return;
            }

            if (LOG_FLAG) {
                console.log(`✅ UUID验证成功 [${clientIP}]`);
            }

            // 解析目标地址 - 使用app.js的解析方式
            let i = msg.slice(17, 18).readUInt8() + 19;
            const port = msg.slice(i, i += 2).readUInt16BE(0);
            const ATYP = msg.slice(i, i += 1).readUInt8();

            let host = '';
            if (ATYP == 1) { // IPv4
                host = msg.slice(i, i += 4).join('.');
            } else if (ATYP == 2) { // 域名
                host = new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8()));
            } else if (ATYP == 3) { // IPv6
                host = msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
                    .map(b => b.readUInt16BE(0).toString(16)).join(':');
            }

            if (LOG_FLAG) {
                console.log(`🎯 目标地址 [${clientIP}]: ${host}:${port}`);
            }

            // 发送Vless响应 - 使用app.js的方式
            ws.send(new Uint8Array([VERSION, 0]));
            if (LOG_FLAG) {
                console.log(`📤 发送Vless握手响应 [${clientIP}]`);
            }

            // 创建WebSocket流 - 使用app.js的高效方式
            const duplex = createWebSocketStream(ws);

            // 建立TCP连接并使用流管道 - 完全按照app.js的方式
            const tcpSocket = net.connect({ host, port }, function () {
                if (LOG_FLAG) {
                    console.log(`🔗 已连接到目标服务器 [${clientIP}]: ${host}:${port}`);
                }

                // 转发握手消息中的剩余数据
                if (i < msg.length) {
                    const extraData = msg.slice(i);
                    this.write(extraData);
                    connectionStats.totalDataTransferred += extraData.length;
                    if (LOG_FLAG) {
                        console.log(`📤 转发额外数据到目标服务器 [${clientIP}]: ${extraData.length} 字节`);
                    }
                }

                // 建立双向流管道 - 完全按照app.js的方式，移除日志以提高性能
                duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);

            }).on('error', (error) => {
                if (LOG_FLAG) {
                    console.error(`❌ TCP连接错误 [${clientIP}]: ${error.message}`);
                }
                if (ws.readyState === 1) {
                    ws.close();
                }
            }).on('close', () => {
                if (LOG_FLAG) {
                    console.log(`🔌 TCP连接关闭 [${clientIP}]`);
                }
                if (ws.readyState === 1) {
                    ws.close();
                }
            });

            // 设置连接超时 - 使用配置的超时时间
            tcpSocket.setTimeout(SOCKET_TIMEOUT, () => {
                if (LOG_FLAG) {
                    console.error(`⏰ TCP连接超时 [${clientIP}]: ${host}:${port}`);
                }
                tcpSocket.destroy();
                if (ws.readyState === 1) {
                    ws.close();
                }
            });

        } catch (error) {
            if (LOG_FLAG) {
                console.error(`❌ Vless握手处理错误 [${clientIP}]:`, error);
            }
            ws.close();
        }
    }).on('error', (error) => {
        if (LOG_FLAG) {
            console.error(`❌ WebSocket错误 [${clientIP}]:`, error);
        }
        connectionStats.activeConnections--;
    }).on('close', (code, reason) => {
        if (LOG_FLAG) {
            console.log(`🔌 WebSocket连接关闭 [${clientIP}]:`, {
                代码: code,
                原因: reason?.toString() || '无'
            });
        }
        connectionStats.activeConnections--;
    });
}

// 启动Nezha监控
function startNezhaMonitoring() {
    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
        let NEZHA_TLS = (NEZHA_PORT === '443') ? '--tls' : '';
        const command = `./server -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --skip-conn --disable-auto-update --skip-procs --report-delay 4 >/dev/null 2>&1 &`;
        try {
            exec(command);
            console.log('Nezha监控已启动');
        } catch (error) {
            console.error(`Nezha监控启动错误: ${error}`);
        }
    } else {
        console.log('未配置Nezha监控，跳过启动');
    }
}

// 主函数
async function main() {
    console.log('正在获取API数据...');
    apiData = await fetchApiData();
    lastUpdateTime = new Date().toLocaleString();

    // 启动Nezha监控
    startNezhaMonitoring();

    // 创建WebSocket服务器
    const wss = new WebSocketServer({ noServer: true });

    // 创建HTTP服务器
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const path = url.pathname;
        const clientIP = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.connection.remoteAddress;

        // 检查Base64参数
        const isBase64 = url.searchParams.has('base64') || url.searchParams.has('b64');

        // 详细的请求日志
        console.log(`\n🌐 收到HTTP请求:`);
        console.log(`  时间: ${new Date().toLocaleString()}`);
        console.log(`  客户端IP: ${clientIP}`);
        console.log(`  方法: ${req.method}`);
        console.log(`  URL: ${req.url}`);
        console.log(`  路径: ${path}`);
        console.log(`  Host: ${req.headers.host}`);
        console.log(`  User-Agent: ${req.headers['user-agent'] || 'Unknown'}`);
        console.log(`  Base64请求: ${isBase64}`);
        console.log(`  所有请求头:`, JSON.stringify(req.headers, null, 2));

        // 设置响应头，确保UTF-8编码
        const headers = {
            'Content-Type': 'text/plain; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        };

        if (path === '/') {
            const totalNodes = builtinNodes.length + apiData.length + (DOMAIN && DOMAIN !== 'your-domain.com' ? 1 : 0);
            const uptime = Math.floor((new Date() - connectionStats.startTime) / 1000);
            const statsInfo = `Hello, World-YGkkk
内置节点数量: ${builtinNodes.length}
API获取节点数量: ${apiData.length}
总节点数量: ${totalNodes}
最后更新时间: ${lastUpdateTime}
UUID: ${uuid}
DOMAIN: ${DOMAIN}

=== 连接统计 ===
总连接数: ${connectionStats.totalConnections}
当前活跃连接: ${connectionStats.activeConnections}
总数据传输: ${(connectionStats.totalDataTransferred / 1024 / 1024).toFixed(2)} MB
运行时间: ${uptime} 秒`;

            if (LOG_FLAG) {
                console.log(`📤 返回根路径响应 [${clientIP}]:`);
                console.log(`  响应长度: ${statsInfo.length}`);
                console.log(`  总节点数: ${totalNodes}`);
                console.log(`  活跃连接: ${connectionStats.activeConnections}`);
            }

            res.writeHead(200, headers);
            res.end(statsInfo);
        } else if (path === `/${uuid}` || path === `/${uuidNoHyphens}`) {
            // 生成Vless配置列表
            let vlessConfigs = [];

            // 首先添加基本域名节点（直连）
            if (DOMAIN && DOMAIN !== 'your-domain.com') {
                const domainNode = { domain: DOMAIN, name: `直连-${NAME}` };
                vlessConfigs.push(generateVlessConfig(domainNode));
            }

            // 添加内置节点
            builtinNodes.forEach(item => {
                const config = generateVlessConfig(item);
                vlessConfigs.push(config);
            });

            // 添加API获取的节点
            apiData.forEach(item => {
                const config = generateVlessConfig(item);
                vlessConfigs.push(config);
            });

            let result = vlessConfigs.join('\n');

            if (LOG_FLAG) {
                console.log(`📤 返回配置页面响应 [${clientIP}]:`);
                console.log(`  配置数量: ${vlessConfigs.length}`);
                console.log(`  Base64编码: ${isBase64}`);
                console.log(`  原始长度: ${result.length}`);
            }

            if (isBase64) {
                // 确保Base64编码正确处理UTF-8
                result = Buffer.from(result, 'utf8').toString('base64');
                if (LOG_FLAG) {
                    console.log(`  Base64长度: ${result.length}`);
                }
            } else {
                result += '\n';
            }

            res.writeHead(200, headers);
            res.end(result);
        } else {
            res.writeHead(404, headers);
            res.end('Not Found\n');
        }
    });

    // WebSocket升级处理
    server.on('upgrade', (request, socket, head) => {
        try {
            if (LOG_FLAG) {
                console.log(`🔄 WebSocket升级请求: ${request.url}`);
            }

            // 使用ws库的WebSocketServer来处理升级
            wss.handleUpgrade(request, socket, head, (ws) => {
                if (LOG_FLAG) {
                    console.log('✅ WebSocket连接已建立');
                }
                handleWebSocket(ws, request);
            });
        } catch (error) {
            if (LOG_FLAG) {
                console.error('❌ WebSocket升级错误:', error);
            }
            socket.end();
        }
    });

    // 优化服务器性能
    server.maxConnections = MAX_CONNECTIONS;
    server.timeout = SOCKET_TIMEOUT;
    server.keepAliveTimeout = 5000;
    server.headersTimeout = 10000;

    // 启动服务器
    server.listen(port, () => {
        console.log(`✅ HTTP服务器已启动，端口: ${port}`);
        console.log(`📍 本地访问地址: http://localhost:${port}/`);
        console.log(`📍 配置页面: http://localhost:${port}/${uuid}`);
        console.log(`🔧 UUID: ${uuid}`);
        console.log(`⚙️ 性能配置:`);
        console.log(`  最大连接数: ${MAX_CONNECTIONS}`);
        console.log(`  连接超时: ${SOCKET_TIMEOUT}ms`);
        console.log(`  详细日志: ${LOG_FLAG ? '开启' : '关闭'}`);
    });

    // 定时更新API数据
    setInterval(async () => {
        console.log('定时更新API数据...');
        apiData = await fetchApiData();
        lastUpdateTime = new Date().toLocaleString();
    }, 300000); // 5分钟更新一次
}

// 启动应用
main().catch(console.error);
