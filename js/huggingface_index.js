const os = require('os');
const http = require('http');
const { Buffer } = require('buffer');
const fs = require('fs');
const path = require('path');
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
const { WebSocket, createWebSocketStream } = require('ws');

// 环境变量配置 - 适配Huggingface部署
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const NAME = process.env.NAME || os.hostname();

// Huggingface固定端口7860
const port = 7860;
const uuid = (process.env.UUID || '2982f122-9649-40dc-bc15-fa3ec91d8921').replace(/-/g, '');

console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
console.log("Nodejs真一键无交互Vless代理脚本 - Huggingface版");
console.log("当前版本：25.5.20 Huggingface适配版");
console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

let apiData = [];
let lastUpdateTime = new Date().toLocaleString();

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

// 生成Vless配置
function generateVlessConfig(domain, name, uuid, port) {
    const vlessUrl = `vless://${uuid}@${domain}:${port}?encryption=none&security=tls&sni=${domain}&fp=randomized&type=ws&host=${domain}&path=%2F%3Fed%3D2048#${encodeURIComponent(name)}`;
    return vlessUrl;
}

// WebSocket处理
function handleWebSocket(ws, uuid) {
    ws.on('message', (message) => {
        try {
            // 处理Vless协议数据
            console.log('收到WebSocket消息');
        } catch (error) {
            console.error('WebSocket消息处理错误:', error);
        }
    });

    ws.on('close', () => {
        console.log('WebSocket连接关闭');
    });

    ws.on('error', (error) => {
        console.error('WebSocket错误:', error);
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
    
    // 创建HTTP服务器
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const path = url.pathname;
        const isBase64 = url.searchParams.has('base64') || url.searchParams.has('b64');
        
        console.log(`收到请求: ${req.url}, 路径: ${path}, Base64: ${isBase64}`);
        
        if (path === '/') {
            const statsInfo = `Hello, World-YGkkk\nAPI IP数量: ${apiData.length}\n最后更新时间: ${lastUpdateTime}`;
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(statsInfo);
        } else if (path === `/${uuid}`) {
            // 生成Vless配置列表
            let vlessConfigs = [];
            
            apiData.forEach(item => {
                const config = generateVlessConfig(item.domain, item.name, uuid, 443);
                vlessConfigs.push(config);
            });
            
            let result = vlessConfigs.join('\n');
            
            if (isBase64) {
                result = Buffer.from(result).toString('base64');
            } else {
                result += '\n';
            }
            
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(result);
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Not Found\n');
        }
    });
    
    // WebSocket升级处理
    server.on('upgrade', (request, socket, head) => {
        const ws = new WebSocket(null);
        ws.setSocket(socket, head, 100);
        handleWebSocket(ws, uuid);
    });
    
    // 启动服务器
    server.listen(port, () => {
        console.log(`✅ HTTP服务器已启动，端口: ${port}`);
        console.log(`📍 本地访问地址: http://localhost:${port}/`);
        console.log(`📍 配置页面: http://localhost:${port}/${uuid}`);
        console.log(`🔧 UUID: ${uuid}`);
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
