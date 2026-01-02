import { NetPacket } from "./core/packet.js";
import { VntContext } from "./core/context.js";
import { PacketHandler } from "./core/handler.js";
import { PROTOCOL, TRANSPORT_PROTOCOL } from "./core/constants.js";
import { parseVNTHeaderFast } from "./utils/fast_parser.js";
import { logger } from "./core/logger.js";

export class RelayRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.connections = new Map();
    this.contexts = new Map();
    this.p2p_connections = new Map();  
    this.connection_last_update = new Map();
    this.packetHandler = new PacketHandler(env);

    // 心跳管理
    this.heartbeatTimers = new Map();
    this.heartbeatInterval = parseInt(env.HEARTBEAT_INTERVAL || "60") * 1000;

    // 连接信息存储
    this.connectionInfos = new Map();
    
  }
  // 获取网关IP地址  
  getGatewayIp(clientId) {  
    const context = this.contexts.get(clientId);  
    if (context && context.link_context && context.link_context.network_info) {  
      return context.link_context.network_info.gateway;  
    }  
    return null;  
  }  
  async handleGatewayPing(clientId, uint8Data) {  
  try {  
    logger.debug(`开始处理系统ping包`);  
      
    // 直接修改原始数据包  
    const modifiedData = new Uint8Array(uint8Data);  
      
    // 正确解析VNT头部的源和目标地址  
    const source = (modifiedData[4] << 24) | (modifiedData[5] << 16) |   
                   (modifiedData[6] << 8) | modifiedData[7];  
    const destination = (modifiedData[8] << 24) | (modifiedData[9] << 16) |   
                        (modifiedData[10] << 8) | modifiedData[11];  
      
    console.log(`[调试] 源地址: ${this.packetHandler.formatIp(source)}`);  
    console.log(`[调试] 目标地址: ${this.packetHandler.formatIp(destination)}`);  
      
    // 交换VNT头部的源和目标地址  
    modifiedData[4] = (destination >> 24) & 0xff;  // 新源地址（原目标）  
    modifiedData[5] = (destination >> 16) & 0xff;  
    modifiedData[6] = (destination >> 8) & 0xff;  
    modifiedData[7] = destination & 0xff;  
    modifiedData[8] = (source >> 24) & 0xff;     // 新目标地址（原源）  
    modifiedData[9] = (source >> 16) & 0xff;  
    modifiedData[10] = (source >> 8) & 0xff;  
    modifiedData[11] = source & 0xff;  
      
    console.log(`[调试] VNT头部地址已交换`);  
      
    // 修改IPv4头部的源和目标地址  
    const ipv4HeaderStart = 12;  
    modifiedData[ipv4HeaderStart + 12] = (destination >> 24) & 0xff;  
    modifiedData[ipv4HeaderStart + 13] = (destination >> 16) & 0xff;  
    modifiedData[ipv4HeaderStart + 14] = (destination >> 8) & 0xff;  
    modifiedData[ipv4HeaderStart + 15] = destination & 0xff;  
    modifiedData[ipv4HeaderStart + 16] = (source >> 24) & 0xff;  
    modifiedData[ipv4HeaderStart + 17] = (source >> 16) & 0xff;  
    modifiedData[ipv4HeaderStart + 18] = (source >> 8) & 0xff;  
    modifiedData[ipv4HeaderStart + 19] = source & 0xff;  
      
    // 修改ICMP类型为Echo Reply (0)  
    const icmpStart = ipv4HeaderStart + 20;  
    console.log(`[调试] 原始ICMP类型: ${modifiedData[icmpStart]}`);  
    modifiedData[icmpStart] = 0;  
    console.log(`[调试] 修改后ICMP类型: ${modifiedData[icmpStart]}`);  
      
    // 重新计算校验和  
    modifiedData[icmpStart + 2] = 0;  
    modifiedData[icmpStart + 3] = 0;  
    const icmpData = modifiedData.slice(icmpStart);  
    const icmpChecksum = this.calculateIcmpChecksum(icmpData);  
    modifiedData[icmpStart + 2] = (icmpChecksum >> 8) & 0xff;  
    modifiedData[icmpStart + 3] = icmpChecksum & 0xff;  
    console.log(`[调试] ICMP校验和: 0x${icmpChecksum.toString(16)}`);  
      
    modifiedData[ipv4HeaderStart + 10] = 0;  
    modifiedData[ipv4HeaderStart + 11] = 0;  
    const ipv4Header = modifiedData.slice(ipv4HeaderStart, icmpStart);  
    const ipv4Checksum = this.calculateIpv4Checksum(ipv4Header);  
    modifiedData[ipv4HeaderStart + 10] = (ipv4Checksum >> 8) & 0xff;  
    modifiedData[ipv4HeaderStart + 11] = ipv4Checksum & 0xff;  
    console.log(`[调试] IPv4校验和: 0x${ipv4Checksum.toString(16)}`);  
      
    console.log(`[调试] 响应包长度: ${modifiedData.length}`);  
    logger.info(`[调试] 响应包内容: ${Array.from(modifiedData).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);  
      
    return { buffer: () => modifiedData };  
  } catch (error) {  
    console.error("处理网关ping失败:", error);  
    return null;  
  }  
}  
  
// 添加原始buffer的校验和计算方法  
 // 添加校验和计算方法  
  calculateIcmpChecksum(data) {  
    let sum = 0;  
    for (let i = 0; i < data.length - 1; i += 2) {  
      sum += (data[i] << 8) | data[i + 1];  
    }  
    if (data.length % 2 === 1) {  
      sum += data[data.length - 1] << 8;  
    }  
    sum = (sum >> 16) + (sum & 0xffff);  
    sum += sum >> 16;  
    return ~sum & 0xffff;  
  }  
  
  calculateIpv4Checksum(header) {  
    let sum = 0;  
    for (let i = 0; i < 20; i += 2) {  
      sum += (header[i] << 8) | header[i + 1];  
    }  
    sum = (sum >> 16) + (sum & 0xffff);  
    sum += sum >> 16;  
    return ~sum & 0xffff;  
  }  
  // 更新P2P连接状态  
  updateP2PStatus(clientId, p2pTargets) {  
    this.p2p_connections.set(clientId, new Set(p2pTargets));  
    this.connection_last_update.set(clientId, Date.now());  
  }  
  
  // 检查是否有P2P连接  
  hasP2PConnection(sourceId, targetIp) {  
    const sourceP2P = this.p2p_connections.get(sourceId);  
    if (!sourceP2P) return false;  
      
    // 查找目标客户端ID  
    for (const [clientId, context] of this.contexts) {  
      if (context.virtual_ip === targetIp) {  
        return sourceP2P.has(clientId);  
      }  
    }  
    return false;  
  } 
  // 处理客户端 P2P 状态报告  
handleP2PStatusReport(clientId, p2pList) {  
  const p2pTargets = [];  
  for (const targetInfo of p2pList) {  
    const targetClientId = this.findClientByIp(targetInfo.target_ip);  
    if (targetClientId) {  
      p2pTargets.push(targetClientId);  
    }  
  }  
  this.updateP2PStatus(clientId, p2pTargets);  
}  

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      return this.handleWebSocket(request);
    }

    return new Response("Not Found", { status: 404 });
  }

  async handleWebSocket(request) {
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const clientId = this.generateClientId();
    const addr = this.parseClientAddress(request);

    console.log(
      `[DEBUG] New WebSocket connection: ${clientId} from ${JSON.stringify(
        addr
      )}`
    );

    // 创建 VNT 上下文
    const context = new VntContext({
      linkAddress: addr,
      serverCipher: null,
    });

    this.contexts.set(clientId, context);
    this.connections.set(clientId, server);

    // 初始化连接状态
    this.initializeConnection(clientId, server);

    // 设置 WebSocket 消息处理
    server.addEventListener("message", async (event) => {
      await this.handleMessage(clientId, event.data);
    });

    server.addEventListener("close", (event) => {
      console.log(`[调试] WebSocket关闭: ${clientId}`);
      this.handleClose(clientId);
    });

    server.addEventListener("error", (error) => {
      console.error(`[调试] WebSocket错误 ${clientId}:`, error);
      this.handleClose(clientId);
    });

    // ping/pong 事件监听
    server.addEventListener("ping", () => {
      server.pong();
    });

    server.addEventListener("pong", () => {
      this.updateLastActivity(clientId);
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  // 初始化连接管理
  initializeConnection(clientId, server) {
    console.log(`[调试] 初始化连接: ${clientId}`);
    const connectionInfo = {
      server: server,
      lastActivity: Date.now(),
      clientId: clientId,
      isAlive: true,
    };

    this.connectionInfos.set(clientId, connectionInfo);

    // 启动心跳定时器
    this.startHeartbeat(clientId);

    // 启动定期健康检查
    if (!this.healthCheckInterval) {
      this.healthCheckInterval = setInterval(() => {
        this.checkConnectionHealth();
      }, 300000); // 5分钟
    }
  }
 
  // 启动心跳机制
  startHeartbeat(clientId) {  
  const server = this.connections.get(clientId);  
  if (!server) return;  
  
  const heartbeatId = setInterval(() => {  
    try {  
      // 只检查连接状态，不主动发送心跳包  
      if (server.readyState !== WebSocket.OPEN) {  
        console.log(`[调试] 连接 ${clientId} 已断开`);  
        this.handleClose(clientId);  
      }  
    } catch (error) {  
      console.error(`[调试] 心跳检查失败 ${clientId}:`, error);  
      this.handleClose(clientId);  
    }  
  }, 30000); // 每30秒检查一次连接状态  
  
  this.heartbeatTimers.set(clientId, heartbeatId);  
}

  // 更新最后活动时间
  updateLastActivity(clientId) {
    const connectionInfo = this.getConnectionInfo(clientId);
    if (connectionInfo) {
      connectionInfo.lastActivity = Date.now();
    }
  }

  // 获取连接信息
  getConnectionInfo(clientId) {
    if (!this.connectionInfos) {
      return null;
    }
    return this.connectionInfos.get(clientId);
  }

  // 轻量级 VNT 头部解析（类似 easytier）
  parseVNTHeader(buffer) {
    if (!buffer || buffer.length < 12) return null;

    return {
      source:
        (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7],
      destination:
        (buffer[8] << 24) | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11],
      protocol: buffer[1],
      transportProtocol: buffer[2],
    };
  }

  // 快速转发判断
  shouldFastForward(data) {    
  if (!data || data.length < 12) return false;    
    
  const protocol = data[1];    
  const transport = data[2];    
    
  return (    
    // IPTURN 数据包（最常见）    
    (protocol === 4 && transport === 4) ||    
    // WGIpv4 数据包    
    (protocol === 4 && transport === 2) ||    
    // Ipv4Broadcast 数据包    
    (protocol === 4 && transport === 3) ||  
    // 注意：移除 IPTURN IPv4（ICMP ping）包  
    false  
  );    
}

  // 需要完整解析的包
  requiresFullParsing(data) {
    if (!data || data.length < 12) return true;

    const protocol = data[1];
    // SERVICE 协议和部分 CONTROL 协议需要完整解析
    return protocol === 1 || (protocol === 3 && data[2] >= 3);
  }
  async relayPacket(sourceClientId, data, header) {  
  console.log(`[调试] 中继数据包从 ${sourceClientId} 到 ${header.destination}`);  
    
  // 检查是否禁用中继  
  if (this.env.VNT_DISABLE_RELAY === "1") {  
    console.log("[调试] 中继已禁用，丢弃数据包");  
    return;  
  }  
  
  // 获取源客户端的网络信息  
  const sourceContext = this.contexts.get(sourceClientId);  
  if (!sourceContext || !sourceContext.link_context) {  
    console.log(`[调试] 源客户端 ${sourceClientId} 上下文不存在`);  
    return;  
  }  
  
  // 查找同一网络中的所有在线客户端  
  const networkInfo = sourceContext.link_context.network_info;  
  const targetClient = networkInfo.clients.get(header.destination);  
    
  if (targetClient && targetClient.online) {  
    // 通过服务器中继到目标客户端  
    for (const [clientId, server] of this.connections) {  
      if (clientId === sourceClientId) continue;  
        
      const clientContext = this.contexts.get(clientId);  
      if (clientContext &&   
          clientContext.link_context &&  
          clientContext.link_context.virtual_ip === header.destination) {  
        try {  
          server.send(data);  
          console.log(`[调试] 数据包已中继到 ${clientId}`);  
          break;  
        } catch (error) {  
          console.error(`[调试] 中继到 ${clientId} 失败:`, error);  
        }  
      }  
    }  
  } else {  
    console.log(`[调试] 目标客户端 ${header.destination} 不在线或不存在`);  
  }  
}
  // 高性能消息处理
  async handleMessage(clientId, data) {  
  try {  
    // 确保数据是 Uint8Array  
    let uint8Data;  
    if (data instanceof ArrayBuffer) {  
      uint8Data = new Uint8Array(data);  
    } else if (data instanceof Uint8Array) {  
      uint8Data = data;  
    } else {  
      console.warn(`[调试] 不支持的数据类型: ${typeof data}`);  
      return;  
    }  
  
    // 更新活动时间  
    this.updateLastActivity(clientId);
    const protocol = uint8Data[1];    
    const transport = uint8Data[2];   
    
    // 检测传输协议4的ping包  
if (protocol === 4 && transport === 4) {    
  console.log(`[调试] 检测到传输协议4包，目标=${this.packetHandler.formatIp(uint8Data[8]<<24|uint8Data[9]<<16|uint8Data[10]<<8|uint8Data[11])}`);   
  const header = parseVNTHeaderFast(uint8Data);    
  if (header && header.destination) {    
    const gatewayIp = this.getGatewayIp(clientId);    
    if (header.destination === gatewayIp) {    
      console.log(`[调试] 检测到ping网关（传输协议4），直接响应`);    
      const response = await this.handleGatewayPing(clientId, uint8Data);  
        
      // 关键修复：发送响应包给客户端  
      if (response) {  
        const server = this.connections.get(clientId);  
        if (server && server.readyState === WebSocket.OPEN) {  
          server.send(response.buffer());  
          console.log(`[调试] ICMP响应已发送给客户端`);  
        }  
      }  
      return;  
    }    
  }    
}
  
    // 优先检查快速转发  
    if (this.shouldFastForward(uint8Data)) {  
      const protocol = uint8Data[1];  
      const transport = uint8Data[2];  
      console.log(`[调试] 快速转发: 协议=${protocol}, 传输=${transport}`);  
        
      // 在快速转发中也检查 P2P 连接  
      const header = parseVNTHeaderFast(uint8Data);  
      if (header && header.destination) {  
        if (this.hasP2PConnection(clientId, header.destination)) {  
          console.log(`[调试] 快速路径: ${clientId} 到 ${header.destination} 有P2P连接，跳过中继`);  
          return;  
        }  
      }  
        
      return await this.fastForward(clientId, uint8Data);  
    }  
  
    // 完整解析路径  
    const header = parseVNTHeaderFast(uint8Data);  
        
    if (!header) {  
      return await this.fullParsingPath(clientId, uint8Data);  
    }  
  
    // 数据包智能处理 - 参照 vnts 的优先 P2P 逻辑  
    if (header.isDataPacket && !(uint8Data[1] === 4 && uint8Data[2] === 1)) {  
      const targetIp = header.destination;  
        
      // 优先检查 P2P 连接 - 类似 vnts 的 route_one_p2p 逻辑  
      if (this.hasP2PConnection(clientId, targetIp)) {  
        console.log(`[调试] ${clientId} 到 ${targetIp} 有P2P连接，跳过中继`);  
        return; // 让客户端直连，不中继  
      }  
        
      // 没有 P2P 连接，尝试直接转发  
      const targetClient = this.findClientByIp(targetIp);  
      if (targetClient && targetClient !== clientId) {  
        const server = this.connections.get(targetClient);  
        if (server && server.readyState === WebSocket.OPEN) {  
          server.send(uint8Data);  
          return;  
        }  
      }  
        
      // 目标不在线或无法直连，才考虑服务器中继  
      if (this.env.VNT_DISABLE_RELAY !== "1") {  
        return await this.relayPacket(clientId, uint8Data, header);  
      }  
    }  
  
    // 控制包和服务包需要完整解析  
    if (header.isControlPacket || header.isServicePacket) {  
      return await this.fullParsingPath(clientId, uint8Data);  
    }  
  
    // 其他情况默认广播（但也要检查 P2P）  
    if (header.destination) {  
      if (this.hasP2PConnection(clientId, header.destination)) {  
        console.log(`[调试] 广播路径: ${clientId} 到 ${header.destination} 有P2P连接，跳过中继`);  
        return;  
      }  
    }  
    return await this.fastForward(clientId, uint8Data);  
  } catch (error) {  
    console.error(`[调试] 处理 ${clientId} 消息时出错:`, error);  
  }  
}  
  
// 辅助函数：根据 IP 查找客户端  
findClientByIp(targetIp) {  
  for (const [clientId, context] of this.contexts) {  
    if (context.link_context &&   
        context.link_context.virtual_ip === targetIp) {  
      return clientId;  
    }  
  }  
  return null;  
}

  // 快速转发路径
  async fastForward(clientId, data) {
    console.log(`[DEBUG] Fast forwarding from ${clientId}`);

    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
        }
      } catch (error) {
        console.error(`Fast forward to ${targetClientId} failed:`, error);
      }
    }
  }

  // 完整解析路径（保持 VNT 兼容性）
  async fullParsingPath(clientId, data) {  
  const packet = NetPacket.parse(data);  
  const context = this.contexts.get(clientId);  
  const addr = this.parseClientAddress({ cf: { colo: "unknown" } });  
  
  console.log(`[DEBUG] Full VNT parsing for ${clientId}`);  
  console.log(  
    `[DEBUG] Packet protocol: ${packet.protocol}, transport: ${packet.transportProtocol}`  
  );  
  
  // 检查是否是 P2P 状态报告包  
  if (packet.protocol === PROTOCOL.SERVICE &&   
      packet.transportProtocol === TRANSPORT_PROTOCOL.RegistrationRequest) {  
    try {  
      const payload = packet.get_payload();  
      if (payload && payload.p2p_status) {  
        this.handleP2PStatusReport(clientId, payload.p2p_status);  
      }  
    } catch (e) {  
      // 忽略解析错误  
    }  
  }  
  
  const response = await this.packetHandler.handle(  
    context,  
    packet,  
    addr,  
    clientId  
  );  
  
  if (response) {  
    const server = this.connections.get(clientId);  
    if (server && server.readyState === WebSocket.OPEN) {  
      server.send(response.buffer());  
    }  
  }  
  
  // VNT 协议的广播逻辑 - 添加 P2P 检查  
  if (this.shouldBroadcast(packet)) {  
    // 检查广播目标是否有 P2P 连接  
    if (packet.destination && this.hasP2PConnection(clientId, packet.destination)) {  
      console.log(`[调试] 广播包 ${clientId} 到 ${packet.destination} 有P2P连接，跳过服务器广播`);  
      return;  
    }  
    await this.broadcastPacket(clientId, packet);  
  }  
}

buildHandshakeResponse(clientId) {  
  const context = this.contexts.get(clientId);  
  const response = {  
    // ... 原有字段  
    p2p_targets: Array.from(this.p2p_connections.get(clientId) || []),  
    request_p2p_status: true, // 请求客户端报告 P2P 状态  
    server_p2p_support: true  // 服务器支持 P2P 智能判断  
  };  
  return response;  
}
  // 基于头部的转发
  async headerBasedForward(clientId, data, header) {
    console.log(`[DEBUG] Header-based forwarding from ${clientId}`);

    // 简单的目标查找和转发
    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
        }
      } catch (error) {
        console.error(
          `Header-based forward to ${targetClientId} failed:`,
          error
        );
      }
    }
  }

  // VNT 协议广播判断
  shouldBroadcast(packet) {
    // 保持原有的 VNT 广播逻辑
    if (packet.protocol === PROTOCOL.SERVICE) {
      return false;
    }

    if (packet.protocol === PROTOCOL.ERROR) {
      return false;
    }

    return true;
  }

  async broadcastPacket(senderId, packet) {
    const senderContext = this.contexts.get(senderId);

    for (const [clientId, server] of this.connections) {
      if (clientId === senderId) continue;

      try {
        if (this.shouldForward(senderContext, packet)) {
          console.log(
            `[DEBUG] Broadcasting packet from ${senderId} to ${clientId}`
          );

          const packetCopy = this.copyPacket(packet);
          server.send(packetCopy.buffer());
        }
      } catch (error) {
        console.error(`[DEBUG] Broadcast error to ${clientId}:`, error);
      }
    }
  }

  copyPacket(originalPacket) {
    try {
      const buffer = originalPacket.buffer();
      const copiedBuffer = new Uint8Array(buffer.length);
      copiedBuffer.set(buffer);
      return NetPacket.parse(copiedBuffer);
    } catch (error) {
      console.error(`[DEBUG] Failed to copy packet:`, error);
      return originalPacket;
    }
  }

  shouldForward(context, packet) {
    return packet.protocol !== PROTOCOL.SERVICE;
  }

  handleClose(clientId) {
    console.log(`[调试] 开始清理连接: ${clientId}`);

    const context = this.contexts.get(clientId);

    if (context) {
      try {
        console.log(`[调试] 清理 ${clientId} 的上下文`);
        this.packetHandler.leave(context);
      } catch (error) {
        console.error(`[调试] 清理 ${clientId} 上下文时出错:`, error);
      }
    }

    // 清理心跳定时器
    const heartbeatId = this.heartbeatTimers.get(clientId);
    if (heartbeatId) {
      console.log(`[调试] 停止 ${clientId} 的心跳定时器`);
      clearInterval(heartbeatId);
      this.heartbeatTimers.delete(clientId);
    }

    // 清理连接和上下文
    this.contexts.delete(clientId);
    this.connections.delete(clientId);

    // 清理连接信息
    if (this.connectionInfos) {
      this.connectionInfos.delete(clientId);
    }

    // 如果没有活跃连接了，停止健康检查
    if (this.connections.size === 0 && this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
      console.log(`[调试] 停止健康检查定时器`);
    }

    console.log(`[调试] 连接 ${clientId} 清理完成`);
  }

  generateClientId() {
    return Math.random().toString(36).substr(2, 9);
  }

  parseClientAddress(request) {
    const cf = request.cf;
    return {
      ip: cf?.colo || "unknown",
      port: 0,
    };
  }

  checkConnectionHealth() {
    console.log(`[调试] 开始健康检查，当前连接数: ${this.connections.size}`);

    for (const [clientId, server] of this.connections) {
      if (server.readyState !== WebSocket.OPEN) {
        console.log(`[调试] 连接 ${clientId} 已断开，准备清理`);
        this.handleClose(clientId);
      }
    }

    console.log(`[调试] 健康检查完成`);
  }
}
