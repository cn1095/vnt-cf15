import { NetPacket } from './packet.js';  
import { PROTOCOL, TRANSPORT_PROTOCOL, ENCRYPTION_RESERVED } from './constants.js';  
import { VntContext, AppCache, NetworkInfo, ClientInfo, Ipv4Addr } from './context.js';  
import { AesCipher, randomU64String } from './crypto.js';  
  
export class PacketHandler {  
  constructor(env) {  
    this.env = env;  
    this.cache = new AppCache();  
    this.serverPeerId = 10000001; // VNT 服务器节点 ID  
  }  
  
  async handle(context, packet, addr, tcpSender) {  
    try {  
      // 检查是否为网关包  
      if (packet.is_gateway()) {  
        return await this.handleServerPacket(context, packet, addr, tcpSender);  
      } else {  
        return await this.handleClientPacket(context, packet, addr);  
      }  
    } catch (error) {  
      console.error('Packet handling error:', error);  
      return this.createErrorPacket(addr, packet.source(), error.message);  
    }  
  }  
  
  async handleServerPacket(context, packet, addr, tcpSender) {  
    const source = packet.source();  
  
    // 处理服务协议 - 握手请求直接处理  
    if (packet.protocol() === PROTOCOL.SERVICE) {  
      switch (packet.transport_protocol()) {  
        case TRANSPORT_PROTOCOL.HandshakeRequest:  
          return await this.handleHandshake(packet, addr);  
          
        case TRANSPORT_PROTOCOL.SecretHandshakeRequest:  
          return await this.handleSecretHandshake(context, packet, addr);  
          
        case TRANSPORT_PROTOCOL.RegistrationRequest:  
          return await this.handleRegistration(context, packet, addr, tcpSender);  
          
        default:  
          break;  
      }  
    }  
  
    // 解密处理  
    const serverSecret = packet.is_encrypt();  
    if (serverSecret) {  
      if (context.server_cipher) {  
        try {  
          context.server_cipher.decrypt_ipv4(packet);  
        } catch (error) {  
          console.error('Decryption failed:', error);  
          return this.createErrorPacket(addr, source, 'Decryption failed');  
        }  
      } else {  
        console.log('No cipher available for encrypted packet');  
        return this.createErrorPacket(addr, source, 'No key');  
      }  
    }  
  
    // 处理解密后的包  
    let response = await this.handleDecryptedPacket(context, packet, addr, tcpSender, serverSecret);  
      
    if (response) {  
      this.setCommonParams(response, source);  
      if (serverSecret && context.server_cipher) {  
        context.server_cipher.encrypt_ipv4(response);  
      }  
    }  
      
    return response;  
  }  
  
  async handleDecryptedPacket(context, packet, addr, tcpSender, serverSecret) {  
    // 如果没有链接上下文，处理基础协议  
    if (!context.link_context) {  
      return await this.handleNotContext(context, packet, addr, tcpSender, serverSecret);  
    }  
  
    // 有链接上下文时的处理  
    if (packet.protocol() === PROTOCOL.Control) {  
      switch (packet.transport_protocol()) {  
        case TRANSPORT_PROTOCOL.Ping:  
          return this.handlePing(packet, context.link_context);  
          
        default:  
          break;  
      }  
    }  
  
    // 数据包转发处理  
    return await this.handleDataForward(context, packet, addr, tcpSender);  
  }  
  
  async handleNotContext(context, packet, addr, tcpSender, serverSecret) {  
    if (packet.protocol() === PROTOCOL.SERVICE) {  
      if (packet.transport_protocol() === TRANSPORT_PROTOCOL.RegistrationRequest) {  
        return await this.handleRegistration(context, packet, addr, tcpSender);  
      }  
    } else if (packet.protocol() === PROTOCOL.CONTROL) {  
      if (packet.transport_protocol() === TRANSPORT_PROTOCOL.AddrRequest) {  
        return this.handleAddrRequest(addr);  
      }  
    }  
      
    // 返回错误，表示需要先建立上下文  
    return this.createErrorPacket(addr, packet.source(), 'No context');  
  }  
  
  async handleHandshake(packet, addr) {  
    try {  
      const payload = packet.payload();  
      const handshakeReq = this.parseHandshakeRequest(payload);  
        
      console.log(`Handshake from ${addr}:`, handshakeReq);  
        
      const response = this.createHandshakeResponse(handshakeReq);  
      return response;  
    } catch (error) {  
      console.error('Handshake error:', error);  
      return this.createErrorPacket(addr, packet.source(), 'Handshake failed');  
    }  
  }  
  
  async handleSecretHandshake(context, packet, addr) {  
    console.log(`Secret handshake from ${addr}`);  
      
    // 这里应该实现 RSA 解密和 AES 密钥交换  
    // 简化实现，实际需要完整的加密逻辑  
    try {  
      const response = NetPacket.new_encrypt(ENCRYPTION_RESERVED);  
      response.set_protocol(PROTOCOL.SERVICE);  
      response.set_transport_protocol(TRANSPORT_PROTOCOL.SecretHandshakeResponse);  
      this.setCommonParams(response, packet.source());  
        
      // 创建加密会话（简化）  
      const cipher = new AesCipher(this.generateRandomKey());  
      context.server_cipher = cipher;  
      this.cache.cipher_session.set(addr, cipher);  
        
      return response;  
    } catch (error) {  
      console.error('Secret handshake error:', error);  
      return this.createErrorPacket(addr, packet.source(), 'Secret handshake failed');  
    }  
  }  
  
  async handleRegistration(context, packet, addr, tcpSender) {  
    try {  
      const payload = packet.payload();  
      const registrationReq = this.parseRegistrationRequest(payload);  
        
      // 验证注册请求  
      this.validateRegistrationRequest(registrationReq);  
        
      // 创建或获取网络信息  
      const networkInfo = this.getOrCreateNetworkInfo(registrationReq.token);  
        
      // 分配虚拟 IP  
      const virtualIp = this.allocateVirtualIp(networkInfo, registrationReq.device_id);  
        
      // 创建客户端信息  
      const clientInfo = new ClientInfo({  
        virtual_ip: virtualIp,  
        device_id: registrationReq.device_id,  
        name: registrationReq.name,  
        version: registrationReq.version,  
        online: true,  
        address: addr,  
        client_secret_hash: registrationReq.client_secret_hash,  
        tcp_sender: tcpSender,  
        timestamp: Date.now()  
      });  
        
      // 添加到网络  
      networkInfo.clients.set(virtualIp, clientInfo);  
      networkInfo.epoch += 1;  
        
      // 创建链接上下文  
      context.link_context = {  
        group: registrationReq.token,  
        virtual_ip: virtualIp,  
        network_info: networkInfo,  
        timestamp: Date.now()  
      };  
        
      // 创建注册响应  
      const response = this.createRegistrationResponse(virtualIp, networkInfo);  
      return response;  
        
    } catch (error) {  
      console.error('Registration error:', error);  
      return this.createErrorPacket(addr, packet.source(), 'Registration failed');  
    }  
  }  
  
  handlePing(packet, linkContext) {  
    const responseSize = 12 + 4 + ENCRYPTION_RESERVED;  
    const response = NetPacket.new_encrypt(responseSize);  
      
    response.set_protocol(PROTOCOL.CONTROL);  
    response.set_transport_protocol(TRANSPORT_PROTOCOL.Pong);  
      
    // 复制 ping 负载  
    const payload = packet.payload();  
    response.set_payload(payload.slice(0, 12));  
      
    // 设置 epoch  
    const pongPayload = response.payload_mut();  
    const view = new DataView(pongPayload.buffer, pongPayload.byteOffset);  
    view.setUint16(12, linkContext.network_info.epoch & 0xFFFF, true);  
      
    return response;  
  }  
  
  handleAddrRequest(addr) {  
    const responseSize = 6 + ENCRYPTION_RESERVED;  
    const response = NetPacket.new_encrypt(responseSize);  
      
    response.set_protocol(PROTOCOL.CONTROL);  
    response.set_transport_protocol(TRANSPORT_PROTOCOL.AddrResponse);  
      
    // 设置地址信息  
    const addrPayload = response.payload_mut();  
    const view = new DataView(addrPayload.buffer, addrPayload.byteOffset);  
      
    // 解析 IPv4 地址  
    const ipv4 = this.parseIpv4(addr.ip);  
    view.setUint32(0, ipv4, true);  
    view.setUint16(4, addr.port || 0, true);  
      
    return response;  
  }  
  
  async handleDataForward(context, packet, addr, tcpSender) {  
    // 增加 TTL  
    if (packet.incr_ttl() > 1) {  
      // 检查是否禁用中继  
      if (this.env.VNT_DISABLE_RELAY === '1') {  
        console.log('Relay disabled, dropping packet');  
        return null;  
      }  
        
      const destination = packet.destination();  
        
      if (this.isBroadcast(destination)) {  
        return await this.broadcastPacket(context.link_context, packet);  
      } else {  
        return await this.forwardToDestination(context.link_context, packet, destination);  
      }  
    }  
    return null;  
  }  
  
  async handleClientPacket(context, packet, addr) {  
    // 客户端包处理 - 主要是转发  
    if (!context.link_context) {  
      throw new Error('No link context for client packet');  
    }  
      
    return await this.forwardPacket(context.link_context, packet);  
  }  
  
  async forwardPacket(linkContext, packet) {  
    const destination = packet.destination();  
      
    if (this.isBroadcast(destination)) {  
      return await this.broadcastPacket(linkContext, packet);  
    } else {  
      const targetClient = linkContext.network_info.clients.get(destination);  
      if (targetClient && targetClient.online && targetClient.tcp_sender) {  
        // 发送到特定客户端  
        try {  
          await targetClient.tcp_sender.send(packet.buffer().to_vec());  
        } catch (error) {  
          console.error('Forward failed:', error);  
          targetClient.online = false;  
        }  
      }  
    }  
    return null;  
  }  
  
  async broadcastPacket(linkContext, packet) {  
    const networkInfo = linkContext.network_info;  
    const sender = packet.source();  
      
    for (const [virtualIp, client] of networkInfo.clients) {  
      if (client.virtual_ip !== sender && client.online && client.tcp_sender) {  
        try {  
          await client.tcp_sender.send(packet.buffer().to_vec());  
        } catch (error) {  
          console.error(`Broadcast to ${virtualIp} failed:`, error);  
          client.online = false;  
        }  
      }  
    }  
    return null;  
  }  
  
  async forwardToDestination(linkContext, packet, destination) {  
    const targetClient = linkContext.network_info.clients.get(destination);  
    if (targetClient && targetClient.online && targetClient.tcp_sender) {  
      try {  
        await targetClient.tcp_sender.send(packet.buffer().to_vec());  
      } catch (error) {  
        console.error(`Forward to ${destination} failed:`, error);  
        targetClient.online = false;  
      }  
    }  
    return null;  
  }  
  
  async leave(context) {  
    await context.leave(this.cache);  
  }  
  
  // 辅助方法  
  setCommonParams(packet, source) {  
    packet.set_source(this.serverPeerId);  
    packet.set_destination(source);  
  }  
  
  createErrorPacket(addr, destination, message) {  
    const errorPacket = NetPacket.new_encrypt(ENCRYPTION_RESERVED);  
    errorPacket.set_protocol(PROTOCOL.DATA);  
    this.setCommonParams(errorPacket, destination);  
    return errorPacket;  
  }  
  
  createHandshakeResponse(request) {  
    const responseData = {  
      version: "1.0.0",  
      key_finger: new Uint8Array(32),  
      public_key: new Uint8Array(0),  
      secret: false  
    };  
      
    const responseBytes = this.encodeHandshakeResponse(responseData);  
    const response = NetPacket.new_encrypt(responseBytes.length + ENCRYPTION_RESERVED);  
      
    response.set_protocol(PROTOCOL.SERVICE);  
    response.set_transport_protocol(TRANSPORT_PROTOCOL.HandshakeResponse);  
    response.set_payload(responseBytes);  
      
    return response;  
  }  
  
  createRegistrationResponse(virtualIp, networkInfo) {  
    const responseData = {  
      virtual_ip: virtualIp,  
      netmask: networkInfo.netmask,  
      gateway: networkInfo.gateway,  
      epoch: networkInfo.epoch  
    };  
      
    const responseBytes = this.encodeRegistrationResponse(responseData);  
    const response = NetPacket.new_encrypt(responseBytes.length + ENCRYPTION_RESERVED);  
      
    response.set_protocol(PROTOCOL.SERVICE);  
    response.set_transport_protocol(TRANSPORT_PROTOCOL.RegistrationResponse);  
    response.set_payload(responseBytes);  
      
    return response;  
  }  
  
  getOrCreateNetworkInfo(token) {  
    if (!this.cache.virtual_network.has(token)) {  
      const networkInfo = new NetworkInfo(  
        new Ipv4Addr([10, 0, 0, 0]),  
        new Ipv4Addr([255, 255, 255, 0]),  
        new Ipv4Addr([10, 0, 0, 1])  
      );  
      this.cache.virtual_network.set(token, networkInfo);  
    }  
    return this.cache.virtual_network.get(token);  
  }  
  
  allocateVirtualIp(networkInfo, deviceId) {  
    // 简单的 IP 分配逻辑  
    const baseIp = 0x0A000000; // 10.0.0.0  
    for (let i = 2; i < 254; i++) {  
      const virtualIp = baseIp + i;  
      if (!networkInfo.clients.has(virtualIp)) {  
        return virtualIp;  
      }  
    }  
    throw new Error('No available IP addresses');  
  }  
  
  parseHandshakeRequest(payload) {  
    // 简化的握手请求解析  
    return {  
      version: "1.0.0",  
      key_finger: new Uint8Array(32)  
    };  
  }  
  
  parseRegistrationRequest(payload) {  
    // 简化的注册请求解析  
    return {  
      token: "default",  
      device_id: randomU64String(),  
      name: "client",  
      version: "1.0.0",  
      client_secret_hash: new Uint8Array(0)  
    };  
  }  
  
  validateRegistrationRequest(request) {  
    if (!request.token || request.token.length === 0 || request.token.length > 128) {  
      throw new Error('Invalid token length');  
    }  
    if (!request.device_id || request.device_id.length === 0 || request.device_id.length > 128) {  
      throw new Error('Invalid device_id length');  
    }  
    if (!request.name || request.name.length === 0 || request.name.length > 128) {  
      throw new Error('Invalid name length');  
    }  
  }  
  
  encodeHandshakeResponse(data) {  
    // 简化的编码实现  
    return new Uint8Array(0);  
  }  
  
  encodeRegistrationResponse(data) {  
    // 简化的编码实现  
    return new Uint8Array(0);  
  }  
  
  parseIpv4(ipStr) {  
    if (!ipStr || typeof ipStr !== 'string') {  
      return 0;  
    }  
    const parts = ipStr.split('.').map(Number);  
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];  
  }  
  
  isBroadcast(addr) {  
    return addr === 0xFFFFFFFF || addr === 0;  
  }  
  
  generateRandomKey() {  
    const array = new Uint8Array(32);  
    crypto.getRandomValues(array);  
    return array;  
  }  
}
