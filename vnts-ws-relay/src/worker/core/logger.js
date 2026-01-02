let globalLogger = null;  
let isInitialized = false;  
  
export class Logger {  
  constructor(env) {  
    this.env = env;  
    this.levels = {  
      error: 0,  
      warn: 1,   
      info: 2,  
      debug: 3  
    };  
      
    // 获取配置的日志级别，支持大小写兼容  
    const configLevel = (env.LOG_LEVEL || 'warn').toLowerCase();  
    this.currentLevel = this.levels[configLevel] ?? this.levels.warn;  
  }  
  
  shouldLog(level) {  
    return this.levels[level] <= this.currentLevel;  
  }  
  
  formatTimestamp() {  
    const now = new Date();  
    const year = now.getFullYear();  
    const month = String(now.getMonth() + 1).padStart(2, '0');  
    const day = String(now.getDate()).padStart(2, '0');  
    const hours = String(now.getHours()).padStart(2, '0');  
    const minutes = String(now.getMinutes()).padStart(2, '0');  
    const seconds = String(now.getSeconds()).padStart(2, '0');  
    return `[${year}-${month}-${day} ${hours}:${minutes}:${seconds}]`;  
  }  
  
  getCallerInfo() {  
    const stack = new Error().stack;  
    const lines = stack.split('\n');  
    const callerLine = lines[3] || '';  
      
    // 提取文件名和行号  
    const pathMatch = callerLine.match(/\/([^\/]+\.js):(\d+):(\d+)$/);  
    if (pathMatch) {  
      const filename = pathMatch[1];  
      const lineNumber = pathMatch[2];  
      return `[${filename} ${lineNumber}]`;  
    }  
      
    // 备用方案：只提取行号  
    const lineMatch = callerLine.match(/:(\d+):(\d+)$/);  
    if (lineMatch) {  
      return `[unknown.js ${lineMatch[1]}]`;  
    }  
      
    return '[unknown.js 0]';  
  }  
  
  createLogMessage(level, ...args) {  
    const timestamp = this.formatTimestamp();  
    const callerInfo = this.getCallerInfo();  
    const message = args.map(arg =>   
      typeof arg === 'object' ? JSON.stringify(arg) : String(arg)  
    ).join(' ');  
      
    return `${timestamp} [${level.toUpperCase()}] ${callerInfo}: ${message}`;  
  }  
  
  error(...args) {  
    if (this.shouldLog('error')) {  
      console.error(this.createLogMessage('error', ...args));  
    }  
  }  
  
  warn(...args) {  
    if (this.shouldLog('warn')) {  
      console.warn(this.createLogMessage('warn', ...args));  
    }  
  }  
  
  info(...args) {  
    if (this.shouldLog('info')) {  
      console.log(this.createLogMessage('info', ...args));  
    }  
  }  
  
  debug(...args) {  
    if (this.shouldLog('debug')) {  
      console.log(this.createLogMessage('debug', ...args));  
    }  
  }  
}  
  
// 智能自动初始化函数  
function autoInitialize() {  
  if (isInitialized) return;  
    
  // 尝试多种方式获取LOG_LEVEL配置  
  let logLevel = 'warn';  
    
  // 方式1: 从globalThis获取（如果已设置）  
  if (typeof globalThis !== 'undefined' && globalThis.LOG_LEVEL) {  
    logLevel = globalThis.LOG_LEVEL;  
  }  
  // 方式2: 从全局变量获取（兼容性）  
  else if (typeof LOG_LEVEL !== 'undefined') {  
    logLevel = LOG_LEVEL;  
  }  
  // 方式3: 从process.env获取（Node.js环境）  
  else if (typeof process !== 'undefined' && process.env && process.env.LOG_LEVEL) {  
    logLevel = process.env.LOG_LEVEL;  
  }  
    
  const env = { LOG_LEVEL: logLevel };  
  globalLogger = new Logger(env);  
  isInitialized = true;  
}  
  
// 导出全局logger，自动初始化  
export const logger = {  
  error: (...args) => {  
    if (!isInitialized) autoInitialize();  
    globalLogger?.error(...args);  
  },  
  warn: (...args) => {  
    if (!isInitialized) autoInitialize();  
    globalLogger?.warn(...args);  
  },  
  info: (...args) => {  
    if (!isInitialized) autoInitialize();  
    globalLogger?.info(...args);  
  },  
  debug: (...args) => {  
    if (!isInitialized) autoInitialize();  
    globalLogger?.debug(...args);  
  },  
};  
  
// 可选：手动设置全局日志级别  
export function setGlobalLogLevel(level) {  
  if (typeof globalThis !== 'undefined') {  
    globalThis.LOG_LEVEL = level;  
  }  
  // 重新初始化  
  globalLogger = new Logger({ LOG_LEVEL: level });  
  isInitialized = true;  
}
