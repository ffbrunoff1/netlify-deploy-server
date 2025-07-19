import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import { nanoid } from 'nanoid';
import { fileURLToPath } from 'url';
import winston from 'winston';
import Joi from 'joi';
import archiver from 'archiver';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuração
const config = {
  port: process.env.PORT || 10000,
  tempDir: path.join(__dirname, 'temp'),
  logsDir: path.join(__dirname, 'logs'),
  maxFileSize: '50mb',
  buildTimeout: 300000, // 5 minutos
  cleanupInterval: 1800000, // 30 minutos
  maxTempAge: 3600000 // 1 hora
};

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'netlify-deploy-server' },
  transports: [
    new winston.transports.File({ filename: path.join(config.logsDir, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(config.logsDir, 'combined.log') }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Criar diretórios necessários
await fs.mkdir(config.tempDir, { recursive: true });
await fs.mkdir(config.logsDir, { recursive: true });

const app = express();

// Configurar trust proxy
app.set('trust proxy', 1);

// Middleware
app.use(express.json({ limit: config.maxFileSize }));
app.use(express.urlencoded({ limit: config.maxFileSize, extended: true }));

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 50, // máximo 50 requests por IP por janela
  message: 'Muitas requisições deste IP, tente novamente em 15 minutos.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Middleware de logging
app.use((req, res, next) => {
  if (req.path !== '/health') {
    logger.info(`${req.method} ${req.path}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
  }
  next();
});

// Esquema de validação
const deployRequestSchema = Joi.object({
  files: Joi.object().pattern(
    Joi.string(),
    Joi.string().allow('')
  ).required(),
  siteName: Joi.string().optional()
});

// Função para executar comandos
const executeCommand = (command, args, cwd, timeout = config.buildTimeout) => {
  return new Promise((resolve, reject) => {
    logger.info(`Executando comando: ${command} ${args.join(' ')}`, { cwd });
    
    const process = spawn(command, args, { 
      cwd, 
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: true 
    });
    
    let stdout = '';
    let stderr = '';
    
    process.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    process.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    const timer = setTimeout(() => {
      process.kill('SIGKILL');
      reject(new Error(`Comando expirou após ${timeout}ms`));
    }, timeout);
    
    process.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) {
        logger.info(`Comando concluído com sucesso`, { command, code });
        resolve({ stdout, stderr, code });
      } else {
        logger.error(`Comando falhou`, { command, code, stderr });
        reject(new Error(`Comando falhou com código ${code}: ${stderr}`));
      }
    });
    
    process.on('error', (error) => {
      clearTimeout(timer);
      logger.error(`Erro ao executar comando`, { command, error: error.message });
      reject(error);
    });
  });
};

// Função para instalar dependências
const installDependencies = async (projectDir) => {
  logger.info('Instalando dependências', { projectDir });
  
  // Verificar se pnpm está disponível
  try {
    await executeCommand('pnpm', ['--version'], projectDir, 10000);
    await executeCommand('pnpm', ['install', '--frozen-lockfile'], projectDir);
    logger.info('Dependências instaladas com pnpm');
  } catch (pnpmError) {
    logger.warn('pnpm não disponível, tentando com npm', { error: pnpmError.message });
    try {
      await executeCommand('npm', ['install'], projectDir);
      logger.info('Dependências instaladas com npm');
    } catch (npmError) {
      logger.error('Falha ao instalar dependências', { pnpmError: pnpmError.message, npmError: npmError.message });
      throw new Error('Falha ao instalar dependências com pnpm e npm');
    }
  }
};

// Função para fazer o build
const runBuild = async (projectDir) => {
  logger.info('Iniciando build', { projectDir });
  
  try {
    // Verificar se pnpm está disponível
    await executeCommand('pnpm', ['--version'], projectDir, 10000);
    await executeCommand('pnpm', ['run', 'build'], projectDir);
    logger.info('Build concluído com pnpm');
  } catch (pnpmError) {
    logger.warn('pnpm não disponível para build, tentando com npm', { error: pnpmError.message });
    try {
      await executeCommand('npm', ['run', 'build'], projectDir);
      logger.info('Build concluído com npm');
    } catch (npmError) {
      logger.error('Falha no build', { pnpmError: pnpmError.message, npmError: npmError.message });
      throw new Error('Falha no build com pnpm e npm');
    }
  }
};

// Função para criar ZIP da pasta dist
const createZipFromDist = (projectDir) => {
  return new Promise((resolve, reject) => {
    const distPath = path.join(projectDir, 'dist');
    const zipPath = path.join(projectDir, 'deploy.zip');
    const output = fs.createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    output.on('close', () => {
      logger.info(`ZIP criado com sucesso: ${zipPath} (${archive.pointer()} bytes)`);
      resolve(zipPath);
    });

    archive.on('error', (err) => {
      logger.error('Erro ao criar ZIP', { error: err.message });
      reject(err);
    });

    archive.pipe(output);
    archive.directory(distPath, false);
    archive.finalize();
  });
};

// Função para publicar na Netlify
const publishToNetlify = async (zipPath, siteName = null) => {
  const NETLIFY_TOKEN = process.env.NETLIFY_AUTH_TOKEN;
  if (!NETLIFY_TOKEN) {
    throw new Error('Token da Netlify não configurado no servidor. Configure a variável NETLIFY_AUTH_TOKEN.');
  }

  logger.info('Enviando para Netlify', { zipPath, siteName });

  try {
    const zipBuffer = await fs.readFile(zipPath);
    
    let apiUrl = 'https://api.netlify.com/api/v1/sites';
    
    if (siteName) {
      apiUrl += `?name=${encodeURIComponent(siteName)}`;
    }

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'Authorization': `Bearer ${NETLIFY_TOKEN}`,
      },
      body: zipBuffer,
    });

    if (!response.ok) {
      const errorData = await response.text();
      logger.error('Erro no deploy da Netlify', { status: response.status, error: errorData });
      throw new Error(`Erro no deploy da Netlify (${response.status}): ${errorData}`);
    }

    const deployData = await response.json();
    logger.info('Deploy na Netlify bem-sucedido!', { 
      url: deployData.ssl_url, 
      siteId: deployData.site_id,
      deployId: deployData.id 
    });

    return deployData;
  } catch (error) {
    logger.error('Falha ao publicar na Netlify', { error: error.message });
    throw error;
  }
};

// Função para limpar arquivos temporários antigos
const cleanupOldFiles = async () => {
  try {
    const entries = await fs.readdir(config.tempDir, { withFileTypes: true });
    const now = Date.now();
    
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const dirPath = path.join(config.tempDir, entry.name);
        const stats = await fs.stat(dirPath);
        
        if (now - stats.mtime.getTime() > config.maxTempAge) {
          await fs.rm(dirPath, { recursive: true, force: true });
          logger.info(`Arquivo temporário removido: ${entry.name}`);
        }
      }
    }
  } catch (error) {
    logger.error('Erro na limpeza de arquivos temporários', { error: error.message });
  }
};

// ROTAS

// Rota de saúde
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'netlify-deploy-server',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Rota principal de deploy
app.post('/deploy', async (req, res) => {
  const deployId = nanoid();
  const projectDir = path.join(config.tempDir, deployId);
  
  logger.info('Requisição de deploy recebida', { deployId });
  
  try {
    // Validar entrada
    const { error, value } = deployRequestSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ 
        error: 'Dados inválidos', 
        details: error.details.map(d => d.message) 
      });
    }
    
    const { files, siteName } = value;
    const fileCount = Object.keys(files).length;
    
    if (fileCount === 0) {
      return res.status(400).json({ error: 'Nenhum arquivo fornecido' });
    }
    
    logger.info('Criando projeto para deploy', { deployId, fileCount, siteName });
    
    // Criar diretório do projeto
    await fs.mkdir(projectDir, { recursive: true });
    
    // Escrever arquivos
    await Promise.all(
      Object.entries(files).map(async ([filePath, content]) => {
        const fullPath = path.join(projectDir, filePath);
        const dir = path.dirname(fullPath);
        await fs.mkdir(dir, { recursive: true });
        await fs.writeFile(fullPath, content, 'utf8');
      })
    );
    
    logger.info('Arquivos escritos, iniciando build', { deployId });
    
    // Instalar dependências
    await installDependencies(projectDir);
    
    // Fazer build
    await runBuild(projectDir);
    
    // Verificar se o build foi bem-sucedido
    const distPath = path.join(projectDir, 'dist');
    const indexPath = path.join(distPath, 'index.html');
    
    try {
      await fs.access(indexPath);
    } catch {
      throw new Error('Build falhou: index.html não encontrado na pasta dist');
    }
    
    // Criar ZIP da pasta dist
    const zipPath = await createZipFromDist(projectDir);
    
    // Publicar na Netlify
    const deployData = await publishToNetlify(zipPath, siteName);
    
    logger.info('Deploy concluído com sucesso', { 
      deployId, 
      netlifyUrl: deployData.ssl_url,
      siteId: deployData.site_id 
    });
    
    res.json({
      success: true,
      deployId,
      deploy: {
        url: deployData.ssl_url,
        siteId: deployData.site_id,
        deployId: deployData.id,
        siteName: deployData.name,
        adminUrl: deployData.admin_url,
        createdAt: deployData.created_at
      },
      message: 'Deploy concluído com sucesso na Netlify'
    });
    
  } catch (error) {
    logger.error('Erro no deploy', { deployId, error: error.message, stack: error.stack });
    
    res.status(500).json({
      error: 'Falha no deploy',
      message: error.message,
      deployId
    });
  } finally {
    // Limpar pasta temporária sempre (sucesso ou erro)
    try {
      await fs.rm(projectDir, { recursive: true, force: true });
      logger.info(`Pasta temporária de deploy removida: ${deployId}`);
    } catch (cleanupError) {
      logger.error('Erro na limpeza após deploy', { deployId, error: cleanupError.message });
    }
  }
});

// Middleware de tratamento de erros
app.use((error, req, res, next) => {
  logger.error('Erro não tratado', { 
    error: error.message, 
    stack: error.stack,
    url: req.url,
    method: req.method
  });
  
  res.status(500).json({
    error: 'Erro interno do servidor',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Algo deu errado'
  });
});

// Middleware para rotas não encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// Iniciar limpeza periódica
setInterval(cleanupOldFiles, config.cleanupInterval);

// Iniciar servidor
app.listen(config.port, '0.0.0.0', () => {
  logger.info(`Servidor de deploy Netlify iniciado`, { 
    port: config.port,
    nodeEnv: process.env.NODE_ENV,
    tempDir: config.tempDir
  });
  
  // Limpeza inicial
  cleanupOldFiles();
});

// Tratamento de sinais de encerramento
process.on('SIGTERM', () => {
  logger.info('Recebido SIGTERM, encerrando servidor...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('Recebido SIGINT, encerrando servidor...');
  process.exit(0);
});

// Tratamento de erros não capturados
process.on('uncaughtException', (error) => {
  logger.error('Exceção não capturada', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Promise rejeitada não tratada', { reason, promise });
  process.exit(1);
});

