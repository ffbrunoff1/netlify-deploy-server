import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { nanoid } from 'nanoid';
import { fileURLToPath } from 'url';
import winston from 'winston';
import Joi from 'joi';
import archiver from 'archiver';
import fetch from 'node-fetch'; // <-- ÚNICA NOVA IMPORTAÇÃO ADICIONADA

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
await fs.promises.mkdir(config.tempDir, { recursive: true });
await fs.promises.mkdir(config.logsDir, { recursive: true });

const app = express();

// Configurar trust proxy
app.set('trust proxy', 1);

// Middleware
app.use(express.json({ limit: config.maxFileSize }));
app.use(express.urlencoded({ limit: config.maxFileSize, extended: true }));

const allowedOrigins = [
  'https://lovableproject.com',
  'http://localhost:3000',
  'http://localhost:5173'
  // Adicione aqui a URL exata do seu ambiente de preview, se for fixa.
  // Ex: 'https://afdd7aeb-a01f-470a-a013-1e29dda9c6c1.lovableproject.com'
];

const corsOptions = {
  origin: function (origin, callback ) {
    // Permite requisições sem 'origin' (ex: Postman, curl)
    if (!origin) return callback(null, true);

    // Verifica se a origem está na lista de permitidas
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // Lógica para permitir subdomínios de lovableproject.com
    // Isso cobre 'https://qualquer-coisa.lovableproject.com'
    const isLovableSubdomain = /^https:\/\/[a-z0-9-]+\.lovableproject\.com$/.test(origin );
    if (isLovableSubdomain) {
      return callback(null, true);
    }

    // Se a origem não for permitida
    const msg = 'A política de CORS para este site não permite acesso da origem especificada.';
    return callback(new Error(msg), false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204 // Retorna 204 para preflight, é mais moderno e evita problemas
};

// Aplica o middleware CORS com as opções configuradas
app.use(cors(corsOptions));

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

// ==========================================
// NOVAS FUNÇÕES PARA INTEGRAÇÃO COM NETLIFY
// ==========================================

// FUNÇÃO: Criar um site na Netlify com domínio personalizado
const createNetlifySite = async (siteName, netlifyToken) => {
  logger.info('Criando novo site na Netlify com domínio personalizado', { siteName });

  // O domínio base da sua ferramenta (VOCÊ PRECISA CONFIGURAR ESTA VARIÁVEL)
  const CUSTOM_DOMAIN = process.env.CUSTOM_DOMAIN || 'papum.ai';

  // Monta o FQDN (Fully Qualified Domain Name) que queremos
  const fqdn = `${siteName}.${CUSTOM_DOMAIN}`;

  const body = {
    name: siteName,
    custom_domain: fqdn,
  };

  const response = await fetch('https://api.netlify.com/api/v1/sites', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${netlifyToken}`,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorData = await response.json();
    logger.error('Falha ao criar site na Netlify', { error: errorData });
    if (errorData.message && errorData.message.includes('must be unique')) {
        throw new Error(`O nome do site '${siteName}' já está em uso. Tente outro.`);
    }
    throw new Error(`Não foi possível criar o site: ${errorData.message}`);
  }

  const siteData = await response.json();
  logger.info('Site criado com sucesso na Netlify', { 
    siteId: siteData.id,
    customUrl: `https://${fqdn}`
  });
  
  return {
    siteId: siteData.id,
    finalUrl: `https://${fqdn}`
  };
};

// FUNÇÃO: Definir o domínio personalizado como o domínio principal do site
const setPrimaryDomain = async (siteId, customDomain, netlifyToken) => {
  logger.info('Definindo domínio principal na Netlify', { siteId, customDomain });

  // O corpo da requisição para atualizar o site precisa incluir o custom_domain
  const body = {
    custom_domain: customDomain,
  };

  const response = await fetch(`https://api.netlify.com/api/v1/sites/${siteId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${netlifyToken}`,
    },
    body: JSON.stringify(body ),
  });

  if (!response.ok) {
    const errorData = await response.json();
    logger.error('Falha ao definir o domínio principal', { error: errorData });
    throw new Error(`Não foi possível definir o domínio principal: ${errorData.message}`);
  }

  logger.info('Domínio principal definido com sucesso!', { siteId, customDomain });
  const updatedSiteData = await response.json();
  return updatedSiteData;
};

// FUNÇÃO: Configurar as variáveis de ambiente para Netlify Emails
const setEnvironmentVariables = async (siteId, netlifyToken) => {
  const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
  const NETLIFY_EMAILS_SECRET = process.env.NETLIFY_EMAILS_SECRET;

  if (!SENDGRID_API_KEY || !NETLIFY_EMAILS_SECRET) {
    throw new Error('Variáveis de ambiente SENDGRID_API_KEY ou NETLIFY_EMAILS_SECRET não configuradas no servidor.');
  }

  logger.info('Configurando variáveis de ambiente na Netlify', { siteId });

  const body = {
    env: [
      { key: 'NETLIFY_EMAILS_PROVIDER', value: 'sendgrid' },
      { key: 'NETLIFY_EMAILS_PROVIDER_API_KEY', value: SENDGRID_API_KEY },
      { key: 'NETLIFY_EMAILS_SECRET', value: NETLIFY_EMAILS_SECRET },
    ],
  };

  const response = await fetch(`https://api.netlify.com/api/v1/sites/${siteId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${netlifyToken}`,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorData = await response.json();
    logger.error('Falha ao configurar variáveis de ambiente', { error: errorData });
    throw new Error(`Não foi possível configurar as variáveis de ambiente: ${errorData.message}`);
  }

  logger.info('Variáveis de ambiente configuradas com sucesso', { siteId });
};

// FUNÇÃO: Fazer o deploy do ZIP para um site existente
const deployZipToSite = async (siteId, zipPath, netlifyToken) => {
  logger.info('Fazendo deploy do ZIP para o site existente', { siteId });
  const zipBuffer = await fs.promises.readFile(zipPath);

  const response = await fetch(`https://api.netlify.com/api/v1/sites/${siteId}/deploys`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/zip',
      'Authorization': `Bearer ${netlifyToken}`,
    },
    body: zipBuffer,
  });

  if (!response.ok) {
    const errorData = await response.text();
    logger.error('Erro no deploy do ZIP para a Netlify', { status: response.status, error: errorData });
    throw new Error(`Erro no deploy do ZIP (${response.status}): ${errorData}`);
  }

  const deployData = await response.json();
  logger.info('Deploy do ZIP bem-sucedido!', { url: deployData.ssl_url, deployId: deployData.id });
  return deployData;
};

// ==========================================
// FUNÇÕES ORIGINAIS (MANTIDAS INTACTAS)
// ==========================================

// Função para executar comandos (VERSÃO FINAL E CORRETA)
const executeCommand = (command, args, cwd, timeout = config.buildTimeout) => {
  return new Promise((resolve, reject) => {
    const fullCommand = `${command} ${args.join(' ')}`;
    logger.info(`Executando comando: ${fullCommand}`, { cwd });

    // AQUI ESTÁ A CORREÇÃO: shell: true é NECESSÁRIO.
    // O comando completo é passado como primeiro argumento.
    const process = spawn(fullCommand, [], { 
      cwd, 
      shell: true, // ESSENCIAL PARA O AMBIENTE DO RENDER ENCONTRAR O VITE
      stdio: 'pipe'
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
        logger.error(`Comando falhou`, { command, code, stderr, stdout });
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

// Função para instalar dependências (VERSÃO CORRETA E MAIS SEGURA)
const installDependencies = async (projectDir) => {
  logger.info('Instalando TODAS as dependências (incluindo dev)', { projectDir });

  // A forma mais segura de garantir que devDependencies sejam instaladas
  // é setar o NODE_ENV para 'development' temporariamente para o comando.
  // No entanto, o spawn do Node não tem uma forma fácil de fazer isso cross-platform.
  // A flag do npm é a melhor abordagem. A flag correta é --omit=dev (para omitir)
  // então para incluir, nós simplesmente não a usamos e garantimos que NODE_ENV não seja 'production'.
  // A flag '--include=dev' é uma opção, mas a mais comum é controlar pelo NODE_ENV.

  // Vamos tentar a abordagem mais explícita com a flag de produção desativada.
  try {
    await executeCommand('npm', ['install', '--include=dev'], projectDir);
    logger.info('Dependências instaladas com npm (incluindo dev)');
  } catch (npmError) {
    logger.error('Falha ao instalar dependências com npm', { npmError: npmError.message });
    throw new Error(`Falha ao instalar dependências: ${npmError.message}`);
  }
};

// Função para fazer o build (VERSÃO FINAL E À PROVA DE FALHAS)
const runBuild = async (projectDir) => {
  logger.info('Iniciando build com caminho explícito para o Vite', { projectDir });

  // Caminho absoluto e explícito para o executável do Vite dentro do projeto temporário.
  // Isso elimina qualquer dependência do PATH do sistema.
  const viteExecutablePath = path.join(projectDir, 'node_modules', '.bin', 'vite');

  try {
    // Verificar se o executável do Vite realmente existe após o 'npm install'
    await fs.promises.access(viteExecutablePath);
    logger.info(`Executável do Vite encontrado em: ${viteExecutablePath}`);
  } catch (accessError) {
    logger.error('CRÍTICO: O executável do Vite não foi encontrado após a instalação das dependências.', {
      path: viteExecutablePath,
      error: accessError.message
    });
    throw new Error('Falha crítica: vite não foi instalado corretamente em node_modules/.bin.');
  }

  try {
    // Executar o Vite DIRETAMENTE pelo seu caminho absoluto.
    // O comando é o caminho para o vite, e o argumento é 'build'.
    await executeCommand(viteExecutablePath, ['build'], projectDir);
    logger.info('Build concluído com sucesso usando caminho explícito do Vite.');
  } catch (buildError) {
    logger.error('Build falhou mesmo com caminho explícito do Vite.', {
      error: buildError.message,
      projectDir
    });
    throw new Error(`Build falhou: ${buildError.message}`);
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

const publishToNetlify = async (zipPath, siteName = null) => {
  const NETLIFY_TOKEN = process.env.NETLIFY_AUTH_TOKEN;
  if (!NETLIFY_TOKEN) {
    throw new Error('Token da Netlify não configurado no servidor. Configure a variável NETLIFY_AUTH_TOKEN.');
  }

  const hasEmailConfig = process.env.SENDGRID_API_KEY && process.env.NETLIFY_EMAILS_SECRET;

  if (hasEmailConfig && siteName) {
    logger.info('Usando fluxo completo com domínio personalizado e e-mail', { siteName });
    
    try {
      // Passo 1: Criar o site. A desestruturação aqui muda um pouco.
      const { siteId } = await createNetlifySite(siteName, NETLIFY_TOKEN); // <-- MUDANÇA AQUI (não pegamos mais finalUrl)

      // Passo 1.5 (NOVO): Definir o domínio personalizado como o principal.
      const CUSTOM_DOMAIN = process.env.CUSTOM_DOMAIN || 'papum.ai';
      const fqdn = `${siteName}.${CUSTOM_DOMAIN}`;
      await setPrimaryDomain(siteId, fqdn, NETLIFY_TOKEN); // <-- MUDANÇA AQUI (adicionamos este passo)

      // Passo 2: Configurar as variáveis de ambiente para o e-mail (sem alteração)
      await setEnvironmentVariables(siteId, NETLIFY_TOKEN);

      // Passo 3: Fazer o deploy do código (ZIP) para o site recém-criado (sem alteração)
      const deployData = await deployZipToSite(siteId, zipPath, NETLIFY_TOKEN);

      // Monta a URL final com o domínio personalizado correto
      const finalUrl = `https://${fqdn}`;

      // Retorna os dados com a URL personalizada (sem alteração )
      return { ...deployData, ssl_url: finalUrl, url: finalUrl };

    } catch (error) {
      logger.error('Falha no processo de publicação orquestrada na Netlify', { error: error.message });
      throw error;
    }
  } else {
    // ================================================================
    // O BLOCO 'ELSE' INTEIRO DEVE PERMANECER EXATAMENTE COMO ESTÁ.
    // ELE NÃO DEVE SER REMOVIDO.
    // ================================================================
    logger.info('Usando fluxo original da Netlify', { zipPath, siteName });

    try {
      const zipBuffer = await fs.promises.readFile(zipPath);
      
      let apiUrl = 'https://api.netlify.com/api/v1/sites';
      
      if (siteName ) {
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
  }
};

// Função para limpar arquivos temporários antigos
const cleanupOldFiles = async () => {
  try {
    const entries = await fs.promises.readdir(config.tempDir, { withFileTypes: true });
    const now = Date.now();
    
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const dirPath = path.join(config.tempDir, entry.name);
        const stats = await fs.promises.stat(dirPath);
        
        if (now - stats.mtime.getTime() > config.maxTempAge) {
          await fs.promises.rm(dirPath, { recursive: true, force: true });
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
    await fs.promises.mkdir(projectDir, { recursive: true });
    
    // Escrever arquivos
    await Promise.all(
      Object.entries(files).map(async ([filePath, content]) => {
        const fullPath = path.join(projectDir, filePath);
        const dir = path.dirname(fullPath);
        await fs.promises.mkdir(dir, { recursive: true });
        await fs.promises.writeFile(fullPath, content, 'utf8');
      })
    );

// ================================================================
// INÍCIO DA INJEÇÃO DE DEPENDÊNCIA
// ================================================================
logger.info('Injetando dependência de e-mail no package.json', { deployId });

const packageJsonPath = path.join(projectDir, 'package.json');
try {
  // Lê o conteúdo atual do package.json
  const packageJsonContent = await fs.promises.readFile(packageJsonPath, 'utf8');
  const packageJson = JSON.parse(packageJsonContent);

  // Garante que a seção devDependencies exista para evitar erros
  if (!packageJson.devDependencies) {
    packageJson.devDependencies = {};
  }
  
  // Adiciona o plugin do Netlify Emails à lista de dependências de desenvolvimento
  // Usamos uma versão específica para garantir consistência.
  packageJson.devDependencies['@netlify/plugin-emails'] = '^1.1.1';

  // Sobrescreve o arquivo package.json com a versão modificada
  await fs.promises.writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2));
  
  logger.info('Dependência @netlify/plugin-emails injetada com sucesso.', { deployId });

} catch (e) {
  // Se o package.json não for encontrado ou houver um erro de parse, o deploy falha com uma mensagem clara.
  logger.error('Falha ao modificar o package.json. Verifique se o arquivo foi enviado corretamente.', { error: e.message });
  throw new Error('Não foi possível encontrar ou modificar o package.json do projeto.');
}
    
    logger.info('Arquivos escritos, iniciando build', { deployId });
    
    // Instalar dependências
    await installDependencies(projectDir);
    
    // Fazer build
    await runBuild(projectDir);
    
    // Verificar se o build foi bem-sucedido
    const distPath = path.join(projectDir, 'dist');
    const indexPath = path.join(distPath, 'index.html');
    
    try {
      await fs.promises.access(indexPath);
    } catch {
      throw new Error('Build falhou: index.html não encontrado na pasta dist');
    }
    
    // Criar ZIP da pasta dist
    const zipPath = await createZipFromDist(projectDir);
    
    // Publicar na Netlify
    const deployData = await publishToNetlify(zipPath, siteName);

    logger.info('RESPOSTA COMPLETA RECEBIDA DO NETLIFY:', { 
      data: JSON.stringify(deployData, null, 2) 
    });
    
    logger.info('Deploy concluído com sucesso', { 
      deployId, 
      netlifyUrl: deployData.ssl_url,
      siteId: deployData.site_id 
    });
    
    // Primeiro, vamos logar o que recebemos do Netlify para ter certeza
logger.info('Dados recebidos do Netlify para montar a resposta:', { deployData });

// Montamos a resposta final PLANA, sem o objeto "deploy" aninhado.
res.json({
  success: true,
  message: 'Deploy concluído com sucesso na Netlify',
  
  // Os dados do deploy vão diretamente no corpo da resposta,
  // exatamente como a função parseDeployResponse no frontend espera.
  id: deployData.id || '',
  deploy_id: deployData.deploy_id || '',
  subdomain: deployData.subdomain || '',
  url: deployData.url || '',
  state: deployData.state || 'uploaded',
  required: deployData.required || []
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
      await fs.promises.rm(projectDir, { recursive: true, force: true });
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
