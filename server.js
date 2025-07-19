const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Configuração do PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Função helper para executar queries
async function query(text, params) {
    const client = await pool.connect();
    try {
        const result = await client.query(text, params);
        return result;
    } finally {
        client.release();
    }
}

// Middlewares de segurança
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
}));

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por IP
    message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' }
});
app.use('/api/', limiter);

// Rate limiting específico para login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: { error: 'Muitas tentativas de login. Tente novamente em 15 minutos.' }
});

// Servir arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Função para inicializar o banco PostgreSQL
async function initializeDatabase() {
    try {
        console.log('🔄 Inicializando banco PostgreSQL...');

        // Criar tabela users
        await query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                partner VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        `);

        // Criar tabela user_progress
        await query(`
            CREATE TABLE IF NOT EXISTS user_progress (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                challenge_id INTEGER NOT NULL,
                completed BOOLEAN DEFAULT FALSE,
                notes TEXT,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Criar tabela activity_logs
        await query(`
            CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                action VARCHAR(100) NOT NULL,
                description TEXT,
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Criar índices para performance
        await query(`
            CREATE INDEX IF NOT EXISTS idx_user_progress_user_id ON user_progress(user_id);
        `);
        await query(`
            CREATE INDEX IF NOT EXISTS idx_user_progress_challenge_id ON user_progress(challenge_id);
        `);
        await query(`
            CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id);
        `);

        // Criar usuário de exemplo se não existir
        const existingUser = await query('SELECT id FROM users WHERE email = $1', ['joao@email.com']);
        
        if (existingUser.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('123456', 10);
            const result = await query(`
                INSERT INTO users (name, email, password, partner)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            `, ['João Silva', 'joao@email.com', hashedPassword, 'Pedro Santos']);
            
            const userId = result.rows[0].id;
            
            // Adicionar progresso de exemplo
            await query(`
                INSERT INTO user_progress (user_id, challenge_id, completed, notes, completed_at)
                VALUES 
                    ($1, 1, true, 'Escolhi meu irmão como parceiro oficial.', CURRENT_TIMESTAMP),
                    ($1, 2, true, 'Identifiquei que preciso melhorar: exercícios, pontualidade e paciência.', CURRENT_TIMESTAMP)
            `, [userId]);
            
            console.log('✅ Usuário de exemplo criado');
        }

        console.log('✅ Banco PostgreSQL inicializado com sucesso');
    } catch (error) {
        console.error('❌ Erro ao inicializar banco:', error);
        throw error;
    }
}

// Middleware de autenticação
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acesso requerido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'intellimen-secret-key', async (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        
        // Buscar dados atualizados do usuário
        try {
            const userResult = await query('SELECT id, name, email, partner FROM users WHERE id = $1', [user.id]);
            if (userResult.rows.length === 0) {
                return res.status(403).json({ error: 'Usuário não encontrado' });
            }
            req.user = userResult.rows[0];
            next();
        } catch (error) {
            console.error('Erro ao buscar usuário:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    });
}

// Função para log de atividades
async function logActivity(userId, action, description, req) {
    try {
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('User-Agent');
        
        await query(`
            INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5)
        `, [userId, action, description, ipAddress, userAgent]);
    } catch (error) {
        console.error('Erro ao registrar atividade:', error);
    }
}

// ROTAS DE AUTENTICAÇÃO

// Registrar usuário
app.post('/api/register', async (req, res) => {
    const { name, email, password, partner } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Nome, email e senha são obrigatórios' });
    }
    
    try {
        // Verificar se usuário já existe
        const existingUser = await query('SELECT id FROM users WHERE email = $1', [email]);
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }
        
        // Hash da senha
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Inserir novo usuário
        const result = await query(`
            INSERT INTO users (name, email, password, partner)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, email, partner
        `, [name, email, hashedPassword, partner || 'Não definido']);
        
        const newUser = result.rows[0];
        
        // Log da atividade
        await logActivity(newUser.id, 'USER_REGISTERED', 'Novo usuário cadastrado', req);
        
        res.json({ message: 'Usuário cadastrado com sucesso', user: newUser });
    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Login
app.post('/api/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }
    
    try {
        // Buscar usuário
        const userResult = await query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        const user = userResult.rows[0];
        
        // Verificar senha
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        // Atualizar último login
        await query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
        
        // Gerar token JWT
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET || 'intellimen-secret-key',
            { expiresIn: '7d' }
        );
        
        // Log da atividade
        await logActivity(user.id, 'USER_LOGIN', 'Login realizado', req);
        
        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                partner: user.partner
            }
        });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ROTAS DE USUÁRIO

// Obter dados do usuário
app.get('/api/user', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Atualizar dados do usuário
app.put('/api/user', authenticateToken, async (req, res) => {
    const { name, partner } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Nome é obrigatório' });
    }
    
    try {
        await query(`
            UPDATE users 
            SET name = $1, partner = $2
            WHERE id = $3
        `, [name, partner || 'Não definido', req.user.id]);

        await logActivity(req.user.id, 'USER_UPDATED', 'Dados do perfil atualizados', req);
        res.json({ message: 'Dados atualizados com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar usuário:', error);
        res.status(500).json({ error: 'Erro ao atualizar dados' });
    }
});

// ROTAS DE PROGRESSO

// Obter progresso do usuário
app.get('/api/progress', authenticateToken, async (req, res) => {
    try {
        const result = await query(`
            SELECT challenge_id, completed, notes, completed_at
            FROM user_progress 
            WHERE user_id = $1 
            ORDER BY challenge_id
        `, [req.user.id]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar progresso:', error);
        res.status(500).json({ error: 'Erro ao buscar progresso' });
    }
});

// Atualizar progresso de um desafio
app.post('/api/progress/:challengeId', authenticateToken, async (req, res) => {
    const challengeId = parseInt(req.params.challengeId);
    const { completed, notes } = req.body;
    
    if (isNaN(challengeId) || challengeId < 1 || challengeId > 53) {
        return res.status(400).json({ error: 'ID do desafio inválido' });
    }
    
    try {
        // Verificar se registro já existe
        const existingResult = await query(`
            SELECT id FROM user_progress 
            WHERE user_id = $1 AND challenge_id = $2
        `, [req.user.id, challengeId]);
        
        if (existingResult.rows.length > 0) {
            // Atualizar registro existente
            await query(`
                UPDATE user_progress 
                SET completed = $1, notes = $2, completed_at = $3, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = $4 AND challenge_id = $5
            `, [completed, notes || '', completed ? new Date() : null, req.user.id, challengeId]);
        } else {
            // Criar novo registro
            await query(`
                INSERT INTO user_progress (user_id, challenge_id, completed, notes, completed_at)
                VALUES ($1, $2, $3, $4, $5)
            `, [req.user.id, challengeId, completed, notes || '', completed ? new Date() : null]);
        }
        
        await logActivity(req.user.id, 'CHALLENGE_UPDATED', `Desafio #${challengeId} ${completed ? 'concluído' : 'atualizado'}`, req);
        res.json({ message: 'Progresso atualizado com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar progresso:', error);
        res.status(500).json({ error: 'Erro ao atualizar progresso' });
    }
});

// ROTAS DE ESTATÍSTICAS

// Obter estatísticas do sistema
app.get('/api/stats', async (req, res) => {
    try {
        const result = await query(`
            SELECT 
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM user_progress WHERE completed = true) as total_challenges_completed,
                (SELECT COUNT(DISTINCT user_id) FROM user_progress WHERE completed = true) as active_users
        `);
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Erro ao buscar estatísticas:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas' });
    }
});

// Rota principal - servir o index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Rota catch-all para SPAs
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Middleware de tratamento de erros
app.use((error, req, res, next) => {
    console.error('Erro não tratado:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
});

// Função para iniciar o servidor
async function startServer() {
    try {
        // Inicializar banco de dados
        await initializeDatabase();
        
        // Iniciar servidor
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Servidor IntelliMen rodando na porta ${PORT}`);
            console.log(`📱 Ambiente: ${process.env.NODE_ENV || 'development'}`);
            if (process.env.NODE_ENV !== 'production') {
                console.log(`🌐 Acesse: http://localhost:${PORT}`);
            }
        });
    } catch (error) {
        console.error('❌ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

// Iniciar o servidor
startServer();

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🔄 Recebido SIGTERM, encerrando graciosamente...');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🔄 Recebido SIGINT, encerrando graciosamente...');
    await pool.end();
    process.exit(0);
});