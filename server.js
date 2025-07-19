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
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
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
    message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' },
    standardHeaders: true,
    legacyHeaders: false,
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
                last_login TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, challenge_id)
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

        // Criar tabela system_stats
        await query(`
            CREATE TABLE IF NOT EXISTS system_stats (
                id SERIAL PRIMARY KEY,
                stat_name VARCHAR(100) UNIQUE NOT NULL,
                stat_value INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            CREATE INDEX IF NOT EXISTS idx_user_progress_completed ON user_progress(completed);
        `);
        await query(`
            CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id);
        `);
        await query(`
            CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at);
        `);
        await query(`
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        `);

        // Criar trigger para atualizar updated_at automaticamente
        await query(`
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        `);

        await query(`
            DROP TRIGGER IF EXISTS update_users_updated_at ON users;
            CREATE TRIGGER update_users_updated_at
                BEFORE UPDATE ON users
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        `);

        await query(`
            DROP TRIGGER IF EXISTS update_user_progress_updated_at ON user_progress;
            CREATE TRIGGER update_user_progress_updated_at
                BEFORE UPDATE ON user_progress
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        `);

        // Inicializar estatísticas do sistema
        await query(`
            INSERT INTO system_stats (stat_name, stat_value)
            VALUES 
                ('total_users', 0),
                ('total_challenges_completed', 0),
                ('active_users', 0)
            ON CONFLICT (stat_name) DO NOTHING;
        `);

        // Criar usuário de exemplo se não existir
        const existingUser = await query('SELECT id FROM users WHERE email = $1', ['joao@email.com']);
        
        if (existingUser.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('123456', 12);
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
                    ($1, 1, true, 'Escolhi meu irmão como parceiro oficial. Foi uma decisão acertada!', CURRENT_TIMESTAMP - INTERVAL '5 days'),
                    ($1, 2, true, 'Identifiquei que preciso melhorar: exercícios físicos, pontualidade e paciência com a família.', CURRENT_TIMESTAMP - INTERVAL '3 days'),
                    ($1, 3, true, 'Descobri que sou bom em: resolver problemas, ajudar outros e liderar projetos.', CURRENT_TIMESTAMP - INTERVAL '1 day')
            `, [userId]);
            
            console.log('✅ Usuário de exemplo criado com progresso inicial');
        }

        // Atualizar estatísticas
        await updateSystemStats();

        console.log('✅ Banco PostgreSQL inicializado com sucesso');
    } catch (error) {
        console.error('❌ Erro ao inicializar banco:', error);
        throw error;
    }
}

// Função para atualizar estatísticas do sistema
async function updateSystemStats() {
    try {
        // Total de usuários
        const totalUsers = await query('SELECT COUNT(*) as count FROM users');
        await query(`
            UPDATE system_stats 
            SET stat_value = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE stat_name = 'total_users'
        `, [parseInt(totalUsers.rows[0].count)]);

        // Total de desafios completados
        const totalChallenges = await query('SELECT COUNT(*) as count FROM user_progress WHERE completed = true');
        await query(`
            UPDATE system_stats 
            SET stat_value = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE stat_name = 'total_challenges_completed'
        `, [parseInt(totalChallenges.rows[0].count)]);

        // Usuários ativos (com pelo menos 1 desafio completado)
        const activeUsers = await query('SELECT COUNT(DISTINCT user_id) as count FROM user_progress WHERE completed = true');
        await query(`
            UPDATE system_stats 
            SET stat_value = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE stat_name = 'active_users'
        `, [parseInt(activeUsers.rows[0].count)]);

    } catch (error) {
        console.error('Erro ao atualizar estatísticas:', error);
    }
}

// Middleware de autenticação
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acesso requerido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'intellimen-secret-key-2024', async (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido ou expirado' });
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
        const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
        const userAgent = req.get('User-Agent') || 'Unknown';
        
        await query(`
            INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5)
        `, [userId, action, description, ipAddress, userAgent]);
    } catch (error) {
        console.error('Erro ao registrar atividade:', error);
    }
}

// Middleware para validação de entrada
function validateInput(schema) {
    return (req, res, next) => {
        for (const [field, rules] of Object.entries(schema)) {
            const value = req.body[field];
            
            if (rules.required && (!value || value.trim() === '')) {
                return res.status(400).json({ error: `Campo '${field}' é obrigatório` });
            }
            
            if (value && rules.minLength && value.length < rules.minLength) {
                return res.status(400).json({ error: `Campo '${field}' deve ter pelo menos ${rules.minLength} caracteres` });
            }
            
            if (value && rules.maxLength && value.length > rules.maxLength) {
                return res.status(400).json({ error: `Campo '${field}' deve ter no máximo ${rules.maxLength} caracteres` });
            }
            
            if (value && rules.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                return res.status(400).json({ error: `Campo '${field}' deve ser um email válido` });
            }
        }
        next();
    };
}

// ROTAS DE AUTENTICAÇÃO

// Registrar usuário
app.post('/api/register', 
    validateInput({
        name: { required: true, minLength: 2, maxLength: 255 },
        email: { required: true, email: true, maxLength: 255 },
        password: { required: true, minLength: 6, maxLength: 255 }
    }),
    async (req, res) => {
        const { name, email, password, partner } = req.body;
        
        try {
            // Verificar se usuário já existe
            const existingUser = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
            
            if (existingUser.rows.length > 0) {
                return res.status(400).json({ error: 'Este email já está cadastrado' });
            }
            
            // Hash da senha
            const hashedPassword = await bcrypt.hash(password, 12);
            
            // Inserir novo usuário
            const result = await query(`
                INSERT INTO users (name, email, password, partner)
                VALUES ($1, $2, $3, $4)
                RETURNING id, name, email, partner, created_at
            `, [name.trim(), email.toLowerCase(), hashedPassword, partner ? partner.trim() : 'Não definido']);
            
            const newUser = result.rows[0];
            
            // Log da atividade
            await logActivity(newUser.id, 'USER_REGISTERED', 'Novo usuário cadastrado no IntelliMen', req);
            
            // Atualizar estatísticas
            await updateSystemStats();
            
            res.status(201).json({ 
                message: 'Usuário cadastrado com sucesso! Bem-vindo ao IntelliMen!', 
                user: {
                    id: newUser.id,
                    name: newUser.name,
                    email: newUser.email,
                    partner: newUser.partner
                }
            });
        } catch (error) {
            console.error('Erro no registro:', error);
            res.status(500).json({ error: 'Erro interno do servidor. Tente novamente.' });
        }
    }
);

// Login
app.post('/api/login', 
    loginLimiter,
    validateInput({
        email: { required: true, email: true },
        password: { required: true, minLength: 1 }
    }),
    async (req, res) => {
        const { email, password } = req.body;
        
        try {
            // Buscar usuário
            const userResult = await query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
            
            if (userResult.rows.length === 0) {
                return res.status(401).json({ error: 'Email ou senha incorretos' });
            }
            
            const user = userResult.rows[0];
            
            // Verificar senha
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Email ou senha incorretos' });
            }
            
            // Atualizar último login
            await query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
            
            // Gerar token JWT
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email,
                    name: user.name
                },
                process.env.JWT_SECRET || 'intellimen-secret-key-2024',
                { expiresIn: '30d' }
            );
            
            // Log da atividade
            await logActivity(user.id, 'USER_LOGIN', 'Login realizado com sucesso', req);
            
            res.json({
                token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    partner: user.partner
                },
                message: 'Login realizado com sucesso!'
            });
        } catch (error) {
            console.error('Erro no login:', error);
            res.status(500).json({ error: 'Erro interno do servidor. Tente novamente.' });
        }
    }
);

// ROTAS DE USUÁRIO

// Obter dados do usuário
app.get('/api/user', authenticateToken, (req, res) => {
    res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        partner: req.user.partner
    });
});

// Atualizar dados do usuário
app.put('/api/user', 
    authenticateToken,
    validateInput({
        name: { required: true, minLength: 2, maxLength: 255 }
    }),
    async (req, res) => {
        const { name, partner } = req.body;
        
        try {
            await query(`
                UPDATE users 
                SET name = $1, partner = $2, updated_at = CURRENT_TIMESTAMP
                WHERE id = $3
            `, [name.trim(), partner ? partner.trim() : 'Não definido', req.user.id]);

            await logActivity(req.user.id, 'USER_UPDATED', 'Dados do perfil atualizados', req);
            
            res.json({ 
                message: 'Perfil atualizado com sucesso!',
                user: {
                    id: req.user.id,
                    name: name.trim(),
                    email: req.user.email,
                    partner: partner ? partner.trim() : 'Não definido'
                }
            });
        } catch (error) {
            console.error('Erro ao atualizar usuário:', error);
            res.status(500).json({ error: 'Erro ao atualizar dados. Tente novamente.' });
        }
    }
);

// Deletar conta do usuário
app.delete('/api/user', authenticateToken, async (req, res) => {
    try {
        await logActivity(req.user.id, 'USER_DELETED', 'Conta deletada pelo usuário', req);
        
        // Deletar usuário (cascata remove progresso e logs)
        await query('DELETE FROM users WHERE id = $1', [req.user.id]);
        
        // Atualizar estatísticas
        await updateSystemStats();
        
        res.json({ message: 'Conta deletada com sucesso' });
    } catch (error) {
        console.error('Erro ao deletar usuário:', error);
        res.status(500).json({ error: 'Erro ao deletar conta. Tente novamente.' });
    }
});

// ROTAS DE PROGRESSO

// Obter progresso do usuário
app.get('/api/progress', authenticateToken, async (req, res) => {
    try {
        const result = await query(`
            SELECT 
                challenge_id, 
                completed, 
                notes, 
                completed_at,
                created_at,
                updated_at
            FROM user_progress 
            WHERE user_id = $1 
            ORDER BY challenge_id
        `, [req.user.id]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar progresso:', error);
        res.status(500).json({ error: 'Erro ao buscar progresso. Tente novamente.' });
    }
});

// Obter progresso de um desafio específico
app.get('/api/progress/:challengeId', authenticateToken, async (req, res) => {
    const challengeId = parseInt(req.params.challengeId);
    
    if (isNaN(challengeId) || challengeId < 1 || challengeId > 53) {
        return res.status(400).json({ error: 'ID do desafio inválido' });
    }
    
    try {
        const result = await query(`
            SELECT challenge_id, completed, notes, completed_at, created_at, updated_at
            FROM user_progress 
            WHERE user_id = $1 AND challenge_id = $2
        `, [req.user.id, challengeId]);
        
        if (result.rows.length === 0) {
            return res.json({
                challenge_id: challengeId,
                completed: false,
                notes: '',
                completed_at: null
            });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Erro ao buscar progresso do desafio:', error);
        res.status(500).json({ error: 'Erro ao buscar progresso do desafio' });
    }
});

// Atualizar progresso de um desafio
app.post('/api/progress/:challengeId', 
    authenticateToken,
    async (req, res) => {
        const challengeId = parseInt(req.params.challengeId);
        const { completed, notes } = req.body;
        
        if (isNaN(challengeId) || challengeId < 1 || challengeId > 53) {
            return res.status(400).json({ error: 'ID do desafio inválido (1-53)' });
        }
        
        if (typeof completed !== 'boolean') {
            return res.status(400).json({ error: 'Campo "completed" deve ser true ou false' });
        }
        
        try {
            // Verificar se registro já existe
            const existingResult = await query(`
                SELECT id, completed as was_completed FROM user_progress 
                WHERE user_id = $1 AND challenge_id = $2
            `, [req.user.id, challengeId]);
            
            const cleanNotes = notes ? notes.trim() : '';
            const completedAt = completed ? 'CURRENT_TIMESTAMP' : 'NULL';
            
            if (existingResult.rows.length > 0) {
                // Atualizar registro existente
                await query(`
                    UPDATE user_progress 
                    SET completed = $1, notes = $2, completed_at = ${completedAt}, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $3 AND challenge_id = $4
                `, [completed, cleanNotes, req.user.id, challengeId]);
                
                const wasCompleted = existingResult.rows[0].was_completed;
                if (!wasCompleted && completed) {
                    await logActivity(req.user.id, 'CHALLENGE_COMPLETED', `Desafio #${challengeId} concluído pela primeira vez`, req);
                } else if (wasCompleted && !completed) {
                    await logActivity(req.user.id, 'CHALLENGE_UNCOMPLETED', `Desafio #${challengeId} marcado como não concluído`, req);
                } else {
                    await logActivity(req.user.id, 'CHALLENGE_UPDATED', `Desafio #${challengeId} atualizado`, req);
                }
            } else {
                // Criar novo registro
                if (completed) {
                    await query(`
                        INSERT INTO user_progress (user_id, challenge_id, completed, notes, completed_at)
                        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                    `, [req.user.id, challengeId, completed, cleanNotes]);
                } else {
                    await query(`
                        INSERT INTO user_progress (user_id, challenge_id, completed, notes, completed_at)
                        VALUES ($1, $2, $3, $4, NULL)
                    `, [req.user.id, challengeId, completed, cleanNotes]);
                }
                
                await logActivity(req.user.id, completed ? 'CHALLENGE_COMPLETED' : 'CHALLENGE_STARTED', 
                    `Desafio #${challengeId} ${completed ? 'concluído' : 'iniciado'}`, req);
            }
            
            // Atualizar estatísticas se um desafio foi completado
            if (completed) {
                await updateSystemStats();
            }
            
            res.json({ 
                message: `Desafio #${challengeId} ${completed ? 'concluído' : 'atualizado'} com sucesso!`,
                challenge_id: challengeId,
                completed,
                notes: cleanNotes
            });
        } catch (error) {
            console.error('Erro ao atualizar progresso:', error);
            res.status(500).json({ error: 'Erro ao atualizar progresso. Tente novamente.' });
        }
    }
);

// Resetar todo o progresso de um usuário
app.delete('/api/progress', authenticateToken, async (req, res) => {
    try {
        const deletedCount = await query('DELETE FROM user_progress WHERE user_id = $1', [req.user.id]);
        
        await logActivity(req.user.id, 'PROGRESS_RESET', 'Todo o progresso foi resetado', req);
        await updateSystemStats();
        
        res.json({ 
            message: 'Todo o progresso foi resetado com sucesso',
            deleted_challenges: deletedCount.rowCount
        });
    } catch (error) {
        console.error('Erro ao resetar progresso:', error);
        res.status(500).json({ error: 'Erro ao resetar progresso. Tente novamente.' });
    }
});

// ROTAS DE ESTATÍSTICAS

// Obter estatísticas do usuário
app.get('/api/user/stats', authenticateToken, async (req, res) => {
    try {
        // Estatísticas básicas
        const basicStats = await query(`
            SELECT 
                COUNT(*) as total_progress,
                COUNT(CASE WHEN completed = true THEN 1 END) as completed_challenges,
                COUNT(CASE WHEN completed = false THEN 1 END) as started_challenges,
                MAX(completed_at) as last_completion
            FROM user_progress 
            WHERE user_id = $1
        `, [req.user.id]);
        
        // Progresso por categoria (simulado baseado no ID do desafio)
        const categoryStats = await query(`
            SELECT 
                CASE 
                    WHEN challenge_id BETWEEN 1 AND 10 THEN 'foundation'
                    WHEN challenge_id BETWEEN 11 AND 19 THEN 'discipline'
                    WHEN challenge_id BETWEEN 20 AND 39 THEN 'excellence'
                    WHEN challenge_id BETWEEN 40 AND 53 THEN 'impact'
                    ELSE 'other'
                END as category,
                COUNT(*) as total,
                COUNT(CASE WHEN completed = true THEN 1 END) as completed
            FROM user_progress 
            WHERE user_id = $1
            GROUP BY category
            ORDER BY category
        `, [req.user.id]);
        
        // Atividade recente (últimos 30 dias)
        const recentActivity = await query(`
            SELECT DATE(completed_at) as date, COUNT(*) as challenges_completed
            FROM user_progress 
            WHERE user_id = $1 AND completed = true 
            AND completed_at >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(completed_at)
            ORDER BY date DESC
            LIMIT 30
        `, [req.user.id]);
        
        const stats = basicStats.rows[0];
        const completionRate = stats.total_progress > 0 ? 
            Math.round((stats.completed_challenges / 53) * 100) : 0;
        
        res.json({
            total_challenges: 53,
            completed_challenges: parseInt(stats.completed_challenges),
            started_challenges: parseInt(stats.started_challenges),
            pending_challenges: 53 - parseInt(stats.total_progress),
            completion_rate: completionRate,
            last_completion: stats.last_completion,
            category_progress: categoryStats.rows,
            recent_activity: recentActivity.rows,
            user_level: getUserLevel(parseInt(stats.completed_challenges))
        });
    } catch (error) {
        console.error('Erro ao buscar estatísticas do usuário:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas' });
    }
});

// Obter estatísticas globais do sistema
app.get('/api/stats', async (req, res) => {
    try {
        const systemStats = await query(`
            SELECT stat_name, stat_value, updated_at 
            FROM system_stats 
            ORDER BY stat_name
        `);
        
        // Estatísticas adicionais
        const additionalStats = await query(`
            SELECT 
                (SELECT AVG(completed_count) FROM (
                    SELECT COUNT(*) as completed_count 
                    FROM user_progress 
                    WHERE completed = true 
                    GROUP BY user_id
                ) as user_averages) as avg_challenges_per_user,
                (SELECT COUNT(DISTINCT user_id) FROM user_progress WHERE completed_at >= CURRENT_DATE - INTERVAL '7 days') as active_this_week,
                (SELECT COUNT(DISTINCT user_id) FROM user_progress WHERE completed_at >= CURRENT_DATE - INTERVAL '30 days') as active_this_month
        `);
        
        const stats = {};
        systemStats.rows.forEach(row => {
            stats[row.stat_name] = {
                value: row.stat_value,
                updated_at: row.updated_at
            };
        });
        
        const additional = additionalStats.rows[0];
        
        res.json({
            system_stats: stats,
            avg_challenges_per_user: Math.round(parseFloat(additional.avg_challenges_per_user) || 0),
            active_this_week: parseInt(additional.active_this_week),
            active_this_month: parseInt(additional.active_this_month),
            generated_at: new Date().toISOString()
        });
    } catch (error) {
        console.error('Erro ao buscar estatísticas globais:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas globais' });
    }
});

// ROTAS DE UTILIDADE

// Função helper para determinar nível do usuário
function getUserLevel(completedChallenges) {
    if (completedChallenges >= 53) return { level: 'IntelliMan Completo', emoji: '🏆' };
    if (completedChallenges >= 40) return { level: 'IntelliMan Líder', emoji: '👑' };
    if (completedChallenges >= 30) return { level: 'IntelliMan Fera', emoji: '🔥' };
    if (completedChallenges >= 20) return { level: 'IntelliMan Avançado', emoji: '⭐' };
    if (completedChallenges >= 10) return { level: 'IntelliMan Esforçado', emoji: '💪' };
    if (completedChallenges >= 5) return { level: 'IntelliMan Básico', emoji: '🎯' };
    if (completedChallenges >= 1) return { level: 'IntelliMan Iniciante', emoji: '🌱' };
    return { level: 'Visitante', emoji: '📚' };
}

// Health check
app.get('/api/health', async (req, res) => {
    try {
        await query('SELECT 1');
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            service: 'IntelliMen API',
            version: '1.0.0'
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'ERROR', 
            error: 'Database connection failed',
            timestamp: new Date().toISOString()
        });
    }
});

// Rota para obter informações do desafio
app.get('/api/challenges/:id', (req, res) => {
    const challengeId = parseInt(req.params.id);
    
    if (isNaN(challengeId) || challengeId < 1 || challengeId > 53) {
        return res.status(400).json({ error: 'ID do desafio inválido (1-53)' });
    }
    
    // Dados dos desafios (seria melhor ter isso em banco, mas por simplicidade...)
    const challengesData = {
        1: { title: "Encontrar um Parceiro Oficial", category: "foundation" },
        2: { title: "Identificar Três Coisas para Melhorar", category: "foundation" },
        // ... adicionar todos os 53 se necessário
    };
    
    const challenge = challengesData[challengeId];
    if (!challenge) {
        return res.status(404).json({ error: 'Desafio não encontrado' });
    }
    
    res.json({
        id: challengeId,
        ...challenge
    });
});

// Rota principal - servir o index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Rota catch-all para SPAs
app.get('*', (req, res) => {
    // Se for uma rota de API, retornar 404
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'Endpoint não encontrado' });
    }
    
    // Caso contrário, servir o index.html (para SPAs)
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Middleware de tratamento de erros
app.use((error, req, res, next) => {
    console.error('Erro não tratado:', error);
    
    // Não expor detalhes do erro em produção
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ error: 'Erro interno do servidor' });
    } else {
        res.status(500).json({ 
            error: 'Erro interno do servidor',
            details: error.message,
            stack: error.stack
        });
    }
});

// Função para iniciar o servidor
async function startServer() {
    try {
        // Inicializar banco de dados
        await initializeDatabase();
        
        // Configurar atualização periódica de estatísticas (a cada 5 minutos)
        setInterval(updateSystemStats, 5 * 60 * 1000);
        
        // Iniciar servidor
        const server = app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Servidor IntelliMen rodando na porta ${PORT}`);
            console.log(`📱 Ambiente: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🕒 Iniciado em: ${new Date().toLocaleString('pt-BR')}`);
            if (process.env.NODE_ENV !== 'production') {
                console.log(`🌐 Acesse: http://localhost:${PORT}`);
            }
            console.log('📊 Estatísticas atualizadas a cada 5 minutos');
        });

        // Configurar timeout para requests
        server.timeout = 30000; // 30 segundos
        
    } catch (error) {
        console.error('❌ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🔄 Recebido SIGTERM, encerrando graciosamente...');
    try {
        await pool.end();
        console.log('✅ Conexões do banco fechadas');
        process.exit(0);
    } catch (error) {
        console.error('❌ Erro durante shutdown:', error);
        process.exit(1);
    }
});

process.on('SIGINT', async () => {
    console.log('🔄 Recebido SIGINT, encerrando graciosamente...');
    try {
        await pool.end();
        console.log('✅ Conexões do banco fechadas');
        process.exit(0);
    } catch (error) {
        console.error('❌ Erro durante shutdown:', error);
        process.exit(1);
    }
});

// Tratamento de exceções não capturadas
process.on('uncaughtException', (error) => {
    console.error('❌ Exceção não capturada:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Promise rejeitada não tratada:', reason);
    console.error('Em:', promise);
    process.exit(1);
});

// Iniciar o servidor
startServer();

module.exports = app;