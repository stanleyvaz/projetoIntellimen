// server.js - IntelliMen Backend Completo
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'intellimen-secret-key-2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuração do banco de dados SQLite
const db = new sqlite3.Database('./intellimen.db');

// Criar tabelas se não existirem
db.serialize(() => {
    // Tabela de usuários
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        partner TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        reset_token TEXT,
        reset_token_expires DATETIME,
        last_login DATETIME,
        avatar_url TEXT
    )`);

    // Tabela de progresso dos desafios
    db.run(`CREATE TABLE IF NOT EXISTS user_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        challenge_id INTEGER,
        completed BOOLEAN DEFAULT FALSE,
        completed_at DATETIME,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, challenge_id)
    )`);

    // Tabela de estatísticas do sistema
    db.run(`CREATE TABLE IF NOT EXISTS system_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        total_users INTEGER DEFAULT 0,
        total_challenges_completed INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabela de logs de atividades
    db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Inserir dados iniciais se não existirem
    db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
        if (err) {
            console.error('Erro ao verificar usuários:', err);
            return;
        }
        
        if (row.count === 0) {
            console.log('📚 Criando usuário de demonstração...');
            
            // Hash da senha padrão
            bcrypt.hash('123456', 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Erro ao criar hash da senha:', err);
                    return;
                }
                
                // Inserir usuário de demonstração
                db.run(
                    `INSERT INTO users (name, email, password, partner) VALUES (?, ?, ?, ?)`,
                    ['João Silva', 'joao@email.com', hashedPassword, 'Pedro Santos'],
                    function(err) {
                        if (err) {
                            console.error('Erro ao criar usuário de demonstração:', err);
                            return;
                        }
                        
                        console.log('✅ Usuário de demonstração criado com sucesso!');
                        console.log('📧 Email: joao@email.com | 🔑 Senha: 123456');
                        
                        // Inserir progresso de exemplo
                        const userId = this.lastID;
                        const sampleProgress = [
                            { challenge_id: 1, notes: 'Escolhi meu irmão como parceiro oficial.' },
                            { challenge_id: 2, notes: 'Identifiquei que preciso melhorar: exercícios, pontualidade e paciência.' },
                            { challenge_id: 3, notes: 'Minhas qualidades: responsável, determinado, leal.' }
                        ];
                        
                        sampleProgress.forEach(progress => {
                            db.run(
                                `INSERT INTO user_progress (user_id, challenge_id, completed, completed_at, notes) 
                                 VALUES (?, ?, 1, ?, ?)`,
                                [userId, progress.challenge_id, new Date().toISOString(), progress.notes]
                            );
                        });
                    }
                );
            });
        }
    });
});

// Configuração do email (Gmail)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'seu-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'sua-senha-app'
    }
});

// Função para registrar atividades
function logActivity(userId, action, details, req) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    db.run(
        `INSERT INTO activity_logs (user_id, action, details, ip_address, user_agent) 
         VALUES (?, ?, ?, ?, ?)`,
        [userId, action, details, ip, userAgent]
    );
}

// Middleware para verificar JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acesso requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// ROTAS DE AUTENTICAÇÃO

// Registro de usuário
app.post('/api/register', async (req, res) => {
    const { name, email, password, partner } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Nome, email e senha são obrigatórios' });
    }

    try {
        // Verificar se email já existe
        db.get('SELECT email FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                console.error('Erro na verificação de email:', err);
                return res.status(500).json({ error: 'Erro interno do servidor' });
            }

            if (row) {
                return res.status(400).json({ error: 'Email já cadastrado' });
            }

            // Hash da senha
            const hashedPassword = await bcrypt.hash(password, 10);

            // Inserir novo usuário
            db.run(
                'INSERT INTO users (name, email, password, partner) VALUES (?, ?, ?, ?)',
                [name, email, hashedPassword, partner || 'Não definido'],
                function(err) {
                    if (err) {
                        console.error('Erro ao criar usuário:', err);
                        return res.status(500).json({ error: 'Erro ao criar usuário' });
                    }

                    // Gerar token JWT
                    const token = jwt.sign(
                        { id: this.lastID, email, name },
                        JWT_SECRET,
                        { expiresIn: '24h' }
                    );

                    // Registrar atividade
                    logActivity(this.lastID, 'USER_REGISTERED', `Novo usuário: ${name}`, req);

                    res.status(201).json({
                        message: 'Usuário criado com sucesso',
                        token,
                        user: { id: this.lastID, name, email, partner: partner || 'Não definido' }
                    });
                }
            );
        });
    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error('Erro na consulta de usuário:', err);
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Email ou senha incorretos' });
        }

        try {
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Email ou senha incorretos' });
            }

            // Atualizar último login
            db.run('UPDATE users SET last_login = ? WHERE id = ?', [new Date().toISOString(), user.id]);

            // Gerar token JWT
            const token = jwt.sign(
                { id: user.id, email: user.email, name: user.name },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Registrar atividade
            logActivity(user.id, 'USER_LOGIN', 'Login realizado', req);

            res.json({
                message: 'Login realizado com sucesso',
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
});

// Esqueceu a senha
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email é obrigatório' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            console.error('Erro na consulta de usuário:', err);
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }

        if (!user) {
            return res.status(404).json({ error: 'Email não encontrado' });
        }

        // Gerar token de recuperação
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hora

        // Salvar token no banco
        db.run(
            'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?',
            [resetToken, resetTokenExpires, email],
            (err) => {
                if (err) {
                    console.error('Erro ao salvar token:', err);
                    return res.status(500).json({ error: 'Erro ao gerar token de recuperação' });
                }

                // Enviar email (se configurado)
                if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
                    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;
                    
                    const mailOptions = {
                        from: process.env.EMAIL_USER,
                        to: email,
                        subject: 'IntelliMen - Recuperação de Senha',
                        html: `
                            <h2>Recuperação de Senha - IntelliMen</h2>
                            <p>Olá, ${user.name}!</p>
                            <p>Você solicitou a recuperação de sua senha. Clique no link abaixo para criar uma nova senha:</p>
                            <a href="${resetUrl}" style="background: #000; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Redefinir Senha</a>
                            <p>Este link expira em 1 hora.</p>
                            <p>Se você não solicitou esta recuperação, ignore este email.</p>
                            <hr>
                            <p><strong>IntelliMen</strong> - 53 Desafios Para Homens Inteligentes</p>
                        `
                    };

                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            console.error('Erro ao enviar email:', error);
                            return res.status(500).json({ error: 'Erro ao enviar email de recuperação' });
                        }
                        
                        logActivity(user.id, 'PASSWORD_RESET_REQUESTED', 'Token de recuperação enviado', req);
                        res.json({ message: 'Email de recuperação enviado com sucesso' });
                    });
                } else {
                    // Para demonstração, retornar o token diretamente
                    res.json({ 
                        message: 'Token de recuperação gerado (DEMO MODE)', 
                        resetToken: resetToken 
                    });
                }
            }
        );
    });
});

// Redefinir senha
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token e nova senha são obrigatórios' });
    }

    db.get(
        'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?',
        [token, new Date()],
        async (err, user) => {
            if (err) {
                console.error('Erro na consulta de token:', err);
                return res.status(500).json({ error: 'Erro interno do servidor' });
            }

            if (!user) {
                return res.status(400).json({ error: 'Token inválido ou expirado' });
            }

            try {
                // Hash da nova senha
                const hashedPassword = await bcrypt.hash(newPassword, 10);

                // Atualizar senha e remover token
                db.run(
                    'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
                    [hashedPassword, user.id],
                    (err) => {
                        if (err) {
                            console.error('Erro ao atualizar senha:', err);
                            return res.status(500).json({ error: 'Erro ao atualizar senha' });
                        }

                        logActivity(user.id, 'PASSWORD_RESET_COMPLETED', 'Senha redefinida', req);
                        res.json({ message: 'Senha redefinida com sucesso' });
                    }
                );
            } catch (error) {
                console.error('Erro ao processar nova senha:', error);
                res.status(500).json({ error: 'Erro interno do servidor' });
            }
        }
    );
});

// ROTAS DE PROGRESSO DOS DESAFIOS

// Obter progresso do usuário
app.get('/api/progress', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM user_progress WHERE user_id = ?',
        [req.user.id],
        (err, rows) => {
            if (err) {
                console.error('Erro ao buscar progresso:', err);
                return res.status(500).json({ error: 'Erro ao buscar progresso' });
            }

            // Transformar em objeto indexado por challenge_id
            const progress = {};
            rows.forEach(row => {
                progress[row.challenge_id] = {
                    completed: Boolean(row.completed),
                    completedAt: row.completed_at,
                    notes: row.notes
                };
            });

            res.json(progress);
        }
    );
});

// Atualizar progresso de um desafio
app.post('/api/progress/:challengeId', authenticateToken, (req, res) => {
    const { challengeId } = req.params;
    const { completed, notes } = req.body;

    const now = new Date().toISOString();

    db.run(
        `INSERT OR REPLACE INTO user_progress 
         (user_id, challenge_id, completed, completed_at, notes, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [req.user.id, challengeId, completed ? 1 : 0, completed ? now : null, notes || '', now],
        function(err) {
            if (err) {
                console.error('Erro ao salvar progresso:', err);
                return res.status(500).json({ error: 'Erro ao salvar progresso' });
            }

            // Registrar atividade
            logActivity(
                req.user.id, 
                'CHALLENGE_UPDATED', 
                `Desafio #${challengeId} - ${completed ? 'Concluído' : 'Atualizado'}`,
                req
            );

            res.json({
                message: 'Progresso salvo com sucesso',
                progress: {
                    completed: Boolean(completed),
                    completedAt: completed ? now : null,
                    notes: notes || ''
                }
            });
        }
    );
});

// Obter dados do usuário
app.get('/api/user', authenticateToken, (req, res) => {
    db.get('SELECT id, name, email, partner, created_at FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) {
            console.error('Erro ao buscar usuário:', err);
            return res.status(500).json({ error: 'Erro ao buscar dados do usuário' });
        }

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        res.json(user);
    });
});

// Atualizar dados do usuário
app.put('/api/user', authenticateToken, (req, res) => {
    const { name, partner } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Nome é obrigatório' });
    }

    db.run(
        'UPDATE users SET name = ?, partner = ? WHERE id = ?',
        [name, partner || 'Não definido', req.user.id],
        function(err) {
            if (err) {
                console.error('Erro ao atualizar usuário:', err);
                return res.status(500).json({ error: 'Erro ao atualizar dados' });
            }

            logActivity(req.user.id, 'USER_UPDATED', 'Dados do perfil atualizados', req);
            res.json({ message: 'Dados atualizados com sucesso' });
        }
    );
});

// ROTAS DE ESTATÍSTICAS

// Obter estatísticas do sistema
app.get('/api/stats', (req, res) => {
    db.all(`
        SELECT 
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM user_progress WHERE completed = 1) as total_challenges_completed,
            (SELECT COUNT(DISTINCT user_id) FROM user_progress WHERE completed = 1) as active_users
    `, (err, stats) => {
        if (err) {
            console.error('Erro ao buscar estatísticas:', err);
            return res.status(500).json({ error: 'Erro ao buscar estatísticas' });
        }

        res.json(stats[0]);
    });
});

// ROTAS DE ADMINISTRAÇÃO (opcional)

// Listar todos os usuários (admin)
app.get('/api/admin/users', authenticateToken, (req, res) => {
    // Verificação simples de admin (em produção, implementar sistema de roles)
    if (req.user.email !== 'admin@intellimen.com') {
        return res.status(403).json({ error: 'Acesso negado' });
    }

    db.all(`
        SELECT 
            u.id, u.name, u.email, u.partner, u.created_at, u.last_login,
            COUNT(up.id) as completed_challenges
        FROM users u
        LEFT JOIN user_progress up ON u.id = up.user_id AND up.completed = 1
        GROUP BY u.id
        ORDER BY u.created_at DESC
    `, (err, users) => {
        if (err) {
            console.error('Erro ao buscar usuários:', err);
            return res.status(500).json({ error: 'Erro ao buscar usuários' });
        }

        res.json(users);
    });
});

// Criar página de reset de senha
app.get('/reset-password', (req, res) => {
    const { token } = req.query;
    
    if (!token) {
        return res.status(400).send('Token não fornecido');
    }

    const html = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Redefinir Senha - IntelliMen</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #000; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            button:hover { background: #333; }
            .message { padding: 10px; margin-bottom: 20px; border-radius: 5px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>IntelliMen - Redefinir Senha</h2>
            <div id="message"></div>
            <form id="resetForm">
                <div class="form-group">
                    <label for="newPassword">Nova Senha:</label>
                    <input type="password" id="newPassword" required minlength="6">
                </div>
                <div class="form-group">
                    <label for="confirmPassword">Confirmar Senha:</label>
                    <input type="password" id="confirmPassword" required minlength="6">
                </div>
                <button type="submit">Redefinir Senha</button>
            </form>
        </div>

        <script>
            document.getElementById('resetForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const newPassword = document.getElementById('newPassword').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                const messageDiv = document.getElementById('message');
                
                if (newPassword !== confirmPassword) {
                    messageDiv.innerHTML = '<div class="error">As senhas não conferem!</div>';
                    return;
                }
                
                try {
                    const response = await fetch('/api/reset-password', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            token: '${token}',
                            newPassword: newPassword
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        messageDiv.innerHTML = '<div class="success">' + data.message + '</div>';
                        document.getElementById('resetForm').style.display = 'none';
                        setTimeout(() => {
                            window.location.href = '/';
                        }, 3000);
                    } else {
                        messageDiv.innerHTML = '<div class="error">' + data.error + '</div>';
                    }
                } catch (error) {
                    messageDiv.innerHTML = '<div class="error">Erro de conexão. Tente novamente.</div>';
                }
            });
        </script>
    </body>
    </html>
    `;
    
    res.send(html);
});

// Servir arquivos estáticos (frontend)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Rota catch-all para SPA
app.get('*', (req, res) => {
    // Se for uma rota da API, retornar 404
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'Endpoint não encontrado' });
    }
    
    // Caso contrário, servir o index.html
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Middleware de tratamento de erros
app.use((err, req, res, next) => {
    console.error('Erro não tratado:', err);
    res.status(500).json({ error: 'Erro interno do servidor' });
});

// Função para criar diretório public se não existir
function ensurePublicDirectory() {
    const publicDir = path.join(__dirname, 'public');
    if (!fs.existsSync(publicDir)) {
        fs.mkdirSync(publicDir, { recursive: true });
        console.log('📁 Diretório public criado');
    }
}

// Inicializar servidor
function startServer() {
    ensurePublicDirectory();
    
    app.listen(PORT, () => {
        console.log('\n🚀 ===============================');
        console.log('   SERVIDOR INTELLIMEN INICIADO');
        console.log('===============================');
        console.log(`📱 URL do Site: http://localhost:${PORT}`);
        console.log(`🔧 API Base: http://localhost:${PORT}/api`);
        console.log('===============================');
        console.log('👤 USUÁRIO DE DEMONSTRAÇÃO:');
        console.log('📧 Email: joao@email.com');
        console.log('🔑 Senha: 123456');
        console.log('===============================');
        console.log('📋 ENDPOINTS PRINCIPAIS:');
        console.log('• POST /api/register - Registro');
        console.log('• POST /api/login - Login');
        console.log('• GET /api/progress - Progresso');
        console.log('• POST /api/progress/:id - Atualizar');
        console.log('• GET /api/user - Dados do usuário');
        console.log('• GET /api/stats - Estatísticas');
        console.log('===============================\n');
        
        // Verificar se o arquivo HTML existe
        const indexPath = path.join(__dirname, 'public', 'index.html');
        if (!fs.existsSync(indexPath)) {
            console.log('⚠️  ATENÇÃO: Arquivo index.html não encontrado!');
            console.log('📝 Crie o arquivo public/index.html com o conteúdo do frontend');
            console.log('🔗 Ou copie o HTML fornecido para public/index.html\n');
        }
    });
}

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Encerrando servidor...');
    db.close((err) => {
        if (err) {
            console.error('Erro ao fechar banco de dados:', err.message);
        } else {
            console.log('✅ Banco de dados fechado.');
        }
        process.exit(0);
    });
});

// Tratamento de erros não capturados
process.on('uncaughtException', (err) => {
    console.error('❌ Erro não capturado:', err);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Promise rejeitada não tratada:', reason);
    process.exit(1);
});

// Iniciar o servidor
startServer();

module.exports = app;