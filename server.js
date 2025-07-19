// server.js - IntelliMen Backend Completo com Perfil de Usuário
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

// Criar tabelas se não existirem (schema atualizado)
db.serialize(() => {
    // Tabela de usuários expandida
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
        avatar_url TEXT,
        
        -- Dados pessoais
        full_name TEXT,
        birth_date DATE,
        phone TEXT,
        address TEXT,
        city TEXT,
        state TEXT,
        country TEXT DEFAULT 'Brasil',
        postal_code TEXT,
        marital_status TEXT CHECK(marital_status IN ('solteiro', 'namorado', 'noivo', 'casado', 'divorciado', 'viuvo')),
        spouse_name TEXT,
        children_count INTEGER DEFAULT 0,
        profession TEXT,
        education_level TEXT CHECK(education_level IN ('fundamental', 'medio', 'superior', 'pos-graduacao', 'mestrado', 'doutorado')),
        about_me TEXT,
        
        -- Dados religiosos
        denomination TEXT,
        church_name TEXT,
        church_address TEXT,
        pastor_name TEXT,
        baptized BOOLEAN DEFAULT FALSE,
        baptism_date DATE,
        confirmation_date DATE,
        church_role TEXT,
        ministry TEXT,
        bible_version TEXT DEFAULT 'NVI',
        favorite_verse TEXT,
        spiritual_gifts TEXT,
        conversion_date DATE,
        conversion_story TEXT,
        prayer_requests TEXT,
        testimony TEXT,
        
        -- Configurações do perfil
        profile_visibility TEXT DEFAULT 'public' CHECK(profile_visibility IN ('public', 'partners_only', 'private')),
        allow_contact BOOLEAN DEFAULT TRUE,
        share_progress BOOLEAN DEFAULT TRUE,
        receive_notifications BOOLEAN DEFAULT TRUE,
        
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabela de progresso dos desafios (mantida)
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

    // Tabela para fotos do perfil
    db.run(`CREATE TABLE IF NOT EXISTS profile_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        photo_url TEXT NOT NULL,
        is_primary BOOLEAN DEFAULT FALSE,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);

    // Tabela de estatísticas do sistema (mantida)
    db.run(`CREATE TABLE IF NOT EXISTS system_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        total_users INTEGER DEFAULT 0,
        total_challenges_completed INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabela de logs de atividades (mantida)
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

    // Verificar e criar usuário de demonstração se não existir
    db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
        if (err) {
            console.error('Erro ao verificar usuários:', err);
            return;
        }
        
        if (row.count === 0) {
            console.log('📚 Criando usuário de demonstração...');
            
            bcrypt.hash('123456', 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Erro ao criar hash da senha:', err);
                    return;
                }
                
                db.run(
                    `INSERT INTO users (name, email, password, partner, full_name, denomination, church_name) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    ['João Silva', 'joao@email.com', hashedPassword, 'Pedro Santos', 'João Silva dos Santos', 'Batista', 'Igreja Batista Central'],
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

// Middleware de autenticação
function authenticateToken(req, res, next) {
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
}

// Função para registrar atividades
function logActivity(userId, action, details, req) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent');
    
    db.run(
        'INSERT INTO activity_logs (user_id, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
        [userId, action, details, ip, userAgent]
    );
}

// ===== ROTAS DE AUTENTICAÇÃO (mantidas) =====

// Registro
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, partner } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nome, email e senha são obrigatórios' });
        }

        // Verificar se email já existe
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
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
                'INSERT INTO users (name, email, password, partner, full_name) VALUES (?, ?, ?, ?, ?)',
                [name, email, hashedPassword, partner || 'Não definido', name],
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
            console.error('Erro na verificação de senha:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    });
});

// ===== ROTAS DE PERFIL DE USUÁRIO =====

// Obter perfil completo do usuário
app.get('/api/profile', authenticateToken, (req, res) => {
    const userId = req.user.id;
    
    db.get(`
        SELECT 
            id, name, email, partner, created_at, last_login, avatar_url,
            full_name, birth_date, phone, address, city, state, country, postal_code,
            marital_status, spouse_name, children_count, profession, education_level, about_me,
            denomination, church_name, church_address, pastor_name, baptized, baptism_date,
            confirmation_date, church_role, ministry, bible_version, favorite_verse,
            spiritual_gifts, conversion_date, conversion_story, prayer_requests, testimony,
            profile_visibility, allow_contact, share_progress, receive_notifications
        FROM users 
        WHERE id = ?
    `, [userId], (err, user) => {
        if (err) {
            console.error('Erro ao buscar perfil:', err);
            return res.status(500).json({ error: 'Erro ao buscar perfil' });
        }

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        // Buscar fotos do perfil
        db.all(`
            SELECT id, photo_url, is_primary, uploaded_at 
            FROM profile_photos 
            WHERE user_id = ? 
            ORDER BY is_primary DESC, uploaded_at DESC
        `, [userId], (err, photos) => {
            if (err) {
                console.error('Erro ao buscar fotos:', err);
                photos = [];
            }

            res.json({
                ...user,
                photos: photos || []
            });
        });
    });
});

// Atualizar dados pessoais
app.put('/api/profile/personal', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const {
        full_name, birth_date, phone, address, city, state, country, postal_code,
        marital_status, spouse_name, children_count, profession, education_level, about_me
    } = req.body;

    // Validação básica
    if (marital_status && !['solteiro', 'namorado', 'noivo', 'casado', 'divorciado', 'viuvo'].includes(marital_status)) {
        return res.status(400).json({ error: 'Status marital inválido' });
    }

    if (education_level && !['fundamental', 'medio', 'superior', 'pos-graduacao', 'mestrado', 'doutorado'].includes(education_level)) {
        return res.status(400).json({ error: 'Nível de educação inválido' });
    }

    if (children_count && (children_count < 0 || children_count > 20)) {
        return res.status(400).json({ error: 'Número de filhos inválido' });
    }

    const query = `
        UPDATE users SET 
            full_name = ?,
            birth_date = ?,
            phone = ?,
            address = ?,
            city = ?,
            state = ?,
            country = ?,
            postal_code = ?,
            marital_status = ?,
            spouse_name = ?,
            children_count = ?,
            profession = ?,
            education_level = ?,
            about_me = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `;

    const params = [
        full_name || null,
        birth_date || null,
        phone || null,
        address || null,
        city || null,
        state || null,
        country || 'Brasil',
        postal_code || null,
        marital_status || null,
        spouse_name || null,
        parseInt(children_count) || 0,
        profession || null,
        education_level || null,
        about_me || null,
        userId
    ];

    db.run(query, params, function(err) {
        if (err) {
            console.error('Erro ao atualizar dados pessoais:', err);
            return res.status(500).json({ error: 'Erro ao atualizar dados pessoais' });
        }

        logActivity(userId, 'PROFILE_PERSONAL_UPDATED', 'Dados pessoais atualizados', req);
        res.json({ message: 'Dados pessoais atualizados com sucesso' });
    });
});

// Atualizar dados religiosos
app.put('/api/profile/religious', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const {
        denomination, church_name, church_address, pastor_name, baptized, baptism_date,
        confirmation_date, church_role, ministry, bible_version, favorite_verse,
        spiritual_gifts, conversion_date, conversion_story, prayer_requests, testimony
    } = req.body;

    const query = `
        UPDATE users SET 
            denomination = ?,
            church_name = ?,
            church_address = ?,
            pastor_name = ?,
            baptized = ?,
            baptism_date = ?,
            confirmation_date = ?,
            church_role = ?,
            ministry = ?,
            bible_version = ?,
            favorite_verse = ?,
            spiritual_gifts = ?,
            conversion_date = ?,
            conversion_story = ?,
            prayer_requests = ?,
            testimony = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `;

    const params = [
        denomination || null,
        church_name || null,
        church_address || null,
        pastor_name || null,
        baptized === true || baptized === 'true' ? 1 : 0,
        baptism_date || null,
        confirmation_date || null,
        church_role || null,
        ministry || null,
        bible_version || 'NVI',
        favorite_verse || null,
        spiritual_gifts || null,
        conversion_date || null,
        conversion_story || null,
        prayer_requests || null,
        testimony || null,
        userId
    ];

    db.run(query, params, function(err) {
        if (err) {
            console.error('Erro ao atualizar dados religiosos:', err);
            return res.status(500).json({ error: 'Erro ao atualizar dados religiosos' });
        }

        logActivity(userId, 'PROFILE_RELIGIOUS_UPDATED', 'Dados religiosos atualizados', req);
        res.json({ message: 'Dados religiosos atualizados com sucesso' });
    });
});

// Atualizar configurações de privacidade
app.put('/api/profile/privacy', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const {
        profile_visibility, allow_contact, share_progress, receive_notifications
    } = req.body;

    if (profile_visibility && !['public', 'partners_only', 'private'].includes(profile_visibility)) {
        return res.status(400).json({ error: 'Visibilidade do perfil inválida' });
    }

    const query = `
        UPDATE users SET 
            profile_visibility = ?,
            allow_contact = ?,
            share_progress = ?,
            receive_notifications = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `;

    const params = [
        profile_visibility || 'public',
        allow_contact === true || allow_contact === 'true' ? 1 : 0,
        share_progress === true || share_progress === 'true' ? 1 : 0,
        receive_notifications === true || receive_notifications === 'true' ? 1 : 0,
        userId
    ];

    db.run(query, params, function(err) {
        if (err) {
            console.error('Erro ao atualizar configurações:', err);
            return res.status(500).json({ error: 'Erro ao atualizar configurações' });
        }

        logActivity(userId, 'PROFILE_PRIVACY_UPDATED', 'Configurações de privacidade atualizadas', req);
        res.json({ message: 'Configurações atualizadas com sucesso' });
    });
});

// Upload de foto do perfil
app.post('/api/profile/photo', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { photo_url, is_primary } = req.body;

    if (!photo_url) {
        return res.status(400).json({ error: 'URL da foto é obrigatória' });
    }

    // Validar URL básica
    try {
        new URL(photo_url);
    } catch (e) {
        return res.status(400).json({ error: 'URL da foto inválida' });
    }

    // Se é foto principal, remover outras fotos principais
    if (is_primary) {
        db.run('UPDATE profile_photos SET is_primary = 0 WHERE user_id = ?', [userId]);
    }

    db.run(`
        INSERT INTO profile_photos (user_id, photo_url, is_primary) 
        VALUES (?, ?, ?)
    `, [userId, photo_url, is_primary ? 1 : 0], function(err) {
        if (err) {
            console.error('Erro ao salvar foto:', err);
            return res.status(500).json({ error: 'Erro ao salvar foto' });
        }

        // Atualizar avatar_url na tabela users se for foto principal
        if (is_primary) {
            db.run('UPDATE users SET avatar_url = ? WHERE id = ?', [photo_url, userId]);
        }

        logActivity(userId, 'PROFILE_PHOTO_UPLOADED', 'Nova foto de perfil adicionada', req);
        res.json({ 
            message: 'Foto adicionada com sucesso',
            photo_id: this.lastID
        });
    });
});

// Remover foto do perfil
app.delete('/api/profile/photo/:photoId', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const photoId = req.params.photoId;

    db.get('SELECT * FROM profile_photos WHERE id = ? AND user_id = ?', [photoId, userId], (err, photo) => {
        if (err) {
            console.error('Erro ao buscar foto:', err);
            return res.status(500).json({ error: 'Erro ao buscar foto' });
        }

        if (!photo) {
            return res.status(404).json({ error: 'Foto não encontrada' });
        }

        db.run('DELETE FROM profile_photos WHERE id = ? AND user_id = ?', [photoId, userId], function(err) {
            if (err) {
                console.error('Erro ao remover foto:', err);
                return res.status(500).json({ error: 'Erro ao remover foto' });
            }

            // Se era a foto principal, limpar avatar_url
            if (photo.is_primary) {
                db.run('UPDATE users SET avatar_url = NULL WHERE id = ?', [userId]);
            }

            logActivity(userId, 'PROFILE_PHOTO_DELETED', 'Foto de perfil removida', req);
            res.json({ message: 'Foto removida com sucesso' });
        });
    });
});

// Obter opções para formulários (denominações, versões da Bíblia, etc.)
app.get('/api/profile/options', (req, res) => {
    const options = {
        denominations: [
            'Católica Romana', 'Católica Ortodoxa',
            'Assembleia de Deus', 'Batista', 'Presbiteriana', 'Metodista',
            'Pentecostal', 'Adventista do 7º Dia', 'Universal do Reino de Deus',
            'Igreja do Evangelho Quadrangular', 'Congregação Cristã no Brasil',
            'Igreja de Cristo', 'Luterana', 'Episcopal', 'Reformada',
            'Igreja Cristã Maranata', 'Igreja Mundial do Poder de Deus',
            'Igreja Apostólica Renascer em Cristo', 'Igreja Internacional da Graça',
            'Casa de Oração para Todos os Povos', 'Bola de Neve Church',
            'Hillsong', 'Lagoinha', 'Outra'
        ],
        bible_versions: [
            'NVI - Nova Versão Internacional',
            'ARA - Almeida Revista e Atualizada',
            'ARC - Almeida Revista e Corrigida',
            'NVT - Nova Versão Transformadora',
            'BLH - Bíblia na Linguagem de Hoje',
            'ACF - Almeida Corrigida Fiel',
            'TB - Tradução Brasileira',
            'NTLH - Nova Tradução na Linguagem de Hoje',
            'NAA - Nova Almeida Atualizada',
            'NKJV - New King James Version',
            'ESV - English Standard Version',
            'NIV - New International Version',
            'KJV - King James Version'
        ],
        marital_status: [
            { value: 'solteiro', label: 'Solteiro' },
            { value: 'namorado', label: 'Namorando' },
            { value: 'noivo', label: 'Noivo' },
            { value: 'casado', label: 'Casado' },
            { value: 'divorciado', label: 'Divorciado' },
            { value: 'viuvo', label: 'Viúvo' }
        ],
        education_levels: [
            { value: 'fundamental', label: 'Ensino Fundamental' },
            { value: 'medio', label: 'Ensino Médio' },
            { value: 'superior', label: 'Ensino Superior' },
            { value: 'pos-graduacao', label: 'Pós-graduação' },
            { value: 'mestrado', label: 'Mestrado' },
            { value: 'doutorado', label: 'Doutorado' }
        ],
        brazilian_states: [
            'Acre', 'Alagoas', 'Amapá', 'Amazonas', 'Bahia', 'Ceará',
            'Distrito Federal', 'Espírito Santo', 'Goiás', 'Maranhão',
            'Mato Grosso', 'Mato Grosso do Sul', 'Minas Gerais', 'Pará',
            'Paraíba', 'Paraná', 'Pernambuco', 'Piauí', 'Rio de Janeiro',
            'Rio Grande do Norte', 'Rio Grande do Sul', 'Rondônia',
            'Roraima', 'Santa Catarina', 'São Paulo', 'Sergipe', 'Tocantins'
        ],
        profile_visibility: [
            { value: 'public', label: 'Público - Visível para todos' },
            { value: 'partners_only', label: 'Apenas Parceiros - Visível apenas para outros IntelliMen' },
            { value: 'private', label: 'Privado - Apenas para você' }
        ]
    };

    res.json(options);
});

// Buscar perfis públicos (para networking entre IntelliMen)
app.get('/api/profiles/public', authenticateToken, (req, res) => {
    const { page = 1, limit = 12, denomination, state, search } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
        SELECT 
            id, name, full_name, city, state, denomination, church_name,
            profession, about_me, avatar_url, created_at,
            (SELECT COUNT(*) FROM user_progress WHERE user_id = users.id AND completed = 1) as completed_challenges
        FROM users 
        WHERE profile_visibility = 'public' 
        AND id != ?
    `;
    
    const params = [req.user.id];
    
    if (denomination) {
        query += ' AND denomination = ?';
        params.push(denomination);
    }
    
    if (state) {
        query += ' AND state = ?';
        params.push(state);
    }
    
    if (search) {
        query += ' AND (name LIKE ? OR full_name LIKE ? OR city LIKE ? OR profession LIKE ?)';
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    db.all(query, params, (err, profiles) => {
        if (err) {
            console.error('Erro ao buscar perfis:', err);
            return res.status(500).json({ error: 'Erro ao buscar perfis' });
        }
        
        // Contar total para paginação
        let countQuery = 'SELECT COUNT(*) as total FROM users WHERE profile_visibility = "public" AND id != ?';
        const countParams = [req.user.id];
        
        if (denomination) {
            countQuery += ' AND denomination = ?';
            countParams.push(denomination);
        }
        
        if (state) {
            countQuery += ' AND state = ?';
            countParams.push(state);
        }
        
        if (search) {
            countQuery += ' AND (name LIKE ? OR full_name LIKE ? OR city LIKE ? OR profession LIKE ?)';
            const searchTerm = `%${search}%`;
            countParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        db.get(countQuery, countParams, (err, countResult) => {
            if (err) {
                console.error('Erro ao contar perfis:', err);
                return res.status(500).json({ error: 'Erro ao buscar perfis' });
            }
            
            res.json({
                profiles,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: countResult.total,
                    totalPages: Math.ceil(countResult.total / limit)
                }
            });
        });
    });
});

// Ver perfil específico (respeitando privacidade)
app.get('/api/profile/:userId', authenticateToken, (req, res) => {
    const viewerId = req.user.id;
    const targetUserId = req.params.userId;
    
    db.get(`
        SELECT 
            id, name, full_name, city, state, denomination, church_name,
            profession, about_me, avatar_url, created_at, profile_visibility,
            (SELECT COUNT(*) FROM user_progress WHERE user_id = users.id AND completed = 1) as completed_challenges
        FROM users 
        WHERE id = ?
    `, [targetUserId], (err, profile) => {
        if (err) {
            console.error('Erro ao buscar perfil:', err);
            return res.status(500).json({ error: 'Erro ao buscar perfil' });
        }
        
        if (!profile) {
            return res.status(404).json({ error: 'Perfil não encontrado' });
        }
        
        // Verificar permissões
        if (profile.profile_visibility === 'private' && profile.id !== viewerId) {
            return res.status(403).json({ error: 'Perfil privado' });
        }
        
        if (profile.profile_visibility === 'partners_only' && profile.id !== viewerId) {
            // Em produção, verificar se são parceiros ou amigos
            // Por enquanto, permitir acesso
        }
        
        res.json(profile);
    });
});

// ===== ROTAS EXISTENTES (mantidas) =====

// Obter dados do usuário (mantida para compatibilidade)
app.get('/api/user', authenticateToken, (req, res) => {
    db.get('SELECT id, name, email, partner, created_at, last_login FROM users WHERE id = ?', 
        [req.user.id], (err, user) => {
            if (err) {
                console.error('Erro ao buscar usuário:', err);
                return res.status(500).json({ error: 'Erro ao buscar dados do usuário' });
            }

            if (!user) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            res.json(user);
        }
    );
});

// Atualizar dados básicos do usuário (mantida para compatibilidade)
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

            logActivity(req.user.id, 'USER_UPDATED', 'Dados básicos atualizados', req);
            res.json({ message: 'Dados atualizados com sucesso' });
        }
    );
});

// Obter progresso dos desafios
app.get('/api/progress', authenticateToken, (req, res) => {
    db.all(`
        SELECT challenge_id, completed, completed_at, notes, updated_at
        FROM user_progress 
        WHERE user_id = ? 
        ORDER BY challenge_id
    `, [req.user.id], (err, progress) => {
        if (err) {
            console.error('Erro ao buscar progresso:', err);
            return res.status(500).json({ error: 'Erro ao buscar progresso' });
        }

        res.json(progress);
    });
});

// Atualizar progresso de um desafio
app.post('/api/progress/:challengeId', authenticateToken, (req, res) => {
    const { challengeId } = req.params;
    const { completed, notes } = req.body;
    const userId = req.user.id;

    if (challengeId < 1 || challengeId > 53) {
        return res.status(400).json({ error: 'ID do desafio inválido' });
    }

    const query = `
        INSERT OR REPLACE INTO user_progress 
        (user_id, challenge_id, completed, completed_at, notes, updated_at) 
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    const completedAt = completed ? new Date().toISOString() : null;
    const updatedAt = new Date().toISOString();

    db.run(query, [userId, challengeId, completed ? 1 : 0, completedAt, notes || '', updatedAt], function(err) {
        if (err) {
            console.error('Erro ao atualizar progresso:', err);
            return res.status(500).json({ error: 'Erro ao atualizar progresso' });
        }

        const action = completed ? 'CHALLENGE_COMPLETED' : 'CHALLENGE_UPDATED';
        const details = `Desafio ${challengeId}: ${completed ? 'Concluído' : 'Atualizado'}`;
        logActivity(userId, action, details, req);

        res.json({ message: 'Progresso atualizado com sucesso' });
    });
});

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
        console.log('• GET /api/profile - Perfil completo');
        console.log('• PUT /api/profile/personal - Dados pessoais');
        console.log('• PUT /api/profile/religious - Dados religiosos');
        console.log('• PUT /api/profile/privacy - Configurações');
        console.log('• POST /api/profile/photo - Upload foto');
        console.log('• GET /api/progress - Progresso');
        console.log('• POST /api/progress/:id - Atualizar');
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