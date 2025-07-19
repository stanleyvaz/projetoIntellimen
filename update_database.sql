-- update_database.sql - Script para atualizar o banco existente
-- Execute este script para adicionar os novos campos de perfil

BEGIN TRANSACTION;

-- Adicionar novos campos à tabela users existente
-- Dados pessoais
ALTER TABLE users ADD COLUMN full_name TEXT;
ALTER TABLE users ADD COLUMN birth_date DATE;
ALTER TABLE users ADD COLUMN phone TEXT;
ALTER TABLE users ADD COLUMN address TEXT;
ALTER TABLE users ADD COLUMN city TEXT;
ALTER TABLE users ADD COLUMN state TEXT;
ALTER TABLE users ADD COLUMN country TEXT DEFAULT 'Brasil';
ALTER TABLE users ADD COLUMN postal_code TEXT;
ALTER TABLE users ADD COLUMN marital_status TEXT;
ALTER TABLE users ADD COLUMN spouse_name TEXT;
ALTER TABLE users ADD COLUMN children_count INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN profession TEXT;
ALTER TABLE users ADD COLUMN education_level TEXT;
ALTER TABLE users ADD COLUMN about_me TEXT;

-- Dados religiosos
ALTER TABLE users ADD COLUMN denomination TEXT;
ALTER TABLE users ADD COLUMN church_name TEXT;
ALTER TABLE users ADD COLUMN church_address TEXT;
ALTER TABLE users ADD COLUMN pastor_name TEXT;
ALTER TABLE users ADD COLUMN baptized BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN baptism_date DATE;
ALTER TABLE users ADD COLUMN confirmation_date DATE;
ALTER TABLE users ADD COLUMN church_role TEXT;
ALTER TABLE users ADD COLUMN ministry TEXT;
ALTER TABLE users ADD COLUMN bible_version TEXT DEFAULT 'NVI';
ALTER TABLE users ADD COLUMN favorite_verse TEXT;
ALTER TABLE users ADD COLUMN spiritual_gifts TEXT;
ALTER TABLE users ADD COLUMN conversion_date DATE;
ALTER TABLE users ADD COLUMN conversion_story TEXT;
ALTER TABLE users ADD COLUMN prayer_requests TEXT;
ALTER TABLE users ADD COLUMN testimony TEXT;

-- Configurações do perfil
ALTER TABLE users ADD COLUMN profile_visibility TEXT DEFAULT 'public';
ALTER TABLE users ADD COLUMN allow_contact BOOLEAN DEFAULT TRUE;
ALTER TABLE users ADD COLUMN share_progress BOOLEAN DEFAULT TRUE;
ALTER TABLE users ADD COLUMN receive_notifications BOOLEAN DEFAULT TRUE;
ALTER TABLE users ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- Criar tabela para fotos do perfil
CREATE TABLE IF NOT EXISTS profile_photos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    photo_url TEXT NOT NULL,
    is_primary BOOLEAN DEFAULT FALSE,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Preencher full_name para usuários existentes
UPDATE users SET full_name = name WHERE full_name IS NULL;

-- Definir valores padrão para usuários existentes
UPDATE users SET 
    country = 'Brasil',
    bible_version = 'NVI',
    profile_visibility = 'public',
    allow_contact = 1,
    share_progress = 1,
    receive_notifications = 1,
    children_count = 0
WHERE country IS NULL;

-- Criar índices para melhor performance
CREATE INDEX IF NOT EXISTS idx_users_denomination ON users(denomination);
CREATE INDEX IF NOT EXISTS idx_users_church ON users(church_name);
CREATE INDEX IF NOT EXISTS idx_users_state ON users(state);
CREATE INDEX IF NOT EXISTS idx_profile_photos_user_id ON profile_photos(user_id);

COMMIT;

-- Verificar se a atualização foi bem-sucedida
SELECT 'Atualização concluída com sucesso!' as status;
SELECT COUNT(*) as total_users FROM users;
SELECT COUNT(*) as users_with_full_name FROM users WHERE full_name IS NOT NULL;