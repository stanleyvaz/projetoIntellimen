// setup.js - Script de Configuração Inicial do IntelliMen
const fs = require('fs');
const path = require('path');

console.log('🚀 ===============================');
console.log('   CONFIGURAÇÃO INICIAL INTELLIMEN');
console.log('===============================\n');

// Criar diretório public se não existir
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
    console.log('✅ Diretório public criado');
} else {
    console.log('📁 Diretório public já existe');
}

// Verificar se o arquivo HTML principal existe
const indexPath = path.join(publicDir, 'index.html');
if (!fs.existsSync(indexPath)) {
    console.log('⚠️  Arquivo index.html não encontrado');
    console.log('📝 Você precisa criar o arquivo public/index.html');
    console.log('🔗 Copie o conteúdo HTML fornecido para este arquivo\n');
} else {
    console.log('✅ Arquivo index.html encontrado');
}

// Criar arquivo .env de exemplo
const envPath = path.join(__dirname, '.env.example');
if (!fs.existsSync(envPath)) {
    const envContent = `# IntelliMen - Variáveis de Ambiente

# Configurações do Servidor
PORT=3000
NODE_ENV=development

# Segurança
JWT_SECRET=intellimen-secret-key-2024-change-in-production

# Configurações de Email (Gmail)
EMAIL_USER=seu-email@gmail.com
EMAIL_PASS=sua-senha-de-app

# Configurações do Banco de Dados
DATABASE_PATH=./intellimen.db

# Configurações de Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# URLs Base
BASE_URL=http://localhost:3000
API_BASE_URL=http://localhost:3000/api

# Configurações de Logs
LOG_LEVEL=info
LOG_FILE=intellimen.log

# Configurações de Backup
BACKUP_INTERVAL_HOURS=24
MAX_BACKUP_FILES=7
`;
    
    fs.writeFileSync(envPath, envContent);
    console.log('✅ Arquivo .env.example criado');
} else {
    console.log('📄 Arquivo .env.example já existe');
}

// Criar arquivo README.md se não existir
const readmePath = path.join(__dirname, 'README.md');
if (!fs.existsSync(readmePath)) {
    const readmeContent = `# IntelliMen - 53 Desafios Para Homens Inteligentes

Website oficial do projeto IntelliMen, baseado no livro de Renato Cardoso.

## 🎯 Sobre o Projeto

O IntelliMen é um projeto de desenvolvimento pessoal voltado exclusivamente para homens que querem ser melhores em todas as áreas de sua vida. São 53 desafios semanais que abordam temas como:

- Caráter e integridade
- Relacionamentos e família  
- Disciplina e hábitos
- Liderança e responsabilidade
- Espiritualidade e propósito
- Saúde física e mental

## 🚀 Instalação e Configuração

### Pré-requisitos

- Node.js 16+ 
- NPM 8+

### Instalação

1. Clone o repositório:
\`\`\`bash
git clone https://github.com/intellimen/website.git
cd intellimen-website
\`\`\`

2. Instale as dependências:
\`\`\`bash
npm install
\`\`\`

3. Configure as variáveis de ambiente:
\`\`\`bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
\`\`\`

4. Crie o arquivo HTML principal:
\`\`\`bash
# Copie o conteúdo HTML fornecido para public/index.html
\`\`\`

5. Inicie o servidor:
\`\`\`bash
npm start
\`\`\`

### Modo de Desenvolvimento

\`\`\`bash
npm run dev
\`\`\`

## 📱 Acesso

- **Website**: http://localhost:3000
- **API**: http://localhost:3000/api

### Usuário de Demonstração

- **Email**: joao@email.com
- **Senha**: 123456

## 🔧 Estrutura do Projeto

\`\`\`
intellimen-website/
├── server.js              # Servidor principal
├── package.json           # Dependências e scripts
├── public/                 # Arquivos estáticos
│   └── index.html         # Frontend principal
├── intellimen.db          # Banco de dados SQLite
├── .env                   # Variáveis de ambiente
└── README.md              # Este arquivo
\`\`\`

## 🗃️ Banco de Dados

O projeto usa SQLite com as seguintes tabelas principais:

- **users**: Dados dos usuários
- **user_progress**: Progresso nos desafios
- **activity_logs**: Logs de atividades
- **system_stats**: Estatísticas do sistema

## 📋 Endpoints da API

### Autenticação
- \`POST /api/register\` - Cadastro de usuário
- \`POST /api/login\` - Login
- \`POST /api/forgot-password\` - Recuperar senha
- \`POST /api/reset-password\` - Redefinir senha

### Usuário
- \`GET /api/user\` - Dados do usuário
- \`PUT /api/user\` - Atualizar dados

### Progresso
- \`GET /api/progress\` - Obter progresso
- \`POST /api/progress/:id\` - Atualizar desafio

### Estatísticas
- \`GET /api/stats\` - Estatísticas do sistema

## 🛡️ Segurança

- Autenticação JWT
- Senhas criptografadas com bcrypt
- Rate limiting implementado
- Validação de dados de entrada
- Logs de atividades

## 📊 Funcionalidades

### Para Usuários
- ✅ Sistema de login/cadastro
- ✅ Acompanhamento de progresso
- ✅ Anotações pessoais em cada desafio
- ✅ Exportação de relatórios
- ✅ Interface responsiva
- ✅ Links para recursos externos

### Para Administradores
- ✅ Estatísticas do sistema
- ✅ Logs de atividades
- ✅ Gestão de usuários

## 🔄 Scripts Disponíveis

\`\`\`bash
npm start         # Iniciar servidor
npm run dev       # Modo desenvolvimento
npm run setup     # Configuração inicial
npm run reset-db  # Resetar banco de dados
npm run backup-db # Backup do banco
\`\`\`

## 📝 Configuração de Email

Para habilitar o envio de emails de recuperação de senha:

1. Configure uma conta Gmail com senha de app
2. Atualize as variáveis no .env:
   - \`EMAIL_USER=seu-email@gmail.com\`
   - \`EMAIL_PASS=sua-senha-de-app\`

## 🚀 Deploy

O projeto pode ser facilmente deployado em:

- **Heroku**: Suporte nativo ao Node.js
- **Railway**: Deploy simples com Git
- **Render**: Hospedagem gratuita
- **DigitalOcean**: Droplets ou App Platform
- **AWS**: EC2, Elastic Beanstalk ou Lambda

## 📄 Licença

MIT License - veja o arquivo LICENSE para detalhes.

## 🤝 Contribuições

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📞 Suporte

- **Email**: contato@intellimen.com
- **Website**: https://intellimen.com
- **Issues**: https://github.com/intellimen/website/issues

---

**IntelliMen - Formar homens melhores será o nosso lema. Ser homens inteligentes é a nossa missão.**
`;
    
    fs.writeFileSync(readmePath, readmeContent);
    console.log('✅ Arquivo README.md criado');
} else {
    console.log('📄 Arquivo README.md já existe');
}

// Verificar dependências
console.log('\n📦 DEPENDÊNCIAS:');
try {
    const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    const dependencies = Object.keys(packageJson.dependencies || {});
    const devDependencies = Object.keys(packageJson.devDependencies || {});
    
    console.log(`✅ ${dependencies.length} dependências principais`);
    console.log(`✅ ${devDependencies.length} dependências de desenvolvimento`);
} catch (error) {
    console.log('⚠️  Erro ao ler package.json');
}

// Instruções finais
console.log('\n🎯 PRÓXIMOS PASSOS:');
console.log('1. Execute: npm install');
console.log('2. Copie o HTML fornecido para public/index.html');
console.log('3. Configure o arquivo .env (opcional)');
console.log('4. Execute: npm start');
console.log('5. Acesse: http://localhost:3000');

console.log('\n👤 USUÁRIO DE TESTE:');
console.log('📧 Email: joao@email.com');
console.log('🔑 Senha: 123456');

console.log('\n===============================');
console.log('   CONFIGURAÇÃO CONCLUÍDA!');
console.log('===============================\n');

module.exports = {
    publicDir,
    envPath,
    readmePath,
    indexPath
};