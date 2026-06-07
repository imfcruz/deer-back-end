require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const origensPermitidas = (process.env.FRONTEND_ORIGIN || 'https://projeto-deer.vercel.app,http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:5501,http://localhost:5501,http://127.0.0.1:5502,http://localhost:5502,http://localhost:5173')
    .split(',')
    .map(origem => origem.trim())
    .filter(Boolean);

app.use(cors({
    origin(origin, callback) {
        if (!origin || origensPermitidas.includes(origin)) return callback(null, true);
        return callback(new Error('Origem não permitida pelo CORS.'));
    }
}));
app.use(express.json());



const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const SALT_ROUNDS = 10;
const SESSION_SECRET = process.env.SESSION_SECRET || 'deer-dev-secret-trocar-no-railway';
const TOKEN_TTL_MS = 1000 * 60 * 60 * 8;
const MERCADO_PAGO_ACCESS_TOKEN = process.env.MERCADO_PAGO_ACCESS_TOKEN;

function base64UrlEncode(valor) {
    return Buffer.from(JSON.stringify(valor)).toString('base64url');
}

function assinarToken(payloadBase64) {
    return crypto
        .createHmac('sha256', SESSION_SECRET)
        .update(payloadBase64)
        .digest('base64url');
}

function gerarToken(usuario, tipo = 'comum') {
    const payload = {
        id: Number(usuario.id),
        email: usuario.email,
        tipo,
        exp: Date.now() + TOKEN_TTL_MS
    };
    const payloadBase64 = base64UrlEncode(payload);
    return `${payloadBase64}.${assinarToken(payloadBase64)}`;
}

function validarToken(token = '') {
    try {
        const [payloadBase64, assinatura] = token.split('.');
        if (!payloadBase64 || !assinatura) return null;

        const assinaturaEsperada = assinarToken(payloadBase64);
        if (assinatura.length !== assinaturaEsperada.length) return null;
        const assinaturaOk = crypto.timingSafeEqual(
            Buffer.from(assinatura),
            Buffer.from(assinaturaEsperada)
        );
        if (!assinaturaOk) return null;

        const payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf8'));
        if (!payload.exp || payload.exp < Date.now()) return null;
        return payload;
    } catch {
        return null;
    }
}

function autenticar(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const usuario = validarToken(token);

    if (!usuario) {
        return res.status(401).json({ error: 'Sessão inválida ou expirada. Faça login novamente.' });
    }

    req.usuario = usuario;
    next();
}

function exigirAdmin(req, res, next) {
    if (req.usuario?.tipo === 'administrador') return next();
    return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
}

function exigirMesmoUsuarioOuAdmin(req, res, next) {
    const id = Number(req.params.id || req.params.usuarioId);
    if (req.usuario?.tipo === 'administrador' || Number(req.usuario?.id) === id) return next();
    return res.status(403).json({ error: 'Você não tem permissão para acessar estes dados.' });
}

function origemPrincipalFrontend() {
    const origemHttps = origensPermitidas.find(origem => origem.startsWith('https://'));
    return origemHttps || 'https://projeto-deer.vercel.app';
}

// As funções abaixo padronizam documentos antes de salvar ou comparar no banco.
function limparCPF(cpf = '') {
    return String(cpf).replace(/\D/g, '');
}

function formatarCPF(cpf = '') {
    const cpfLimpo = limparCPF(cpf);
    if (cpfLimpo.length !== 11) return cpf;
    return cpfLimpo.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
}

function limparCNPJ(cnpj = '') {
    return String(cnpj).replace(/\D/g, '');
}

function limparTelefone(telefone = '') {
    return String(telefone).replace(/\D/g, '');
}

function validarChavePix(tipo, chave) {
    const valor = String(chave || '').trim();
    if (!valor) return 'Informe a chave Pix.';

    if (tipo === 'cpf' && limparCPF(valor).length !== 11) {
        return 'Informe um CPF com 11 dígitos.';
    }

    if (tipo === 'cnpj' && limparCNPJ(valor).length !== 14) {
        return 'Informe um CNPJ com 14 dígitos.';
    }

    if (tipo === 'telefone' && limparTelefone(valor).length !== 11) {
        return 'Informe um celular com DDD e 11 dígitos.';
    }

    if (tipo === 'email') {
        if (valor.length > 120) return 'O e-mail deve ter no máximo 120 caracteres.';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(valor)) return 'Informe um e-mail válido.';
    }

    if (tipo === 'aleatoria') {
        const uuidPix = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        const hexPix = /^[0-9a-f]{32}$/i;
        if (!uuidPix.test(valor) && !hexPix.test(valor)) return 'Informe uma chave aleatória válida.';
    }

    return '';
}

// Permite migrar contas antigas: senha nova fica com hash, mas senha antiga em texto ainda loga uma vez.
function senhaEstaCriptografada(senha = '') {
    return typeof senha === 'string' && /^\$2[aby]\$\d{2}\$/.test(senha);
}

async function conferirSenha(senhaDigitada, senhaSalva) {
    if (!senhaSalva) return false;
    if (senhaEstaCriptografada(senhaSalva)) {
        return bcrypt.compare(senhaDigitada, senhaSalva);
    }
    return senhaDigitada === senhaSalva;
}

function removerSenhaDoUsuario(usuario) {
    if (!usuario) return usuario;
    const { senha, ...usuarioSemSenha } = usuario;
    return usuarioSemSenha;
}

// Lista fechada de categorias para impedir que o front envie valores fora do combinado.
const categoriasPermitidas = [
    'alimentos',
    'roupas',
    'higiene',
    'educacao',
    'brinquedos',
    'pets',
    'moveis'
];

const tiposPixPermitidos = ['cpf', 'cnpj', 'email', 'telefone', 'aleatoria'];

// Cadastro de usuário: cria a conta já guardando a senha com bcrypt.
app.post('/usuarios', async (req, res) => {
    try {
        const { nome, cpf, email, senha, telefone, cep, rua, bairro, cidade, estado, numero, complemento } = req.body;
        const cpfLimpo = limparCPF(cpf);

        if (!email || !senha || senha.length < 6 || cpfLimpo.length !== 11) {
            return res.status(400).json({ error: 'Dados de cadastro inválidos.' });
        }

        const senhaCriptografada = await bcrypt.hash(senha, SALT_ROUNDS);

        const { data, error } = await supabase
            .from('Usuario')
            .insert([{ nome, cpf: cpfLimpo, email, senha: senhaCriptografada, telefone, cep, rua, bairro, cidade, estado, numero, complemento }])
            .select();

        if (error) throw error;

        const usuariosSemSenha = data.map(removerSenhaDoUsuario);
        res.status(201).json({
            mensagem: "Usuário cadastrado com sucesso!",
            data: usuariosSemSenha,
            token: gerarToken(usuariosSemSenha[0])
        });
    } catch (error) {
        console.error("Erro ao salvar:", error.message);
        res.status(400).json({ error: error.message });
    }
});

// Login: aceita email ou CPF e remove a senha antes de devolver os dados ao front.
app.post('/login', async (req, res) => {
    const { email, cpf, senha } = req.body;

    try {
        let usuarioEncontrado = null;
        let tipoUsuario = 'comum';

        if (cpf) {
            const cpfLimpo = limparCPF(cpf);
            const cpfFormatado = formatarCPF(cpfLimpo);
            const { data: usuarios, error } = await supabase
                .from('Usuario')
                .select('*')
                .in('cpf', [cpfLimpo, cpfFormatado]);

            if (error) throw error;
            usuarioEncontrado = usuarios?.[0] || null;
        } else if (email) {
            const { data: usuarios, error } = await supabase
                .from('Usuario')
                .select('*')
                .eq('email', email);

            if (error) throw error;
            usuarioEncontrado = usuarios?.[0] || null;

            if (!usuarioEncontrado) {
                const { data: admins, error: erroAdmin } = await supabase
                    .from('administrador')
                    .select('*')
                    .eq('email', email);

                if (erroAdmin) throw erroAdmin;

                if (admins && admins.length > 0) {
                    usuarioEncontrado = admins[0];
                    tipoUsuario = 'administrador';
                }
            }
        } else {
            return res.status(400).json({ error: 'Informe e-mail ou CPF.' });
        }

        if (!usuarioEncontrado) {
            return res.status(401).json({ error: 'E-mail/CPF ou senha incorretos.' });
        }

        const senhaCorreta = await conferirSenha(senha, usuarioEncontrado.senha);
        if (!senhaCorreta) {
            return res.status(401).json({ error: 'E-mail/CPF ou senha incorretos.' });
        }

        if (tipoUsuario === 'comum' && !senhaEstaCriptografada(usuarioEncontrado.senha)) {
            const senhaCriptografada = await bcrypt.hash(senha, SALT_ROUNDS);
            const { error: erroMigracao } = await supabase
                .from('Usuario')
                .update({ senha: senhaCriptografada })
                .eq('id', usuarioEncontrado.id);
            if (erroMigracao) throw erroMigracao;
            usuarioEncontrado.senha = senhaCriptografada;
        }

        usuarioEncontrado.tipo = tipoUsuario;

        res.json({
            message: "Login realizado!",
            usuario: removerSenhaDoUsuario(usuarioEncontrado),
            token: gerarToken(usuarioEncontrado, tipoUsuario)
        });

    } catch (error) {
        console.error("Erro no login:", error.message);
        res.status(500).json({ error: 'Erro interno. Tente novamente.' });
    }
});

app.get('/usuarios/:id', autenticar, exigirMesmoUsuarioOuAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        let { data, error } = await supabase
            .from('Usuario')
            .select('*')
            .eq('id', Number(id))
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            const { data: dataAdmin, error: erroAdmin } = await supabase
                .from('administrador')
                .select('*')
                .eq('id', Number(id))
                .maybeSingle();
            
            if (erroAdmin) throw erroAdmin;
            
            if (dataAdmin) {
                data = dataAdmin;
                data.tipo = 'administrador'; // Injeta a etiqueta VIP
            }
        }

        if (!data) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        res.json({ usuario: removerSenhaDoUsuario(data) });
    } catch (error) {
        console.error('Erro ao buscar usuário:', error.message);
        res.status(400).json({ error: error.message });
    }
});

// Update do perfil: aceita só os campos enviados, então o front pode salvar dados em partes.
app.put('/usuarios/:id', autenticar, exigirMesmoUsuarioOuAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const {
            nome, telefone, email, senha,
            cep, rua, bairro, cidade, estado, numero, complemento,
            perfil_url, banner_cor, biografia, tema_preferido
        } = req.body;

        const dadosParaAtualizar = {};

        if (nome !== undefined)        dadosParaAtualizar.nome = nome;
        if (telefone !== undefined)    dadosParaAtualizar.telefone = telefone;
        if (email !== undefined)       dadosParaAtualizar.email = email;
        if (senha)                     dadosParaAtualizar.senha = await bcrypt.hash(senha, SALT_ROUNDS);
        if (cep !== undefined)         dadosParaAtualizar.cep = cep;
        if (rua !== undefined)         dadosParaAtualizar.rua = rua;
        if (bairro !== undefined)      dadosParaAtualizar.bairro = bairro;
        if (cidade !== undefined)      dadosParaAtualizar.cidade = cidade;
        if (estado !== undefined)      dadosParaAtualizar.estado = estado;
        if (numero !== undefined)      dadosParaAtualizar.numero = numero;
        if (complemento !== undefined) dadosParaAtualizar.complemento = complemento;
        if (perfil_url !== undefined) {
            const urlPerfil = String(perfil_url || '');
            if (urlPerfil && !urlPerfil.startsWith(`${supabaseUrl}/storage/v1/object/public/`)) {
                return res.status(400).json({ error: "URL de perfil inválida." });
            }
            dadosParaAtualizar.perfil_url = perfil_url;
        }
        if (banner_cor !== undefined) {
            if (!/^#[0-9A-Fa-f]{6}$/.test(String(banner_cor))) {
                return res.status(400).json({ error: "Cor do banner inválida." });
            }
            dadosParaAtualizar.banner_cor = banner_cor;
        }
        if (biografia !== undefined)   dadosParaAtualizar.biografia = biografia;
        if (tema_preferido !== undefined) {
            if (!['claro', 'escuro'].includes(tema_preferido)) {
                return res.status(400).json({ error: "Tema inválido." });
            }
            dadosParaAtualizar.tema_preferido = tema_preferido;
        }

        const { data, error } = await supabase
            .from('Usuario')
            .update(dadosParaAtualizar)
            .eq('id', Number(id))
            .select();

        if (error) throw error;

        res.json({ mensagem: "Dados atualizados com sucesso!", data: data.map(removerSenhaDoUsuario) });
    } catch (error) {
        console.error("Erro ao atualizar:", error.message);
        res.status(400).json({ error: error.message });
    }
});

app.post('/usuarios/:id/foto', autenticar, exigirMesmoUsuarioOuAdmin, express.raw({
    type: ['image/jpeg', 'image/png', 'image/webp'],
    limit: '2mb'
}), async (req, res) => {
    try {
        const { id } = req.params;
        const tipoArquivo = req.headers['content-type'];
        const extensoes = {
            'image/jpeg': 'jpg',
            'image/png': 'png',
            'image/webp': 'webp'
        };

        if (!extensoes[tipoArquivo] || !req.body?.length) {
            return res.status(400).json({ error: 'Arquivo de imagem inválido.' });
        }

        const caminhoArquivo = `avatares/${Number(id)}.${extensoes[tipoArquivo]}`;
        const respostaUpload = await fetch(
            `${supabaseUrl}/storage/v1/object/imagens/${caminhoArquivo}`,
            {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${supabaseKey}`,
                    'Content-Type': tipoArquivo,
                    'x-upsert': 'true'
                },
                body: req.body
            }
        );

        if (!respostaUpload.ok) {
            const erroUpload = await respostaUpload.text();
            console.error('Erro no upload do Supabase:', erroUpload);
            return res.status(400).json({ error: 'Erro ao enviar foto.' });
        }

        const urlFoto = `${supabaseUrl}/storage/v1/object/public/imagens/${caminhoArquivo}?t=${Date.now()}`;
        const { data, error } = await supabase
            .from('Usuario')
            .update({ perfil_url: urlFoto })
            .eq('id', Number(id))
            .select();

        if (error) throw error;

        res.json({ mensagem: 'Foto atualizada com sucesso.', perfil_url: urlFoto, data: data.map(removerSenhaDoUsuario) });
    } catch (error) {
        console.error('Erro ao atualizar foto:', error.message);
        res.status(400).json({ error: 'Erro ao atualizar foto.' });
    }
});

app.post('/instituicoes', autenticar, async (req, res) => {
    try {
        const {
            usuario_id, cnpj, razao_social, nome_fantasia, nome_publico,
            situacao_cadastral, descricao, categorias_aceitas,
            cep, rua, bairro, cidade, estado, numero, complemento,
            logo_url, banner_url, chave_pix, tipo_chave_pix, observacao_endereco
        } = req.body;

        const usuarioIdAutenticado = req.usuario.id;

        if (!usuarioIdAutenticado) {
            return res.status(400).json({ error: 'Usuário não informado.' });
        }

        const cnpjLimpo = limparCNPJ(cnpj);
        if (cnpjLimpo.length !== 14) {
            return res.status(400).json({ error: 'CNPJ inválido.' });
        }

        if (!nome_publico || !nome_publico.trim()) {
            return res.status(400).json({ error: 'Informe o nome público da instituição.' });
        }

        if (!descricao || descricao.trim().length < 20) {
            return res.status(400).json({ error: 'A descrição deve ter pelo menos 20 caracteres.' });
        }

        // Categorias chegam como array do PostgreSQL/Supabase.
        const categorias = Array.isArray(categorias_aceitas) ? categorias_aceitas : [];
        if (categorias.length === 0) {
            return res.status(400).json({ error: 'Selecione pelo menos uma categoria aceita.' });
        }

        const categoriasInvalidas = categorias.filter(categoria => !categoriasPermitidas.includes(categoria));
        if (categoriasInvalidas.length > 0) {
            return res.status(400).json({ error: 'Categoria inválida.' });
        }

        const tipoPix = String(tipo_chave_pix || '').trim().toLowerCase();
        const chavePix = String(chave_pix || '').trim();

        if (!tipoPix || !tiposPixPermitidos.includes(tipoPix)) {
            return res.status(400).json({ error: 'Selecione um tipo de chave Pix válido.' });
        }

        const erroChavePix = validarChavePix(tipoPix, chavePix);
        if (erroChavePix) {
            return res.status(400).json({ error: erroChavePix });
        }

        const { data: existente, error: erroBusca } = await supabase
            .from('Instituicao')
            .select('id, status')
            .eq('usuario_id', Number(usuarioIdAutenticado))
            .maybeSingle();

        if (erroBusca) throw erroBusca;

        if (existente) {
            return res.status(409).json({ error: 'Este usuário já possui uma instituição vinculada.' });
        }

        const dadosInstituicao = {
            usuario_id: Number(usuarioIdAutenticado),
            cnpj: cnpjLimpo,
            razao_social,
            nome_fantasia,
            nome_publico: nome_publico.trim(),
            situacao_cadastral,
            descricao: descricao.trim(),
            categorias_aceitas: categorias,
            cep,
            rua,
            bairro,
            cidade,
            estado,
            numero,
            complemento,
            logo_url,
            banner_url,
            chave_pix: chavePix,
            tipo_chave_pix: tipoPix,
            status: 'pendente'
        };

        if (observacao_endereco) {
            dadosInstituicao.observacao_endereco = String(observacao_endereco).trim();
        }

        const { data, error } = await supabase
            .from('Instituicao')
            .insert([dadosInstituicao])
            .select();

        if (error) throw error;

        res.status(201).json({ mensagem: 'Instituição enviada para análise.', data });
    } catch (error) {
        console.error('Erro ao salvar instituição:', error.message);
        res.status(400).json({ error: error.message });
    }
});

app.get('/instituicoes', async (req, res) => {
    try {
        // A listagem pública mostra apenas instituições aprovadas.
        const { data, error } = await supabase
            .from('Instituicao')
            .select('id, cnpj, razao_social, nome_fantasia, nome_publico, situacao_cadastral, descricao, categorias_aceitas, cidade, estado, logo_url, banner_url, created_at')
            .eq('status', 'aprovada')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json(data || []);
    } catch (error) {
        console.error('Erro ao listar instituições:', error.message);
        res.status(400).json({ error: error.message });
    }
});

app.get('/instituicoes/usuario/:usuarioId', autenticar, exigirMesmoUsuarioOuAdmin, async (req, res) => {
    try {
        const { usuarioId } = req.params;

        const { data, error } = await supabase
            .from('Instituicao')
            .select('*')
            .eq('usuario_id', Number(usuarioId))
            .maybeSingle();

        if (error) throw error;

        res.json({ instituicao: data || null });
    } catch (error) {
        console.error('Erro ao buscar instituição do usuário:', error.message);
        res.status(400).json({ error: error.message });
    }
});

app.post('/pagamentos/preferencia', async (req, res) => {
    try {
        if (!MERCADO_PAGO_ACCESS_TOKEN) {
            return res.status(500).json({ error: 'Mercado Pago não configurado no servidor.' });
        }

        const instituicaoId = Number(req.body.instituicao_id);
        const valor = Number(req.body.valor);

        if (!instituicaoId || !Number.isFinite(valor) || valor < 1 || valor > 10000) {
            return res.status(400).json({ error: 'Informe um valor de doação válido.' });
        }

        const { data: instituicao, error: erroInstituicao } = await supabase
            .from('Instituicao')
            .select('id, nome_publico, razao_social, status')
            .eq('id', instituicaoId)
            .eq('status', 'aprovada')
            .maybeSingle();

        if (erroInstituicao) throw erroInstituicao;

        if (!instituicao) {
            return res.status(404).json({ error: 'Instituição aprovada não encontrada.' });
        }

        const origem = origemPrincipalFrontend();
        const nomeInstituicao = instituicao.nome_publico || instituicao.razao_social || 'Instituição parceira';

        const preferencePayload = {
            items: [
                {
                    title: `Doação para ${nomeInstituicao}`,
                    description: 'Simulação de doação pela plataforma DEER',
                    quantity: 1,
                    currency_id: 'BRL',
                    unit_price: Number(valor.toFixed(2))
                }
            ],
            back_urls: {
                success: `${origem}/pages/ongs.html?pagamento=sucesso`,
                failure: `${origem}/pages/ongs.html?pagamento=falha`,
                pending: `${origem}/pages/ongs.html?pagamento=pendente`
            },
            auto_return: 'approved',
            external_reference: `deer-${instituicao.id}-${Date.now()}`,
            metadata: {
                instituicao_id: instituicao.id,
                ambiente: 'sandbox'
            }
        };

        const resposta = await fetch('https://api.mercadopago.com/checkout/preferences', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${MERCADO_PAGO_ACCESS_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(preferencePayload)
        });

        const preference = await resposta.json();

        if (!resposta.ok) {
            console.error('Erro Mercado Pago:', preference);
            return res.status(400).json({ error: 'Não foi possível iniciar o checkout de pagamento.' });
        }

        res.status(201).json({
            id: preference.id,
            checkout_url: preference.sandbox_init_point || preference.init_point
        });
    } catch (error) {
        console.error('Erro ao criar preferência de pagamento:', error.message);
        res.status(400).json({ error: 'Erro ao criar preferência de pagamento.' });
    }
});

app.delete('/instituicoes/:id', autenticar, async (req, res) => {
    try {
        const { id } = req.params;

        const { data: instituicao, error: erroBusca } = await supabase
            .from('Instituicao')
            .select('id, usuario_id, status')
            .eq('id', Number(id))
            .maybeSingle();

        if (erroBusca) throw erroBusca;

        if (!instituicao) {
            return res.status(404).json({ error: 'Instituição não encontrada.' });
        }

        // Garante que um usuário não cancele a solicitação de outro perfil.
        if (req.usuario.tipo !== 'administrador' && Number(instituicao.usuario_id) !== Number(req.usuario.id)) {
            return res.status(403).json({ error: 'Você não pode cancelar esta solicitação.' });
        }

        if (instituicao.status !== 'pendente') {
            return res.status(400).json({ error: 'Somente solicitações pendentes podem ser canceladas.' });
        }

        const { error } = await supabase
            .from('Instituicao')
            .delete()
            .eq('id', Number(id));

        if (error) throw error;

        res.json({ mensagem: 'Solicitação cancelada com sucesso.' });
    } catch (error) {
        console.error('Erro ao cancelar instituição:', error.message);
        res.status(400).json({ error: error.message });
    }
});

// Exclusão de conta: exige a senha novamente antes de apagar o usuário.
app.delete('/usuarios/:id', autenticar, async (req, res) => {
    try {
        const { id } = req.params;
        const { senha } = req.body;

        if (Number(req.usuario.id) !== Number(id) || req.usuario.tipo !== 'comum') {
            return res.status(403).json({ error: 'Você não tem permissão para excluir esta conta.' });
        }

        if (!senha) {
            return res.status(400).json({ error: "Informe sua senha para excluir a conta." });
        }

        const { data: usuario, error: erroBusca } = await supabase
            .from('Usuario')
            .select('id, senha')
            .eq('id', Number(id))
            .maybeSingle();

        if (erroBusca) throw erroBusca;

        if (!usuario) {
            return res.status(404).json({ error: "Usuário não encontrado." });
        }

        const senhaCorreta = await conferirSenha(senha, usuario.senha);
        if (!senhaCorreta) {
            return res.status(401).json({ error: "Senha incorreta." });
        }

        const { error } = await supabase
            .from('Usuario')
            .delete()
            .eq('id', Number(id));

        if (error) throw error;

        res.json({ mensagem: "Conta excluída com sucesso." });
    } catch (error) {
        console.error("Erro ao excluir:", error.message);
        res.status(400).json({ error: error.message });
    }
});

// Rotas administrativas exigem token válido e usuário marcado como administrador pelo back-end.
const verificarSeEAdmin = [autenticar, exigirAdmin];

// Como aplicar o middleware em uma rota específica
app.get('/admin/dados-sensiveis', verificarSeEAdmin, (req, res) => {
    res.json({ mensagem: "Bem-vindo, Administrador! Aqui estão os dados." });
});

//Rota da Tabela de Pedidos de criação de perfil ONG
//criando rota para o endereço especificado('/admin/instituicoes-pendentes')
app.get('/admin/instituicoes-pendentes', verificarSeEAdmin, async (req, res) => {
    
    try {
        // Busca no supabase a tabela instituição
        const { data, error } = await supabase
            .from('Instituicao')
            .select('*')
            .eq('status', 'pendente'); // Filtra para trazer só as pendentes

        // Se der algum erro no banco de dados, interrompe e vai para o 'catch'
        if (error) throw error;

        // Envia o Dados devolta para o Front-End em formato JSON
        res.json(data);

    } catch (error) {
        // Mensagem de Erro
        console.error('Erro na cozinha:', error.message);
        res.status(500).json({ error: 'Erro interno ao buscar as ONGs.' });
    }
});

// Rota para Aprovar a ONG
app.put('/admin/instituicoes/:id/aprovar', verificarSeEAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Atualiza o status para 'aprovada' no Supabase
        const { data, error } = await supabase
            .from('Instituicao')
            .update({ status: 'aprovada' })
            .eq('id', Number(id))
            .select();

        if (error) throw error;

        res.json({ mensagem: 'Instituição aprovada com sucesso!', data });
    } catch (error) {
        console.error('Erro ao aprovar instituição:', error.message);
        res.status(400).json({ error: error.message });
    }
});

// Rota para Recusar a ONG
app.put('/admin/instituicoes/:id/recusar', verificarSeEAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Atualiza o status para 'rejeitada' no Supabase
        const { data, error } = await supabase
            .from('Instituicao')
            .update({ status: 'rejeitada' })
            .eq('id', Number(id))
            .select();

        if (error) throw error;

        res.json({ mensagem: 'Instituição rejeitada com sucesso!', data });
    } catch (error) {
        console.error('Erro ao rejeitar instituição:', error.message);
        res.status(400).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor ativo na porta ${PORT}`);
});
