require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const SALT_ROUNDS = 10;

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
        const senhaCriptografada = await bcrypt.hash(senha, SALT_ROUNDS);

        const { data, error } = await supabase
            .from('Usuario')
            .insert([{ nome, cpf: cpfLimpo, email, senha: senhaCriptografada, telefone, cep, rua, bairro, cidade, estado, numero, complemento }])
            .select();

        if (error) throw error;

        res.status(201).json({ mensagem: "Usuário cadastrado com sucesso!", data: data.map(removerSenhaDoUsuario) });
    } catch (error) {
        console.error("Erro ao salvar:", error.message);
        res.status(400).json({ error: error.message });
    }
});

// Login: aceita email ou CPF e remove a senha antes de devolver os dados ao front.
app.post('/login', async (req, res) => {
    const { email, cpf, senha } = req.body;

    try {
        let query = supabase.from('Usuario').select('*');

        if (cpf) {
            const cpfLimpo = limparCPF(cpf);
            const cpfFormatado = formatarCPF(cpfLimpo);

            // Aceita CPFs novos salvos sem máscara e contas antigas salvas com máscara.
            query = query.in('cpf', [cpfLimpo, cpfFormatado]);
        } else if (email) {
            // login por email
            query = query.eq('email', email);
        } else {
            return res.status(400).json({ error: 'Informe e-mail ou CPF.' });
        }

        const { data: usuarios, error } = await query;

        if (error) throw error;

        if (!usuarios || usuarios.length === 0) {
            return res.status(401).json({ error: 'Nenhuma conta encontrada com esses dados.' });
        }

        const usuario = usuarios[0];

        const senhaCorreta = await conferirSenha(senha, usuario.senha);
        if (!senhaCorreta) {
            return res.status(401).json({ error: 'Senha incorreta. Tente novamente.' });
        }

        if (!senhaEstaCriptografada(usuario.senha)) {
            const senhaCriptografada = await bcrypt.hash(senha, SALT_ROUNDS);
            const { error: erroMigracao } = await supabase
                .from('Usuario')
                .update({ senha: senhaCriptografada })
                .eq('id', usuario.id);
            if (erroMigracao) throw erroMigracao;
            usuario.senha = senhaCriptografada;
        }

        res.json({ message: "Login realizado!", usuario: removerSenhaDoUsuario(usuario) });

    } catch (error) {
        console.error("Erro no login:", error.message);
        res.status(500).json({ error: 'Erro interno. Tente novamente.' });
    }
});

app.get('/usuarios/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const { data, error } = await supabase
            .from('Usuario')
            .select('*')
            .eq('id', Number(id))
            .maybeSingle();

        if (error) throw error;

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
app.put('/usuarios/:id', async (req, res) => {
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
        if (perfil_url !== undefined)  dadosParaAtualizar.perfil_url = perfil_url;
        if (banner_cor !== undefined)  dadosParaAtualizar.banner_cor = banner_cor;
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

app.post('/instituicoes', async (req, res) => {
    try {
        const {
            usuario_id, cnpj, razao_social, nome_fantasia, nome_publico,
            situacao_cadastral, descricao, categorias_aceitas,
            cep, rua, bairro, cidade, estado, numero, complemento,
            logo_url, banner_url, chave_pix, tipo_chave_pix, observacao_endereco
        } = req.body;

        if (!usuario_id) {
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
            .eq('usuario_id', Number(usuario_id))
            .maybeSingle();

        if (erroBusca) throw erroBusca;

        if (existente) {
            return res.status(409).json({ error: 'Este usuário já possui uma instituição vinculada.' });
        }

        const dadosInstituicao = {
            usuario_id: Number(usuario_id),
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
            .select('*')
            .eq('status', 'aprovada')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json(data || []);
    } catch (error) {
        console.error('Erro ao listar instituições:', error.message);
        res.status(400).json({ error: error.message });
    }
});

app.get('/instituicoes/usuario/:usuarioId', async (req, res) => {
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

app.delete('/instituicoes/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { usuario_id } = req.body;

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
        if (Number(instituicao.usuario_id) !== Number(usuario_id)) {
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
app.delete('/usuarios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { senha } = req.body;

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor ativo na porta ${PORT}`);
});
