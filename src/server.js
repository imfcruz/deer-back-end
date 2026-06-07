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
        
        let { data: usuarios, error } = await supabase.from('Usuario').select('*').eq('email', email);
        let usuarioEncontrado = usuarios && usuarios.length > 0 ? usuarios[0] : null;
        let tipoUsuario = 'comum';

        
        if (!usuarioEncontrado) {
            let { data: admins, error: erroAdmin } = await supabase.from('administrador').select('*').eq('email', email);
            
            if (admins && admins.length > 0) {
                usuarioEncontrado = admins[0];
                tipoUsuario = 'administrador'; // Salvamos que ele é admin!
            }
        }

        
        if (!usuarioEncontrado) {
            return res.status(401).json({ error: 'Nenhuma conta encontrada com esses dados.' });
        }

        
        const senhaCorreta = await conferirSenha(senha, usuarioEncontrado.senha);
        if (!senhaCorreta) {
            return res.status(401).json({ error: 'Senha incorreta. Tente novamente.' });
        }

        
        usuarioEncontrado.tipo = tipoUsuario;

        res.json({ message: "Login realizado!", usuario: removerSenhaDoUsuario(usuarioEncontrado) });

    } catch (error) {
        console.error("Erro no login:", error.message);
        res.status(500).json({ error: 'Erro interno. Tente novamente.' });
    }
});

app.get('/usuarios/:id', async (req, res) => {
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

// Middleware de Segurança no Servidor
const verificarSeEAdmin = (req, res, next) => {
    // Imagine que pegamos o tipo do usuário que veio na requisição
    const tipoUsuario = req.headers['tipo-usuario']; 

    if (tipoUsuario === 'administrador') {
        // Se for admin, o "segurança" abre a porta
        next(); 
    } else {
        // Se não for, o servidor responde com erro 403 (Proibido)
        // O servidor não usa alert(), ele envia um status de erro
        res.status(403).json({ erro: "Acesso negado. Apenas administradores." });
    }
};

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