# Meu Financeiro 1.3.0 — casal, com login Google e sincronização

Cada um entra com a própria conta Google e lança do próprio jeito, no PC ou no celular.
Os lançamentos aparecem para os dois em tempo real. Os dados ficam cifrados: o Google e o servidor não conseguem ler.

Este guia são os passos que **só você** pode fazer (conta Google e console do Firebase). Leva uns 20 minutos, uma vez só.

---

## 1. Criar o projeto no Firebase

1. Abra https://console.firebase.google.com e entre com uma das contas do casal.
2. Clique em **Criar um projeto** (ou **Adicionar projeto**). Dê um nome, ex.: `meu-financeiro-casal`.
3. Desative o Google Analytics (não é necessário). Clique em **Criar projeto**.

## 2. Ativar o login com Google

1. No menu da esquerda: **Criação > Authentication** → **Começar**.
2. Aba **Sign-in method** → **Google** → ative → escolha um e-mail de suporte → **Salvar**.
3. Aba **Settings > Authorized domains** → confira que `localhost` está na lista. Depois, no passo 6, você adiciona o endereço do seu site.

## 3. Criar o banco de dados (Firestore)

1. No menu: **Criação > Firestore Database** → **Criar banco de dados**.
2. Escolha **Iniciar no modo de produção**. Localização sugerida: `southamerica-east1` (São Paulo). **Ativar**.
3. Aba **Regras**: apague o conteúdo e cole o conteúdo do arquivo `firestore.rules` **depois de editar os e-mails** (passo 5). Clique em **Publicar**.

## 4. Registrar o app web e copiar a configuração

1. Na tela inicial do projeto (ícone de engrenagem > **Configurações do projeto**), role até **Seus apps** → ícone **</>** (Web).
2. Dê um apelido (ex.: `meu-financeiro`). **Não** marque Firebase Hosting. Clique em **Registrar app**.
3. Vai aparecer um bloco `const firebaseConfig = { apiKey: "...", authDomain: "...", projectId: "...", appId: "..." }`.
4. Abra o arquivo `config.js` deste pacote e substitua os valores `COLE_AQUI` pelos valores desse bloco (apiKey, authDomain, projectId, appId). Esses valores **não são segredos**; a segurança está nas regras e na senha do casal.

## 5. Colocar os e-mails do casal

Os e-mails precisam estar **em letras minúsculas** e ser exatamente os das contas Google de vocês.

1. No `config.js`, em `MEMBERS`, troque `email.dele@gmail.com` e `email.dela@gmail.com` pelos e-mails reais e escolha o nome que aparece no app (ex.: `"seu.email@gmail.com": "Carlos"`).
2. No `firestore.rules`, troque os mesmos dois e-mails na lista. **Os dois lugares precisam ser iguais.**
3. Publique as regras de novo no Firestore (passo 3, aba Regras → **Publicar**).

## 6. Colocar o site no ar (GitHub Pages, sem instalar nada)

O login Google só funciona em endereço **https**, então o app precisa estar publicado.

1. Crie uma conta em https://github.com (se não tiver) e entre.
2. Clique em **+ > New repository**. Nome: `meu-financeiro`. Pode ser **público** (o código fica visível, mas os dados não: estão cifrados). Clique em **Create repository**.
3. Na página do repositório, clique em **uploading an existing file**, arraste **todos os arquivos desta pasta** (index.html, styles.css, app.js, config.js, backend-firebase.js, firestore.rules, LEIA-ME.md) e clique em **Commit changes**.
4. Vá em **Settings > Pages**. Em **Build and deployment**, escolha **Deploy from a branch**, branch `main`, pasta `/ (root)`, **Save**.
5. Depois de 1–2 minutos, aparece o endereço `https://SEU-USUARIO.github.io/meu-financeiro/`.
6. **Volte ao Firebase**: Authentication > **Settings > Authorized domains** > **Adicionar domínio** > `SEU-USUARIO.github.io`.

## 7. Usar

1. No PC e no celular, abra o endereço do passo 6.
2. Toque em **Entrar com Google** e escolha a sua conta. Só as duas contas da lista conseguem entrar.
3. A **primeira vez** o app pede para **criar a senha do casal** (mínimo 12 caracteres). Combinem a senha e digitem nos dois aparelhos. Ela protege os dados: **sem ela ninguém lê nada, nem o Google, nem o servidor**.
4. Pronto. Quem entra depois só digita a senha do casal no aparelho novo (uma vez por aparelho). Continua logado enquanto não clicar em **Sair da conta**.

Para adicionar ao celular como aplicativo: no Chrome/Safari, menu do navegador → **Adicionar à tela inicial**.

---

## Segurança — o que está protegido e o que não está

**Protegido**
- Só as duas contas cadastradas entram e leem dados (login Google + regras do Firestore).
- Os lançamentos, descrições, valores, nomes e fotos de comprovantes são cifrados (AES-256-GCM) **no seu aparelho**, com uma chave derivada da senha do casal (PBKDF2-SHA-256, 310 mil iterações). O servidor só guarda texto cifrado.
- Trocar a senha do casal recifra tudo. Em **Casal > Trocar senha do casal**.
- Bloqueio automático após 10 minutos sem uso; limite de tentativas de senha.

**Limites que você precisa saber**
- **Não há recuperação de senha.** Se a senha do casal for esquecida, os dados não podem ser lidos. Anote a senha em local seguro.
- **Backup JSON e planilha CSV não são cifrados.** Guarde-os em local seguro e apague depois de usar.
- O Google e o Firebase veem **quando** cada documento foi alterado e quantos existem (não o conteúdo).
- O aplicativo de OCR (leitura de comprovantes) carrega um componente de uma CDN pública; é opcional — dá para preencher tudo à mão.
- Se os relógios dos dois aparelhos estiverem muito diferentes, a edição mais recente pode perder para a outra. Mantenha a data e hora automáticas.

## Problemas comuns

- **"Esta conta não faz parte deste casal"**: o e-mail está diferente do `config.js` e do `firestore.rules`, ou não está em minúsculas.
- **Login não abre / "unauthorized domain"**: o endereço `SEU-USUARIO.github.io` não foi adicionado em Authorized domains (passo 6).
- **"Permission denied" ou nada carrega**: as regras não foram publicadas (passo 3) ou os e-mails das regras estão diferentes.
- **"Configuração ausente"**: os valores `COLE_AQUI` do `config.js` não foram substituídos.
- **Senha trocada em outro aparelho**: o outro aparelho pede a nova senha automaticamente.
