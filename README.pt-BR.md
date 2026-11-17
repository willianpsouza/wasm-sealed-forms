# Formulário PII Selado em WASM

> [English version](README.md)

Repositório de exemplo: um formulário cheio de dados pessoais (pense em cadastro
de seguro — nome, CPF, endereço, conta bancária, data de nascimento, filhos,
local de trabalho) é **assinado e selado no navegador com Rust/WebAssembly**
antes de ser enviado. Só o backend consegue descriptografar. Todo intermediário
no caminho vê apenas texto cifrado.

Mesma técnica de criptografia do [validador de arquivos](https://github.com/willianpsouza/wasm-file-validator),
aplicada à confidencialidade dos dados do formulário em vez do veredito de arquivos.

## O problema

HTTPS protege os dados **em trânsito**, mas o TLS normalmente é **terminado
antes** da aplicação: num load balancer, API gateway, proxy reverso, CDN ou WAF.
Depois da terminação, o corpo da requisição é texto puro, e qualquer um desses
saltos — mais seus logs de acesso e qualquer captura na rede interna — consegue
ler cada campo de PII.

```
navegador ──TLS──▶ [ API gateway / proxy reverso / CDN / WAF ] ──▶ backend
                          ▲ o TLS termina aqui: vê PII EM TEXTO PURO
```

## A técnica

Selar o corpo **ponta a ponta** no navegador, para uma chave que só o backend tem:

```
navegador                                 intermediários        backend
┌───────────────────────────┐             (gateway/proxy)       ┌──────────────┐
│ JSON do formulário         │                                  │ segredo x25519│
│  ├─ assina (Ed25519)       │   só ciphertext, ilegível        │ descriptografa│
│  └─ sela (x25519 + XChaCha)│ ───────────────────────────────▶ │ verifica assin│
│      → envelope base64      │                                  │ faz o parse   │
└───────────────────────────┘                                  └──────────────┘
```

- `GET /` — a SPA do formulário
- `GET /pkg/*` — o artefato WASM compilado + cola JS
- `POST /api/submit` — descriptografa o envelope, verifica a assinatura, faz o
  parse do PII **dentro do perímetro de confiança** e responde apenas com
  metadados sem PII (id do envio, contagem de campos, quais obrigatórios estavam
  presentes/ausentes).

Um bônus citado no pedido: a API pública **não expõe nenhum schema legível** — o
endpoint consome blobs selados opacos. Isso aumenta o custo de raspar ou fuzzar a
API casualmente. É defesa em profundidade, não uma garantia por si só.

## Modelo de ameaça — o que isto faz e o que NÃO faz

**Protege contra** (o objetivo): um intermediário passivo ou "curioso mas
honesto" entre o navegador e o backend — API gateway, proxy reverso, CDN, WAF,
logs de requisição/acesso, capturas na rede interna — lendo o PII do usuário.
Eles só veem o envelope selado.

**NÃO protege contra:**

- **Origem comprometida.** O servidor que entrega o WASM pode entregar um build
  com backdoor. O selamento ponta a ponta assume que o cliente entregue é honesto.
  Use SRI, builds reprodutíveis e revisão de código para limitar isso.
- **Autenticidade do remetente.** A chave Ed25519 está embutida no `.wasm`
  público e é extraível, e o selamento x25519 usa a chave *pública* do backend —
  então **qualquer um** pode forjar um envio selado válido. Esta camada não diz ao
  backend *quem* enviou; mantenha sua autenticação normal (sessão, token, mTLS) e
  validação no servidor.
- **Substituir o TLS.** Mantenha HTTPS. Isto é uma camada *em cima* dele para que
  a terminação de TLS deixe de expor o corpo.
- **Segurança por obscuridade.** A API opaca aumenta o esforço do atacante; não
  substitui autenticação/autorização.

Resumindo: isto garante **confidencialidade dos dados do formulário contra
intermediários**, e nada além disso. É exatamente a propriedade de que o demo trata.

## ⚠️ Chaves

Como o repositório é público, os pares de chave são gerados em tempo de build por
`cmd/genkeys` em arquivos ignorados pelo git (`keys_gen.rs`, `keys_gen.go`) e
**nunca são commitados**. Em produção, o segredo x25519 do backend vive só dentro
do perímetro de confiança (KMS/HSM/cofre de segredos) e você deve rotacioná-lo.

## Executar (Docker)

```bash
docker compose up --build
# abra http://localhost:8097
```

Envie o formulário e observe: o painel "o que sai do navegador" mostra só o
ciphertext base64 (a visão do proxy), enquanto o painel do backend mostra o
resultado já aberto. Abra DevTools → Network em `/api/submit` para confirmar que
nenhum PII trafega.

## Build local (sem Docker)

Precisa de Go ≥1.23, Rust e [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
go mod tidy
go run ./cmd/genkeys .
cd web/wasm && wasm-pack build --release --target web --out-dir ../static/pkg
cd ../..
go run ./cmd/server                    # http://localhost:8097
```

## Testes e cobertura

Stack mínima de testes com meta de **80% de cobertura** (Go + Rust).

```bash
make keys           # gera keys_gen.* (necessário antes de testar)
make test           # testes unitários Go + Rust
make cover          # porta de 80% em Go e Rust (precisa de cargo-llvm-cov)
make cover-docker   # roda tudo em container, sem instalar nada no host
```

Os testes Go recriam o selamento dentro do teste para exercitar
`unseal`/`handleSubmit`, garantem que a resposta **não vaza PII**, cobrem a lógica
de campos obrigatórios, assinaturas válidas/inválidas e entradas malformadas. Os
testes Rust cobrem selamento, assinatura, rejeição de JSON e o auxiliar de digest
nativamente.

## Criptografia, em detalhe

- **Assinatura:** Ed25519 sobre os bytes canônicos do formulário em JSON.
- **Selamento:** par x25519 efêmero;
  `shared = X25519(eph_secret, backend_pub)`;
  `key = HKDF-SHA256(shared, info="wasm-sealed-forms-v1")`;
  `XChaCha20-Poly1305(key, nonce)` com a chave pública efêmera como AAD.
- **Envelope:** `eph_pub(32) || nonce(24) || ciphertext`, codificado em base64.

## Estrutura

```
cmd/genkeys/      gera os pares de chave + arquivos-fonte com chaves embutidas
cmd/server/       servidor chi: SPA + wasm + /api/submit
web/wasm/         crate Rust (assinatura + selamento)
web/static/       SPA do formulário; a saída do wasm-pack vai para web/static/pkg/
```

## Licença

MIT
