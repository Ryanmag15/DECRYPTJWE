# DECRYPTJWE

Este projeto é responsável por manipular e descriptografar tokens JWE (JSON Web Encryption) para integração com a API de antifraude.

## Pré-requisitos

- PHP 7.4 ou superior
- Composer
- OpenSSL

## Instalação

1. Clone o repositório:

```bash
git clone https://github.com/Ryanmag15/DECRYPTJWE.git
cd DECRYPTJWE
```

2. Instale as dependências via Composer:

```bash
composer install
```

3. Configure as chaves RSA

O projeto requer um par de chaves RSA (pública/privada) para criptografia e descriptografia dos tokens JWE. As chaves podem ser obtidas de duas formas:

### Opção 1: Solicitar as chaves à J17

Para ambiente de produção, solicite o par de chaves diretamente à J17.

### Opção 2: Gerar novas chaves para teste

Para ambiente de desenvolvimento/teste, você pode gerar suas próprias chaves:

1. Gere a chave privada:

```bash
openssl genpkey -algorithm RSA -out private.pem -pkcs8 -aes256
```

2. Gere a chave pública correspondente:

```bash
openssl rsa -pubout -in private.pem -out public.pem
```

### Requisitos das Chaves

- A chave privada (`private.pem`) deve:
  - Estar no formato PEM
  - Começar com `-----BEGIN PRIVATE KEY-----`
  - Ter permissões restritas (600 ou -rw-------)

- A chave pública (`public.pem`) deve:
  - Estar no formato PEM
  - Começar com `-----BEGIN PUBLIC KEY-----`
  - Pode ter permissões mais abertas (644 ou -rw-r--r--)

## Configuração do Ambiente

1. Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
GRANT_TYPE=""      # Fornecido pela J17
CLIENT_ID=""       # Fornecido pela J17
USERNAME_LOGIN=""  # Seu usuário
PASSWORD=""        # Sua senha
```

## Como Usar

O script principal `jwe.php` contém as seguintes funcionalidades:

1. Geração de token de acesso
2. Solicitação de processo com criptografia JWE
3. Consulta de resultado de processo
4. Consulta de documento

### Funções Principais

- `gerarToken()`: Gera um token de acesso para a API
- `solicitarProcesso($token)`: Envia uma solicitação criptografada
- `consultarResultado($token, $idProcesso)`: Consulta o resultado de um processo
- `consultarDocumento($token, $idDocumento)`: Consulta um documento específico
- `descriptografarResposta($resposta, $nomeArquivo)`: Utilitário para descriptografar respostas JWE

Para executar o projeto:

```bash
php jwe.php
```

## Estrutura do Projeto

- `jwe.php`: Arquivo principal com as funções de integração
- `private.pem`: Chave privada RSA para descriptografia (deve ser protegida)
- `public.pem`: Chave pública RSA para criptografia
- `vendor/`: Diretório de dependências do Composer
- `.env`: Arquivo de configuração com variáveis de ambiente

## Dependências Principais

O projeto utiliza as seguintes bibliotecas:

- `web-token/jwt-encryption`: Para manipulação de tokens JWE
- `web-token/jwt-key-mgmt`: Para gerenciamento de chaves RSA
- `vlucas/phpdotenv`: Para gerenciamento de variáveis de ambiente

## Segurança

⚠️ **IMPORTANTE**:
- Nunca compartilhe ou comite sua chave privada (`private.pem`)
- Mantenha as credenciais no arquivo `.env` seguras
- Use permissões apropriadas nos arquivos de chave
- Considere usar um gerenciador de segredos em produção
- Em ambiente Windows, certifique-se de que apenas usuários autorizados tenham acesso aos arquivos de chave

## Resolução de Problemas

Se encontrar problemas ao executar o projeto:

1. Verifique se as chaves estão no formato correto:
   - Use `openssl rsa -in private.pem -check` para validar a chave privada
   - Use `openssl rsa -pubin -in public.pem -text` para validar a chave pública

2. Certifique-se que todas as variáveis de ambiente estão configuradas no `.env`

3. Verifique as permissões dos arquivos:
   - No Windows, clique com o botão direito -> Propriedades -> Segurança
   - No Linux/Mac, use `chmod 600 private.pem` e `chmod 644 public.pem`

4. Se receber erros de criptografia:
   - Confirme que está usando o par correto de chaves (pública/privada)
   - Verifique se as chaves são compatíveis com o algoritmo RSA-OAEP-256

## Suporte

Em caso de problemas:
1. Verifique o log de erros do PHP
2. Consulte a documentação da J17
3. Abra uma issue no repositório do GitHub
