# DECRYPTJWE

Este projeto é responsável por manipular e descriptografar tokens JWE (JSON Web Encryption).

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

3. Configure as chaves

O projeto utiliza um par de chaves (pública/privada) para criptografia. As chaves já estão incluídas no projeto:

- `public.pem`: Chave pública
- `private.pem`: Chave privada

Caso necessite gerar novas chaves, solicite a J17:


## Configuração

1. Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
GRANT_TYPE=""
CLIENT_ID=""
USERNAME_LOGIN=""
PASSWORD=""
```

## Como Usar

Para executar o projeto:

```bash
php jwe.php
```

## Estrutura do Projeto

- `jwe.php`: Arquivo principal do projeto
- `src/`: Diretório contendo os arquivos fonte
- `private.pem`: Chave privada para descriptografia
- `public.pem`: Chave pública para criptografia
- `vendor/`: Diretório de dependências do Composer

## Dependências Principais

O projeto utiliza as seguintes bibliotecas principais:

- `web-token/jwt-encryption`: Para manipulação de tokens JWE
- `web-token/jwt-key-mgmt`: Para gerenciamento de chaves
- `vlucas/phpdotenv`: Para gerenciamento de variáveis de ambiente

## Suporte

Em caso de dúvidas ou problemas, abra uma issue no repositório do GitHub.
