# JWE Antifraude - J17 Bank

Este projeto demonstra como enviar dados criptografados via JWE (JSON Web Encryption) para a API de antifraude do J17 Bank utilizando PHP.

## Funcionalidades
- Carrega chaves pública e privada (PEM)
- Codifica uma imagem em base64
- Monta o payload de dados do processo antifraude
- Criptografa os dados usando JWE (RSA-OAEP-256 + A256GCM)
- Envia os dados criptografados para a API via cURL
- Recebe e tenta descriptografar a resposta da API
- Salva respostas criptografadas e descriptografadas em arquivos

## Estrutura
- `jwe.php`: Script principal
- `public.pem` / `private.pem`: Chaves para criptografia
- `eu.jpg`: Imagem usada como documento
- `resposta_criptografada.txt`: Resposta da API (criptografada)
- `resposta_final.json`: Resposta da API (descriptografada)
- `composer.json` / `composer.lock`: Gerenciamento de dependências
- `vendor/`: Bibliotecas instaladas via Composer

## Como executar
1. Instale as dependências:
   ```powershell
   composer install
   ```
2. Adicione suas chaves `public.pem` e `private.pem` na raiz do projeto.
3. Coloque a imagem `eu.jpg` na raiz do projeto.
4. Execute o script:
   ```powershell
   php jwe.php
   ```

## Principais bibliotecas
- [web-token/jwt-encryption](https://github.com/web-token/jwt-encryption)
- [spomky-labs/pki-framework](https://github.com/Spomky-Labs/pki-framework)
- [symfony/console](https://github.com/symfony/console)

## Exemplo de payload enviado
```json
{
  "callbackUri": "/",
  "fluxo": "faceocr",
  "processo": {
    "pessoa": {
      "cpf": "12345678911",
      "nome": "João da Silva Santos",
      "telefone": "31987152400",
      "email": "joao.teste@exemplo.com"
    },
    "expiracao": "3600s",
    "documentos": [
      {
        "tipo": "Documento RG",
        "conteudoBase64": "<base64 da imagem>"
      }
    ]
  },
  "webhookUrl": "https://webhook.site/4d370680-4b2b-4631-b552-aab70f1caa6e"
}
```

## Observações
- Certifique-se de que as chaves estejam corretas e compatíveis com a API.
- O token Bearer deve ser válido para autenticação.
- O script salva as respostas para facilitar depuração.

## Licença
Este projeto é apenas para fins de demonstração e testes.
