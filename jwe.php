<?php
require 'vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Encryption\Serializer\CompactSerializer;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

/**
 * Função utilitária para descriptografar respostas JWE
 */
function descriptografarResposta($resposta, $nomeArquivo = 'resposta.json') {
    try {
        $privateKey = JWKFactory::createFromKey(file_get_contents('private.pem'));
        $serializer = new CompactSerializer();

        if (strpos($resposta, '.') !== false && substr_count($resposta, '.') >= 4) {
            $jwe = $serializer->unserialize($resposta);
            $decrypter = new JWEDecrypter(
                new AlgorithmManager([new RSAOAEP256()]),
                new AlgorithmManager([new A256GCM()])
            );

            if ($decrypter->decryptUsingKey($jwe, $privateKey, 0)) {
                $payload = $jwe->getPayload();
                echo "RESPOSTA DESCRIPTOGRAFADA:\n$payload\n";

                // salvar JSON formatado em arquivo
                $jsonArr = json_decode($payload, true);
                if ($jsonArr) {
                    file_put_contents($nomeArquivo, json_encode($jsonArr, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
                } else {
                    file_put_contents($nomeArquivo, $payload); // fallback se não for JSON válido
                }

                return $payload;
            } else {
                echo "Não conseguiu descriptografar. Verifique a chave.\n";
            }
        } else {
            echo "Resposta não criptografada:\n$resposta\n";
            file_put_contents($nomeArquivo, $resposta);
            return $resposta;
        }
    } catch (Exception $e) {
        echo "Erro ao descriptografar: ".$e->getMessage()."\n";
    }
    return null;
}

/**
 * 01 - Gerar Token
 */
function gerarToken() {
    try {
        $url = 'https://sbx.antifraude.j17bank.com.br/protocol/openid-connect/token';
        $data = http_build_query([
            'grant_type' => $_ENV['GRANT_TYPE'],
            'client_id'  => $_ENV['CLIENT_ID'],
            'username'   => $_ENV['USERNAME_LOGIN'],
            'password'   => $_ENV['PASSWORD']
        ]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false
        ]);
        $result = curl_exec($ch);
        curl_close($ch);

        $json = json_decode($result, true);
        echo "Token: " . ($json['access_token'] ?? 'erro') . "\n";
        return $json['access_token'] ?? null;
    } catch (Exception $e) {
        echo "Erro gerarToken: ".$e->getMessage()."\n";
    }
    return null;
}

/**
 * 02 - Solicitar Processo (com criptografia e descriptografia)
 */
function solicitarProcesso($token) {
    try {
        $publicKey = JWKFactory::createFromKey(file_get_contents('public.pem'));
        $serializer = new CompactSerializer();
        $fotoBase64 = base64_encode(file_get_contents('contrato.pdf'));

        $dados = [
            "callbackUri" => "https://www.j17bank.com.br/",
            "fluxo" => "complete",
            "processo" => [
                "pessoa" => [
                    "cpf" => "03228935426",
                    "nome" => "Joao da Silva Santos",
                    "telefone" => "31987152444",
                    "email" => "joao.teste@exemplo.com"
                ],
                "expiracao" => "3600s",
                "documentos" => [
                    ["nome" => "Contrato", "conteudoBase64" => $fotoBase64]
                ]
            ],
            "webhookUrl" => "https://webhook.site/69311e4f-cbbb-4163-b77f-0f14481fcc77"
        ];

        // Criptografar payload
        $jwe = (new JWEBuilder(
            new AlgorithmManager([new RSAOAEP256()]),
            new AlgorithmManager([new A256GCM()])
        ))
        ->create()
        ->withPayload(json_encode($dados))
        ->withSharedProtectedHeader(['alg' => 'RSA-OAEP-256','enc'=>'A256GCM'])
        ->addRecipient($publicKey)
        ->build();

        $dadosCriptografados = $serializer->serialize($jwe);

        // Enviar requisição
        $ch = curl_init("https://sbx.antifraude.j17bank.com.br/J17/api/v1/processo");
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/jose',
                'Authorization: Bearer ' . $token
            ],
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $dadosCriptografados,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false
        ]);
        $resposta = curl_exec($ch);
        curl_close($ch);

        file_put_contents('resposta_solicitar_processo.txt', $resposta);
        return descriptografarResposta($resposta, 'resposta_solicitar_processo.json');
    } catch (Exception $e) {
        echo "Erro solicitarProcesso: ".$e->getMessage()."\n";
    }
}

/**
 * 03 - Consultar Resultado
 */
function consultarResultado($token, $idProcesso) {
    try {
        $url = "https://sbx.antifraude.j17bank.com.br/J17/api/v1/consulta-resultado-processo?idProcesso={$idProcesso}";
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => ['Authorization: Bearer '.$token],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false
        ]);
        $resposta = curl_exec($ch);
        curl_close($ch);

        file_put_contents('resposta_consultar_resultado.txt', $resposta);
        return descriptografarResposta($resposta, 'resposta_consultar_resultado.json');
    } catch (Exception $e) {
        echo "Erro consultarResultado: ".$e->getMessage()."\n";
    }
}

/**
 * 04 - Consultar Documento
 */
function consultarDocumento($token, $idDocumento) {
    try {
        $url = "https://sbx.antifraude.j17bank.com.br/J17/api/v1/consulta-documento/{$idDocumento}";
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => ['Authorization: Bearer '.$token],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false
        ]);
        $resposta = curl_exec($ch);
        curl_close($ch);

        file_put_contents('resposta_consultar_documento.txt', $resposta);
        return descriptografarResposta($resposta, 'resposta_consultar_documento.json');
    } catch (Exception $e) {
        echo "Erro consultarDocumento: ".$e->getMessage()."\n";
    }
}

// ------------------------------
// Exemplo de uso
// ------------------------------
$token = gerarToken();

// Comente/descomente para testar
solicitarProcesso($token);
consultarResultado($token, "5042");
consultarDocumento($token, "363f3051-ea70-4abf-932b-2767a2fe66d9");
