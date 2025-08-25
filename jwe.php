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
function getBearerToken() {
    $url = 'https://sbx.antifraude.j17bank.com.br/protocol/openid-connect/token';
    $data = http_build_query([
        'grant_type' => $_ENV['GRANT_TYPE'],
        'client_id' => $_ENV['CLIENT_ID'],
        'username' => $_ENV['USERNAME_LOGIN'],
        'password' => $_ENV['PASSWORD']
    ]);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/x-www-form-urlencoded'
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $result = curl_exec($ch);
    curl_close($ch);
    $json = json_decode($result, true);
    return $json['access_token'] ?? null;
}

// Use o token dinâmico:
$bearerToken = getBearerToken();

$apiUrl = 'https://sbx.antifraude.j17bank.com.br/J17/api/v1/processo';

echo "J17 Bank Antifraude\n";
echo "==================\n";

try {
    // Carregar chaves
    $publicKey = JWKFactory::createFromKey(file_get_contents('public.pem'));
    $privateKey = JWKFactory::createFromKey(file_get_contents('private.pem'));
    
    // Setup JWE
    $keyManager = new AlgorithmManager([new RSAOAEP256()]);
    $contentManager = new AlgorithmManager([new A256GCM()]);
    $serializer = new CompactSerializer();

    // pegar a foto e colocar ela como base64 eu.jpg
    $fotoBase64 = base64_encode(file_get_contents('eu.jpg'));

    // Dados para enviar
    $dados = [
        "callbackUri" => "/",
        "fluxo" => "complete",
        "processo" => [
            "pessoa" => [
                "cpf" => "03228935426",
                "nome" => "João da Silva Santos",
                "telefone" => "31987152444",
                "email" => "joao.teste@exemplo.com"
            ],
            "expiracao" => "3600s",
            "documentos" => [
                [
                    "tipo" => "Documento RG",
                    "conteudoBase64" => "$fotoBase64"
                ]
            ]
        ],
        "webhookUrl" => "https://webhook.site/4d370680-4b2b-4631-b552-aab70f1caa6e"
    ];

    // Criptografar dados
    $jweBuilder = new JWEBuilder($keyManager, $contentManager);
    $jwe = $jweBuilder
        ->create()
        ->withPayload(json_encode($dados))
        ->withSharedProtectedHeader([
            'alg' => 'RSA-OAEP-256',
            'enc' => 'A256GCM'
        ])
        ->addRecipient($publicKey)
        ->build();

    $dadosCriptografados = $serializer->serialize($jwe, 0);
    echo "Dados criptografados ✓\n";

    // Enviar para API
    $ch = curl_init($apiUrl);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/jose',
        'Authorization: Bearer ' . $bearerToken
    ]);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $dadosCriptografados);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    $resposta = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    echo "HTTP Status: $httpCode\n";

    if ($resposta) {
        // Verificar se resposta está criptografada
        if (strpos($resposta, '.') !== false && substr_count($resposta, '.') >= 4) {
            echo "Resposta criptografada - tentando descriptografar...\n";
            
            // Salvar resposta criptografada
            file_put_contents('resposta_criptografada.txt', $resposta);
            
            try {
                $decrypter = new JWEDecrypter($keyManager, $contentManager);
                $jweResposta = $serializer->unserialize($resposta);
                
                if ($decrypter->decryptUsingKey($jweResposta, $privateKey, 0)) {
                    $respostaDescriptografada = $jweResposta->getPayload();
                    echo "\nRESPOSTA DESCRIPTOGRAFADA:\n";
                    echo $respostaDescriptografada . "\n";
                    file_put_contents('resposta_final.json', $respostaDescriptografada);
                } else {
                    echo "Erro: Não conseguiu descriptografar\n";
                    echo "Verifique se o J17 tem sua chave pública\n";
                }
            } catch (Exception $e) {
                echo "Erro na descriptografia: " . $e->getMessage() . "\n";
            }
        } else {
            echo "Resposta não criptografada:\n";
            echo $resposta . "\n";
        }
    } else {
        echo "Resposta vazia\n";
    }

} catch (Exception $e) {
    echo "ERRO: " . $e->getMessage() . "\n";
}
?>