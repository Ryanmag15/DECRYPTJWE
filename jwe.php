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
        $url = 'https://antifraude.j17bank.com.br/protocol/openid-connect/token';
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

        // $dados = [
        //     "callbackUri" => "https://www.j17bank.com.br/",
        //     "fluxo" => "complete",
        //     "processo" => [
        //         "pessoa" => [
        //             "cpf" => "37436645854",
        //             "nome" => "Alexandre Zupa de Souza",
        //             "telefone" => "5543991821833",
        //             "email" => "alexandre.zupa@j17tech.com.br"
        //         ],
        //         "expiracao" => "3600s",
        //         "documentos" => [
        //             ["nome" => "Contrato", "conteudoBase64" => $fotoBase64]
        //         ]
        //     ],
        //     "webhookUrl" => "https://webhook.site/c1c14ce0-4824-4fdb-b359-30da7d41414b"
        // ];
        // $dados = [
        //     "callbackUri" => "https://www.j17bank.com.br/",
        //     "fluxo" => "complete",
        //     "processo" => [
        //         "pessoa" => [
        //             "cpf" => "02181775699",
        //             "nome" => "RYAN MAGALHAES MATHIAS",
        //             "telefone" => "5531987152409",
        //             "email" => "ryan.mathias@idealizeservicos.com.br"
        //         ],
        //         "expiracao" => "3600s",
        //         "documentos" => [
        //             ["nome" => "Contrato", "conteudoBase64" => $fotoBase64]
        //         ]
        //     ],
        //     "webhookUrl" => "https://webhook.site/c1c14ce0-4824-4fdb-b359-30da7d41414b"
        // ];
        $dados = [
            "callbackUri" => "https://www.j17bank.com.br/",
            "fluxo" => "complete",
            "processo" => [
                "pessoa" => [
                    "cpf" => "08031406901",
                    "nome" => "Andrey Ribeiro Frisselli",
                    "telefone" => "5543991447905",
                    "email" => "andrey.frisselli@j17tech.com.br"
                ],
                "expiracao" => "3600s",
                "documentos" => [
                    ["nome" => "Contrato", "conteudoBase64" => $fotoBase64]
                ]
            ],
            "webhookUrl" => "https://webhook.site/c1c14ce0-4824-4fdb-b359-30da7d41414b"
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
        $ch = curl_init("https://antifraude.j17bank.com.br/J17/api/v1/processo");
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
        $url = "https://antifraude.j17bank.com.br/J17/api/v1/consulta-resultado-processo?idProcesso={$idProcesso}";
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
        $url = "https://antifraude.j17bank.com.br/J17/api/v1/consulta-documento/{$idDocumento}";
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
// consultarResultado($token, "11");
// consultarDocumento($token, "363f3051-ea70-4abf-932b-2767a2fe66d9");

// $webhookRecebido = "eyJraWQiOiI1ZDczNzE5YS0wYmFlLTRlYjktOWYxZC0zMDMzNjI2ZTlhZDciLCJjdHkiOiJhcHBsaWNhdGlvbi9qc29uIiwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IlJTQS1PQUVQLTI1NiJ9.Fl7R37kdC7v_wQ4pqEoYjJSiYHS3t7y1tFU_z-7THwACtsxlqNQRCTgQ9RBeDYyHhOcEmC9tQkabz_k5Izsx3eAeh5yyyw9iYZ5kKpOvQ8gjF0EwO9lT2QGhHdBf3LmiEWOL3cb9dxxHeLK_wXIsJrT_7mdTy1gv7GS9z-0nmLF7bTSoOkbsMC5AA2nveJYvzye_9--u0B798LJFJ_xNlJNPP2b0lqAvTCDO8PsK_1scJdgt2Qx_TUPxwb7dS2y94yFu56jVwyYA_Z08_jvOuvzuTRLQqYuyDOS7nwRkrBqEbSxOtJZeRwQkYXVxxnY8u8pM9VoO-zy7b5YjHkaDlA.VLQucHmGyJZPBZ9Q.vX91P-hvZHpRwgriWZVdIvUc6vY-xs3Pv8-nTnN1eZ3-P4YqSsqK-Z32Zm0q4G5-n2JZiTUK0kVqZghS0hKrKQqNvGfdYpmcQVC8mxdBK5rNCLkjn1xnuTYwqOABTDoHTjsclsY-CyPHCO_JwmX7rjpqeTW5IfoibADu84KOg3tWP64Qse6QDd6k8F4xml-qd_KwskIunIJggd14ZjnSrTi7YhWhxzAALqIj00EIJEwMB4FjyjN0QO0kteMzJERbxDMbk6RrHw-oeMdBlxY63KXYtuoiLe6RktO7ZHE-PxGb4LLfweKCUHnB-Gg-FzP8tCGuK8v4vURRTSLJVRWhCCBINBTunuAjqA3851PyqhTIwsFitCkB8XhdRP2-RTU4jQTnk9Md22sEdng1RPasOYDvi6ZqUTJYzwDU_tpq0QPUmTF1iXKMgw0OXb5fUF7vUacP4qhwIE9vrcuRuVmXhHLJnbTgh5lRD6ainuj90tfBkQ1PAmNcT6sA-fvnYtbzsW6OXuJEB8S4vz8qy7C70P-YlCkvVTJks4h3EQu-k6ZpD94VNPSmYY2LUyvKw6j8U1M_9_YWExSWHMioh5-_iETpi3aqiaaeKscmKwpaUstlDDDIgRrq_nfrcmIsdloKzjcoIqNbDcuOStUghXZlnK79kW_m71s5_OvrWcXVRTlK04i9klVSQxwnhlp2iGSfnrgI1xcXlL5aOJaYNs-J13k1VOoaElaHdDVhk-VMPUFLg-KHWv5ozMEOo1x-BWU0CzTa0q0XyNBVM_X2pZitDDkQa-XCr0zGkQ595jJVQ9ZBKsfCYshQ76Y2CLQW6Rv42XeEXmwTcyny70ud3-VY0nQV51pW3_csj9f3oyA8lMRsQ1YPubMqgKkEeQz8WdOYSmdDUOqwkV05-ZvxznYfZpcXm19fS8nXvO0NT9Y84kWzGfBjWyXye-uQ0j97OKGrnStnzaT9N3ojI5VAPgQ3hQkyecaFAaTxX14J3j8aEdqBUOJbOaLF98gQVlHRLupZEhTxOvqT6w2I3fFp-CqzM_ljG1gGQX3sPoru90POITglAByzSkyoznM8hFh_7PzU-DwbdiNZkAQhxets5Rcim3U5i3bnZVLQnqeA9-qOHVRtStAf1JeGR-pkv1w10bqTIrOFykEP1SmF_A0UkA5cJiqHdzUtoqHCFPLkMgALkn1SzooEBhADUhWGTtU6TrD8eXD3F1af2sbweY_8AGsDoMRYAwjG8QEls8c-i9bw6_uu4rB6xtgMWsJvwlPbgTL7I9UUmfAXb3-lH5IaXfYL1F_VcllJivwgg8Q8vU8SFvR3HJeDV1Lp39I9JskAc6BkiZbl77Dijz4qqbwm8zgxHu7CKt9TRGgMTzvq9YYCvCanwI1QVP1R84EHIhjrLAU9AfiYnzRqNE9Tcf26-2aFAUSJr8O4qCmWnMDx_SAC6pdlmkLbxMLaEjBHYMqFpD7jHEv6rk3a9rtgAxBg_HC7TKHqNg55VTUCGE9Dv1I5ZAw5ABA0EoidhyYMP2cs0KOtw5aI4SNd1-zYzJ0suHDSNAqMCNtCkiRif4cLlukNOH9VjM4CCfhCgjSjAUSpEDiZzNf9FUsZQGJG1LZtkuub3hjiLwqfQdBvOLiXG3BHMIdMmxuj5N-maxWmFIbT-pmhIaUR8s6c_lAvw-mo7nAIwWg2UoaWX-3IB7doq8gmTgAxo88Qgh4WLOQa1wjTag8wuJXSMr6uU4F51WApBuNC4PBoCb6-5uOCb0-q2gMx9HYJaCEXByn7vimmaBRog0tbug4OFqUHZ36L_gBHIlH8L0IB6w_mgfaM74PzrUtuqc-MLRQ6vujI2kHPBIheVDZJrRrciTLMcEpqMw.zVNdL7PSo1gXLNc_WnxkAw"
// descriptografarResposta($webhookRecebido, 'resposta_webhook.json');
