<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Ileva\SdkApiV3\Auth\Exception\ApiException;
use Ileva\SdkApiV3\Auth\Exception\AuthenticationException;
use Ileva\SdkApiV3\Auth\Exception\LockTimeoutException;
use Ileva\SdkApiV3\Auth\Exception\TransportException;
use Ileva\SdkApiV3\Auth\IlevaSdkApiV3Auth;
use Ileva\SdkApiV3\Auth\Store\InMemoryTokenStore;
use Ileva\SdkApiV3\Auth\Store\TokenStore;
use Ileva\SdkApiV3\Auth\Token;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class IlevaSdkApiV3AuthTest extends TestCase
{
    private MockHandler $mock;
    /** @var list<array{request: RequestInterface}> */
    private array $history = [];
    private Client $guzzle;
    private InMemoryTokenStore $store;

    /**
     * Verificador da senha "segredo" gerado com salt fixo (16 bytes 0x01). O SDK de Node testa o
     * mesmo valor: os dois precisam aceitar o verificador gravado pelo outro.
     */
    private const SEGREDO_CHECK = 'pbkdf2-sha256$100000$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=';

    protected function setUp(): void
    {
        InMemoryTokenStore::clear();
        self::clearVerified();

        $this->mock = new MockHandler();
        $this->history = [];
        $stack = HandlerStack::create($this->mock);
        $stack->push(Middleware::history($this->history));
        $this->guzzle = new Client(['handler' => $stack]);
        $this->store = new InMemoryTokenStore();
    }

    protected function tearDown(): void
    {
        InMemoryTokenStore::clear();
        self::clearVerified();
    }

    /** Esquece as conferências de senha memorizadas no processo, para cada teste começar do zero. */
    private static function clearVerified(): void
    {
        (new \ReflectionProperty(IlevaSdkApiV3Auth::class, 'verified'))->setValue(null, []);
    }

    /** Grava um token no cache como o SDK grava: com o verificador da senha "segredo". */
    private function seed(Token $token, int $ttl, ?string $passwordCheck = self::SEGREDO_CHECK): void
    {
        $this->store->set($this->tokenKey(), $token->toJson($passwordCheck), $ttl);
    }

    private function auth(array $options = []): IlevaSdkApiV3Auth
    {
        return new IlevaSdkApiV3Auth(...array_merge([
            'appKey' => 'app-key',
            'username' => 'integracao',
            'password' => 'segredo',
            'guzzle' => $this->guzzle,
            'baseUrl' => 'https://api.teste/',
        ], $options));
    }

    private function queueToken(string $accessToken, int $expiresIn = 86400): self
    {
        return $this->queue(200, ['access_token' => $accessToken, 'token_type' => 'Bearer', 'expires_in' => $expiresIn]);
    }

    private function queue(int $status, mixed $body): self
    {
        $this->mock->append(new Response($status, ['Content-Type' => 'application/json'], is_string($body) ? $body : json_encode($body)));
        return $this;
    }

    private function tokenKey(): string
    {
        return 'ileva:auth:token:' . hash('sha256', "https://api.teste\napp-key\nintegracao");
    }

    private function lockKey(): string
    {
        return 'ileva:auth:lock:' . hash('sha256', "https://api.teste\napp-key\nintegracao");
    }

    public function testGeraTokenPeloGuzzleInjetado(): void
    {
        $this->queueToken('tok-1');

        self::assertSame('tok-1', $this->auth()->getToken());

        self::assertCount(1, $this->history);
        $request = $this->history[0]['request'];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('https://api.teste/oauth/token', (string) $request->getUri());
        self::assertSame('app-key', $request->getHeaderLine('app_key'));
        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));
        self::assertSame(['username' => 'integracao', 'password' => 'segredo'], json_decode((string) $request->getBody(), true));
    }

    public function testSemRedisInstanciasComAsMesmasCredenciaisCompartilhamOToken(): void
    {
        $this->queueToken('tok-1');
        $this->auth()->getToken();

        // Nova instância, sem Redis e sem store: reaproveita o token da lista estática.
        $outra = $this->auth();
        self::assertSame('tok-1', $outra->getToken());
        self::assertSame('Bearer tok-1', $outra->getAuthorizationHeader());
        self::assertCount(1, $this->history);
    }

    public function testUsuariosDaMesmaAppKeyTemTokensIndependentes(): void
    {
        $this->queueToken('tok-joao')->queueToken('tok-maria');
        $joao = $this->auth(['username' => 'joao']);
        $maria = $this->auth(['username' => 'maria']);

        self::assertSame('tok-joao', $joao->getToken());
        self::assertSame('tok-maria', $maria->getToken());
        // Nenhum dos dois foi substituído pela geração do outro.
        self::assertSame('tok-joao', $this->auth(['username' => 'joao'])->getToken());
        self::assertSame('tok-maria', $this->auth(['username' => 'maria'])->getToken());
        self::assertCount(2, $this->history);
        self::assertSame('joao', json_decode((string) $this->history[0]['request']->getBody(), true)['username']);
        self::assertSame('maria', json_decode((string) $this->history[1]['request']->getBody(), true)['username']);
    }

    public function testInvalidarUmUsuarioNaoAfetaOutro(): void
    {
        $this->queueToken('tok-joao')->queueToken('tok-maria')->queueToken('tok-joao-2');
        $joao = $this->auth(['username' => 'joao']);
        $maria = $this->auth(['username' => 'maria']);
        $joao->getToken();
        $maria->getToken();

        $joao->invalidate();

        self::assertSame('tok-maria', $maria->getToken());
        self::assertSame('tok-joao-2', $joao->getToken());
        self::assertCount(3, $this->history);
    }

    public function testMesmoUsuarioEmAppKeysDiferentesTemTokensIndependentes(): void
    {
        $this->queueToken('tok-a')->queueToken('tok-b');

        self::assertSame('tok-a', $this->auth(['appKey' => 'associacao-a'])->getToken());
        self::assertSame('tok-b', $this->auth(['appKey' => 'associacao-b'])->getToken());
        self::assertSame('tok-a', $this->auth(['appKey' => 'associacao-a'])->getToken());
        self::assertCount(2, $this->history);
    }

    public function testChaveDoCacheIgnoraCaixaDoUsuarioEBarraFinalDaUrl(): void
    {
        $this->queueToken('tok-1');

        $this->auth()->getToken();

        self::assertNotNull($this->store->get($this->tokenKey()));
        self::assertSame('tok-1', $this->auth(['username' => ' Integracao ', 'baseUrl' => 'https://api.teste'])->getToken());
        self::assertCount(1, $this->history);
    }

    public function testChaveUsaMinusculasSoEmAsciiComoOsOutrosSdks(): void
    {
        // "Ã" não vira "ã": as funções de minúsculas de cada linguagem divergem fora do ASCII, e a
        // chave precisa ser igual em todos os SDKs.
        $this->queueToken('tok-1');
        $this->auth(['username' => " JOÃO\t"])->getToken();

        $key = 'ileva:auth:token:' . hash('sha256', "https://api.teste\napp-key\njoÃo");
        self::assertNotNull($this->store->get($key));
    }

    public function testGravaNoCacheNoFormatoCompartilhadoEntreSdks(): void
    {
        $this->queueToken('tok-1', 3600);
        $before = time();

        $this->auth()->getToken();

        $stored = json_decode($this->store->get($this->tokenKey()), true);
        self::assertSame('tok-1', $stored['access_token']);
        self::assertSame('Bearer', $stored['token_type']);
        self::assertGreaterThanOrEqual($before + 3600, $stored['expires_at']);
        self::assertLessThanOrEqual(time() + 3600, $stored['expires_at']);
    }

    public function testRenovaTokenDentroDaMargemDeRenovacao(): void
    {
        $this->seed(new Token('velho', 'Bearer', time() + 200), 200);
        $this->queueToken('novo');

        self::assertSame('novo', $this->auth(['refreshMargin' => 300])->getToken());
    }

    public function testUsaTokenForaDaMargemDeRenovacao(): void
    {
        $this->seed(new Token('atual', 'Bearer', time() + 400), 400);

        self::assertSame('atual', $this->auth(['refreshMargin' => 300])->getToken());
        self::assertCount(0, $this->history);
    }

    public function testValorCorrompidoNoCacheEhTratadoComoVazio(): void
    {
        $this->store->set($this->tokenKey(), 'nao-e-json', 60);
        $this->queueToken('tok-1');

        self::assertSame('tok-1', $this->auth()->getToken());
    }

    public function testInvalidateComTokenRecusadoPreservaTokenNovoDeOutroProcesso(): void
    {
        $this->seed(new Token('novo', 'Bearer', time() + 3600), 3600);
        $auth = $this->auth();

        $auth->invalidate('velho');

        self::assertSame('novo', $auth->getToken());
        self::assertCount(0, $this->history);
    }

    public function testInvalidateComTokenAtualForcaNovaGeracao(): void
    {
        $this->queueToken('tok-1')->queueToken('tok-2');
        $auth = $this->auth();

        $auth->invalidate($auth->getToken());

        self::assertSame('tok-2', $auth->getToken());
    }

    public function testRefreshGeraTokenMesmoComTokenValido(): void
    {
        $this->queueToken('tok-1')->queueToken('tok-2');
        $auth = $this->auth();
        $auth->getToken();

        self::assertSame('tok-2', $auth->refresh());
    }

    public function testEnviaCodigoDoisFatores(): void
    {
        $this->queueToken('tok-1');

        $this->auth(['twoFactorCode' => fn () => '123456'])->getToken();

        self::assertSame('123456', json_decode((string) $this->history[0]['request']->getBody(), true)['two_fa']);
    }

    public function testErro401ViraAuthenticationExceptionComMensagemDaApi(): void
    {
        $this->queue(401, ['status' => 401, 'mensagem' => 'Usuário ou senha inválidos']);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Usuário ou senha inválidos');
        $this->expectExceptionCode(401);

        $this->auth()->getToken();
    }

    public function testErro401ComGuzzleConfiguradoParaLancarExcecao(): void
    {
        // Mesmo que o cliente da aplicação tenha http_errors ligado por padrão, a mensagem da API chega.
        $guzzle = new Client(['handler' => HandlerStack::create($this->mock), 'http_errors' => true]);
        $this->queue(401, ['status' => 401, 'mensagem' => 'App key inválida']);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('App key inválida');

        $this->auth(['guzzle' => $guzzle])->getToken();
    }

    public function testErroDiferenteDe401ViraApiException(): void
    {
        $this->queue(500, 'Internal Server Error');

        $this->expectException(ApiException::class);
        $this->expectExceptionCode(500);

        $this->auth()->getToken();
    }

    public function testRespostaSemAccessTokenViraApiException(): void
    {
        $this->queue(200, ['expires_in' => 60]);

        $this->expectException(ApiException::class);

        $this->auth()->getToken();
    }

    public function testFalhaDeConexaoViraTransportException(): void
    {
        $this->mock->append(new ConnectException('Connection refused', new Request('POST', 'https://api.teste/oauth/token')));

        $this->expectException(TransportException::class);
        $this->expectExceptionMessage('Connection refused');

        $this->auth()->getToken();
    }

    public function testSenhaNaoApareceNoTraceDeFalhaDeConexao(): void
    {
        $this->mock->append(new ConnectException('Connection refused', new Request('POST', 'https://api.teste/oauth/token')));

        try {
            $this->auth(['password' => 'senha-secreta-123'])->getToken();
            self::fail('Era esperada TransportException.');
        } catch (TransportException $e) {
            // Ferramentas como o Sentry enviam os argumentos de cada frame, da exceção e das anteriores:
            // strings e arrays por inteiro, objetos só pelo nome da classe.
            for ($current = $e; $current !== null; $current = $current->getPrevious()) {
                foreach ($current->getTrace() as $frame) {
                    self::assertNotContains('senha-secreta-123', self::scalarValues($frame['args'] ?? []), $frame['function']);
                }
            }
        }
    }

    /** @return list<string> */
    private static function scalarValues(array $values): array
    {
        $found = [];
        array_walk_recursive($values, function ($value) use (&$found) {
            if (is_string($value)) {
                $found[] = $value;
            }
        });
        return $found;
    }

    public function testDumpDaInstanciaNaoExpoeSenhaNemAppKey(): void
    {
        $dump = print_r($this->auth(['password' => 'senha-secreta-123', 'appKey' => 'app-key-secreta']), true);

        self::assertStringNotContainsString('senha-secreta-123', $dump);
        self::assertStringNotContainsString('app-key-secreta', $dump);
        self::assertStringContainsString('integracao', $dump);
    }

    public function testSenhaErradaComTokenEmCacheConsultaAApiERecebe401(): void
    {
        $this->queueToken('tok-certo');
        $this->auth()->getToken();
        $this->queue(401, ['status' => 401, 'mensagem' => 'Usuário ou senha inválidos']);

        try {
            $this->auth(['password' => 'errada'])->getToken();
            self::fail('Era esperada AuthenticationException.');
        } catch (AuthenticationException $e) {
            self::assertSame('Usuário ou senha inválidos', $e->getMessage());
        }

        // A senha errada foi à API; o token de quem acertou continua no cache.
        self::assertCount(2, $this->history);
        self::assertSame('errada', json_decode((string) $this->history[1]['request']->getBody(), true)['password']);
        self::assertSame('tok-certo', $this->auth()->getToken());
        self::assertCount(2, $this->history);
    }

    public function testSenhaErradaNaoAproveitaConferenciaMemorizadaDaSenhaCerta(): void
    {
        $this->queueToken('tok-certo');
        $this->auth()->getToken();
        self::assertSame('tok-certo', $this->auth()->getToken()); // conferência memorizada no processo
        $this->queue(401, ['status' => 401, 'mensagem' => 'Usuário ou senha inválidos']);

        $this->expectException(AuthenticationException::class);

        $this->auth(['password' => 'errada'])->getToken();
    }

    public function testAceitaOVerificadorGravadoPeloSdkDeNode(): void
    {
        $this->seed(new Token('do-node', 'Bearer', time() + 3600), 3600, self::SEGREDO_CHECK);

        self::assertSame('do-node', $this->auth()->getToken());
        self::assertCount(0, $this->history);
    }

    public function testTokenSemVerificadorEhTratadoComoCacheVazio(): void
    {
        $this->seed(new Token('sem-verificador', 'Bearer', time() + 3600), 3600, null);
        $this->queueToken('tok-novo');

        self::assertSame('tok-novo', $this->auth()->getToken());
    }

    public function testVerificadorAdulteradoEhTratadoComoSenhaDiferente(): void
    {
        foreach ([
            'pbkdf2-sha256$99999999$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=',
            'md5$1$AQ==$AQ==',
            'lixo',
        ] as $check) {
            $this->seed(new Token('adulterado', 'Bearer', time() + 3600), 3600, $check);
            $this->queueToken('tok-novo');
            self::assertSame('tok-novo', $this->auth()->getToken());
        }
    }

    public function testSenhaNovaCorretaSubstituiTokenGeradoComSenhaAntiga(): void
    {
        $this->queueToken('tok-senha-antiga')->queueToken('tok-senha-nova');
        $this->auth(['password' => 'antiga'])->getToken();

        // A API aceita a senha nova; o token gerado com a antiga dá lugar ao novo.
        self::assertSame('tok-senha-nova', $this->auth(['password' => 'nova'])->getToken());
        self::assertSame('tok-senha-nova', $this->auth(['password' => 'nova'])->getToken());
        self::assertCount(2, $this->history);
    }

    public function testTokenObtidoCom2faNaoEhDevolvidoDoCacheSemOCodigo(): void
    {
        $this->queueToken('tok-com-2fa');
        $this->auth(['twoFactorCode' => fn () => '123456'])->getToken();
        $this->queue(401, ['status' => 401, 'mensagem' => 'Informe o código de verificação de autenticação de dois fatores (two_fa)']);

        // Senha certa, sem o código: vai à API, que exige o 2FA.
        try {
            $this->auth()->getToken();
            self::fail('Era esperada AuthenticationException.');
        } catch (AuthenticationException $e) {
            self::assertStringContainsString('dois fatores', $e->getMessage());
        }
        self::assertCount(2, $this->history);
        self::assertArrayNotHasKey('two_fa', json_decode((string) $this->history[1]['request']->getBody(), true));
    }

    public function testCadaLoginCom2faConsultaAApi(): void
    {
        $this->queueToken('tok-1')->queueToken('tok-2');

        self::assertSame('tok-1', $this->auth(['twoFactorCode' => fn () => '111111'])->getToken());
        self::assertSame('tok-2', $this->auth(['twoFactorCode' => fn () => '222222'])->getToken());

        self::assertCount(2, $this->history);
        self::assertSame('222222', json_decode((string) $this->history[1]['request']->getBody(), true)['two_fa']);
    }

    public function testTokenCom2faFicaMarcadoNoCache(): void
    {
        $this->queueToken('tok-1');
        $this->auth(['twoFactorCode' => fn () => '123456'])->getToken();

        self::assertTrue(json_decode($this->store->get($this->tokenKey()), true)['two_factor']);
    }

    public function testTokenSem2faNaoLevaAMarca(): void
    {
        $this->queueToken('tok-1');
        $this->auth()->getToken();

        self::assertArrayNotHasKey('two_factor', json_decode($this->store->get($this->tokenKey()), true));
    }

    public function testRespeitaAMarcaDe2faGravadaPeloSdkDeNode(): void
    {
        $this->store->set(
            $this->tokenKey(),
            '{"access_token":"do-node-com-2fa","token_type":"Bearer","expires_at":' . (time() + 3600)
                . ',"password_check":"' . self::SEGREDO_CHECK . '","two_factor":true}',
            3600,
        );
        $this->queueToken('tok-novo');

        self::assertSame('tok-novo', $this->auth()->getToken());
    }

    public function testCacheNaoGuardaASenha(): void
    {
        $this->queueToken('tok-1');
        $this->auth()->getToken();

        $stored = $this->store->get($this->tokenKey());
        self::assertStringNotContainsString('segredo', $stored);
        self::assertMatchesRegularExpression('/^pbkdf2-sha256\$100000\$[A-Za-z0-9+\/=]+\$[A-Za-z0-9+\/=]+$/', json_decode($stored, true)['password_check']);
    }

    public function testFalhaNaGeracaoLiberaOLock(): void
    {
        $this->queue(500, '')->queueToken('tok-1');
        $auth = $this->auth(['lockWait' => 0.3]);

        try {
            $auth->getToken();
            self::fail('Era esperada ApiException.');
        } catch (ApiException) {
        }

        // Se o lock tivesse ficado preso, esta chamada esperaria e daria LockTimeoutException.
        self::assertSame('tok-1', $auth->getToken());
    }

    public function testEsperaTokenGeradoPorOutroProcessoQueSeguraOLock(): void
    {
        $this->store->acquireLock($this->lockKey(), 'outro-processo', 10_000);
        $store = new TokenAppearsAfterReadsStore($this->store, $this->tokenKey(), 3, new Token('do-outro', 'Bearer', time() + 3600));

        self::assertSame('do-outro', $this->auth(['store' => $store])->getToken());
        self::assertCount(0, $this->history);
    }

    public function testLockPresoSemTokenEstouraOTempoDeEspera(): void
    {
        $this->store->acquireLock($this->lockKey(), 'outro-processo', 10_000);

        $this->expectException(LockTimeoutException::class);

        $this->auth(['lockWait' => 0.3])->getToken();
    }

    public function testRedisEStoreJuntosSaoRecusados(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->auth(['redis' => new \stdClass(), 'store' => $this->store]);
    }

    public function testConexaoRedisNaoSuportadaEhRecusada(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Conexão Redis não suportada');

        $this->auth(['redis' => new \stdClass()]);
    }
}

/** Simula outro processo que grava o token no cache depois de algumas leituras. */
final class TokenAppearsAfterReadsStore implements TokenStore
{
    private const SEGREDO_CHECK = 'pbkdf2-sha256$100000$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=';

    private int $reads = 0;

    public function __construct(
        private readonly TokenStore $inner,
        private readonly string $tokenKey,
        private readonly int $afterReads,
        private readonly Token $token,
    ) {
    }

    public function get(string $key): ?string
    {
        if ($key === $this->tokenKey && ++$this->reads === $this->afterReads) {
            $this->inner->set($key, $this->token->toJson(self::SEGREDO_CHECK), 3600);
        }
        return $this->inner->get($key);
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        $this->inner->set($key, $value, $ttlSeconds);
    }

    public function delete(string $key, ?string $accessToken = null): void
    {
        $this->inner->delete($key, $accessToken);
    }

    public function acquireLock(string $key, string $owner, int $ttlMilliseconds): bool
    {
        return $this->inner->acquireLock($key, $owner, $ttlMilliseconds);
    }

    public function releaseLock(string $key, string $owner): void
    {
        $this->inner->releaseLock($key, $owner);
    }
}
