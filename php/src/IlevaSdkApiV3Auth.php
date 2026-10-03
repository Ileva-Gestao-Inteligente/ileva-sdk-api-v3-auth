<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth;

use Closure;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use Ileva\SdkApiV3\Auth\Exception\ApiException;
use Ileva\SdkApiV3\Auth\Exception\AuthenticationException;
use Ileva\SdkApiV3\Auth\Exception\LockTimeoutException;
use Ileva\SdkApiV3\Auth\Exception\TransportException;
use Ileva\SdkApiV3\Auth\Store\InMemoryTokenStore;
use Ileva\SdkApiV3\Auth\Store\RedisTokenStore;
use Ileva\SdkApiV3\Auth\Store\TokenStore;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;

/**
 * Obtém o token de acesso da API Ileva e mantém sua validade.
 *
 * O token é guardado no store e reaproveitado enquanto for válido; perto de expirar, é renovado.
 * A API mantém um único token ativo por usuário — gerar um novo invalida o anterior —, então a
 * renovação é feita sob lock: só um processo pede o token e os outros esperam por ele no cache.
 *
 * O token em cache só é devolvido a quem informa a mesma senha que o gerou: junto dele fica um
 * verificador da senha (PBKDF2), e uma senha diferente faz o SDK consultar a API. Assim a
 * aplicação pode usar o SDK no login dos seus usuários sem que o cache aceite qualquer senha.
 *
 * Token obtido com código 2FA nunca é devolvido do cache: o SDK não tem como conferir o código (o
 * segredo fica no sistema Ileva), então cada uso vai à API com o código informado.
 */
final class IlevaSdkApiV3Auth
{
    public const DEFAULT_BASE_URL = 'https://api.ileva.com.br';

    private const PASSWORD_CHECK_ALGORITHM = 'pbkdf2-sha256';
    private const PASSWORD_CHECK_ITERATIONS = 100_000;
    // Um valor adulterado no cache não pode travar o processo com um número absurdo de iterações.
    private const PASSWORD_CHECK_MAX_ITERATIONS = 1_000_000;

    /**
     * Conferências de senha já feitas neste processo, por chave do token: o token conferido e um
     * HMAC da senha com uma chave aleatória do processo (nunca a senha). No PHP-FPM o worker
     * sobrevive entre requisições, então o PBKDF2 é pago uma vez por worker a cada token.
     *
     * @var array<string, array{accessToken: string, passwordDigest: string}>
     */
    private static array $verified = [];
    private static ?string $processSecret = null;

    private readonly string $baseUrl;
    private readonly TokenStore $store;
    private readonly ClientInterface $guzzle;
    private readonly string $tokenKey;
    private readonly string $lockKey;

    /**
     * Instâncias com a mesma app key e o mesmo usuário compartilham o token: sem Redis, pela lista
     * estática do InMemoryTokenStore (todo o processo); com Redis, entre processos e servidores.
     *
     * @param string $appKey Valor de Configurações > Integrações > API Integração no sistema Ileva.
     * @param string $username Usuário ou e-mail usado para entrar no sistema Ileva; o perfil precisa estar
     *                         liberado para acesso via API.
     * @param object|null $redis Conexão Redis da aplicação (\Redis, \RedisCluster ou \Predis\ClientInterface).
     *                           Sem Redis o token fica em memória estática, só neste processo.
     * @param ClientInterface|null $guzzle Cliente Guzzle da aplicação. Sem ele, é criado um cliente padrão.
     * @param TokenStore|null $store Store próprio, no lugar de `$redis`.
     * @param (Closure(): string)|null $twoFactorCode Chamado a cada geração de token, para usuários
     *                                              com autenticação em dois fatores.
     * @param int $refreshMargin Segundos antes da expiração em que o token passa a ser renovado.
     * @param float $timeout Timeout da requisição de token, em segundos.
     * @param float $lockWait Quanto tempo esperar, em segundos, por outro processo que esteja renovando.
     * @param string $keyPrefix Prefixo das chaves no Redis.
     */
    public function __construct(
        private readonly string $appKey,
        private readonly string $username,
        #[\SensitiveParameter] private readonly string $password,
        ?object $redis = null,
        ?ClientInterface $guzzle = null,
        ?TokenStore $store = null,
        string $baseUrl = self::DEFAULT_BASE_URL,
        private readonly ?Closure $twoFactorCode = null,
        private readonly int $refreshMargin = 300,
        private readonly float $timeout = 15.0,
        private readonly float $lockWait = 20.0,
        string $keyPrefix = 'ileva:auth',
    ) {
        if ($appKey === '' || $username === '' || $password === '') {
            throw new InvalidArgumentException('app key, usuário e senha são obrigatórios.');
        }
        if ($redis !== null && $store !== null) {
            throw new InvalidArgumentException('Informe $redis ou $store, não os dois.');
        }
        if ($refreshMargin < 0 || $timeout <= 0 || $lockWait <= 0) {
            throw new InvalidArgumentException('refreshMargin não pode ser negativo; timeout e lockWait devem ser positivos.');
        }

        $this->baseUrl = rtrim($baseUrl, '/');
        $this->store = $store ?? ($redis !== null ? new RedisTokenStore($redis) : new InMemoryTokenStore());
        $this->guzzle = $guzzle ?? new Client();

        // A chave identifica o token pelo ambiente, pela associação (app key) e pelo usuário — a
        // mesma combinação que a API usa para manter um token ativo. A senha fica fora, para que
        // uma troca de senha não deixe o token antigo órfão no cache. É o mesmo cálculo nos SDKs
        // das outras linguagens, para que todos compartilhem o token.
        // Minúsculas só em ASCII e trim só de " \t\n\r\v\0", iguais nos SDKs de todas as linguagens:
        // as funções nativas divergem em acentos e espaços Unicode (e o strtolower do PHP 8.1 depende
        // do locale), e a chave precisa ser a mesma para o token ser compartilhado.
        $hash = hash('sha256', self::asciiLower($this->baseUrl) . "\n" . $appKey . "\n" . self::asciiLower(trim($username, " \t\n\r\v\0")));
        $this->tokenKey = $keyPrefix . ':token:' . $hash;
        $this->lockKey = $keyPrefix . ':lock:' . $hash;
    }

    private static function asciiLower(string $value): string
    {
        return strtr($value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
    }

    /** Token de acesso válido, gerado ou renovado se necessário. */
    public function getToken(): string
    {
        return $this->resolveToken()->accessToken;
    }

    /** Valor pronto para o header Authorization, ex.: "Bearer eyJ...". */
    public function getAuthorizationHeader(): string
    {
        return $this->resolveToken()->authorizationHeader();
    }

    /** Token com o instante de expiração. */
    public function getTokenDetails(): Token
    {
        return $this->resolveToken();
    }

    /**
     * Descarta o token do cache, para que a próxima chamada gere outro. Chame ao receber 401 da API,
     * passando o token que foi recusado: se outro processo já o substituiu, o novo é preservado.
     */
    public function invalidate(?string $rejectedToken = null): void
    {
        $this->store->delete($this->tokenKey, $rejectedToken);
    }

    /** Gera um token novo mesmo que o atual ainda seja válido. */
    public function refresh(): string
    {
        $this->invalidate();
        return $this->getToken();
    }

    private function resolveToken(): Token
    {
        $cached = $this->readCachedToken();
        if ($cached !== null) {
            return $cached;
        }

        // Espera o suficiente para outro processo terminar a requisição de token (timeout) e, se
        // ele tiver morrido segurando o lock, para o lock expirar e ser obtido aqui.
        $lockTtlMs = (int) (($this->timeout + 5) * 1000);
        $deadline = microtime(true) + $this->lockWait;
        $pollIntervalUs = 100_000;

        do {
            $owner = bin2hex(random_bytes(16));
            if ($this->store->acquireLock($this->lockKey, $owner, $lockTtlMs)) {
                try {
                    // Outro processo pode ter renovado entre a leitura acima e a obtenção do lock.
                    return $this->readCachedToken() ?? $this->requestAndStoreToken();
                } finally {
                    $this->store->releaseLock($this->lockKey, $owner);
                }
            }

            usleep($pollIntervalUs);

            $cached = $this->readCachedToken();
            if ($cached !== null) {
                return $cached;
            }
        } while (microtime(true) < $deadline);

        throw new LockTimeoutException(sprintf(
            'O token não foi renovado por outro processo em %.0f segundos.',
            $this->lockWait,
        ));
    }

    /**
     * Token do cache, se ainda válido e gerado com a mesma senha informada nesta instância. Com
     * outra senha devolve null, como se o cache estivesse vazio: o SDK consulta a API, que recusa a
     * senha errada — e o token de quem acertou continua no cache.
     */
    private function readCachedToken(): ?Token
    {
        $value = $this->store->get($this->tokenKey);
        if ($value === null) {
            return null;
        }
        $token = Token::fromJson($value);
        if ($token === null || !$token->isValid(time(), $this->refreshMargin)) {
            return null;
        }
        // Servir do cache pularia o 2FA: quem soubesse só a senha receberia o token. Ele continua
        // gravado para substituir o token anterior do usuário, que a API invalidou ao gerar este.
        if ($token->twoFactor) {
            return null;
        }
        if ($this->isVerified($token)) {
            return $token;
        }
        $check = Token::passwordCheckFromJson($value);
        if ($check === null || !$this->passwordMatches($check)) {
            return null;
        }
        $this->markVerified($token);
        return $token;
    }

    private function requestAndStoreToken(): Token
    {
        $token = $this->requestToken();
        $this->store->set($this->tokenKey, $token->toJson($this->createPasswordCheck()), $token->expiresAt - time());
        $this->markVerified($token);
        return $token;
    }

    // A senha nunca é passada como argumento nos métodos abaixo, pelo mesmo motivo do post(): o
    // trace das exceções guarda os argumentos.

    private function createPasswordCheck(): string
    {
        $salt = random_bytes(16);
        $hash = hash_pbkdf2('sha256', $this->password, $salt, self::PASSWORD_CHECK_ITERATIONS, 32, true);
        return sprintf(
            '%s$%d$%s$%s',
            self::PASSWORD_CHECK_ALGORITHM,
            self::PASSWORD_CHECK_ITERATIONS,
            base64_encode($salt),
            base64_encode($hash),
        );
    }

    /** Um verificador fora do formato conta como senha diferente. */
    private function passwordMatches(string $check): bool
    {
        $parts = explode('$', $check);
        if (count($parts) !== 4 || $parts[0] !== self::PASSWORD_CHECK_ALGORITHM || !ctype_digit($parts[1])) {
            return false;
        }
        $iterations = (int) $parts[1];
        $salt = base64_decode($parts[2], true);
        $expected = base64_decode($parts[3], true);
        if ($iterations < 1 || $iterations > self::PASSWORD_CHECK_MAX_ITERATIONS || $salt === false || $salt === '' || $expected === false || $expected === '') {
            return false;
        }
        $actual = hash_pbkdf2('sha256', $this->password, $salt, $iterations, strlen($expected), true);
        return hash_equals($expected, $actual);
    }

    private function isVerified(Token $token): bool
    {
        $entry = self::$verified[$this->tokenKey] ?? null;
        return $entry !== null
            && $entry['accessToken'] === $token->accessToken
            && hash_equals($entry['passwordDigest'], $this->passwordDigest());
    }

    private function markVerified(Token $token): void
    {
        self::$verified[$this->tokenKey] = ['accessToken' => $token->accessToken, 'passwordDigest' => $this->passwordDigest()];
    }

    private function passwordDigest(): string
    {
        self::$processSecret ??= random_bytes(32);
        return hash_hmac('sha256', $this->password, self::$processSecret, true);
    }

    private function requestToken(): Token
    {
        $requestedAt = time();
        $response = $this->post($this->baseUrl . '/oauth/token');
        $status = $response->getStatusCode();
        $data = json_decode((string) $response->getBody(), true);

        if ($status !== 200) {
            $message = is_array($data) && isset($data['mensagem']) && is_string($data['mensagem'])
                ? $data['mensagem']
                : sprintf('A API respondeu HTTP %d ao gerar o token.', $status);
            if ($status === 401) {
                throw new AuthenticationException($message, 401);
            }
            throw new ApiException($message, $status);
        }

        if (
            !is_array($data)
            || !isset($data['access_token'], $data['expires_in'])
            || !is_string($data['access_token'])
            || !is_numeric($data['expires_in'])
        ) {
            throw new ApiException('Resposta de token fora do formato esperado.', $status);
        }

        $tokenType = isset($data['token_type']) && is_string($data['token_type']) ? $data['token_type'] : 'Bearer';

        // Conta a validade a partir do envio, não da resposta: assim o tempo de rede nunca faz o
        // SDK achar que o token vale mais do que a API considera.
        return new Token($data['access_token'], $tokenType, $requestedAt + (int) $data['expires_in'], $this->twoFactorCode !== null);
    }

    /**
     * A senha e a app key nunca são passadas como argumento de função, nem daqui nem para o Guzzle:
     * com `zend.exception_ignore_args` desligado, o trace das exceções guarda os argumentos, e
     * ferramentas como o Sentry os enviam. Dentro de um objeto Request elas aparecem só como o nome
     * da classe.
     */
    private function post(string $url): ResponseInterface
    {
        $request = new Request('POST', $url, [
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'app_key' => $this->appKey,
        ], $this->encodeCredentials());

        try {
            return $this->guzzle->send($request, [
                'timeout' => $this->timeout,
                'connect_timeout' => $this->timeout,
                // O status é tratado acima, para devolver a mensagem da API na exceção certa.
                'http_errors' => false,
            ]);
        } catch (RequestException $e) {
            // Um middleware do cliente da aplicação ainda pode lançar exceção com resposta.
            if ($e->hasResponse()) {
                return $e->getResponse();
            }
            throw new TransportException(sprintf('Falha ao conectar em %s: %s', $url, $e->getMessage()), 0, $e);
        } catch (GuzzleException $e) {
            throw new TransportException(sprintf('Falha ao conectar em %s: %s', $url, $e->getMessage()), 0, $e);
        }
    }

    private function encodeCredentials(): string
    {
        $body = ['username' => $this->username, 'password' => $this->password];
        if ($this->twoFactorCode !== null) {
            $body['two_fa'] = ($this->twoFactorCode)();
        }

        try {
            return json_encode($body, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // Sem a exceção original: o trace dela guardaria o array com a senha.
            throw new InvalidArgumentException('Usuário, senha ou código 2FA com caracteres que não são UTF-8 válido.');
        }
    }

    /** Oculta a senha e a app key em var_dump, print_r e serializadores de erro. */
    public function __debugInfo(): array
    {
        return [
            'baseUrl' => $this->baseUrl,
            'username' => $this->username,
            'appKey' => '***',
            'password' => '***',
            'store' => $this->store::class,
            'refreshMargin' => $this->refreshMargin,
            'timeout' => $this->timeout,
            'lockWait' => $this->lockWait,
        ];
    }
}
