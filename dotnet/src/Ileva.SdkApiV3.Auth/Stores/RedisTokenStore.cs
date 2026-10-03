using StackExchange.Redis;

namespace Ileva.SdkApiV3.Auth.Stores;

/// <summary>
/// Store em Redis, compartilhado entre processos e servidores.
///
/// Recebe por injeção o <see cref="IDatabase"/> que a aplicação já usa (StackExchange.Redis). Cada
/// operação usa uma única chave, então funciona em cluster. Os valores são texto puro, no mesmo
/// formato dos SDKs de PHP, Node e Python.
/// </summary>
public sealed class RedisTokenStore : ITokenStore
{
    // Comparar e apagar precisa ser atômico: entre um GET e um DEL feitos pelo cliente, o lock
    // pode expirar e ser obtido por outro processo, e o DEL apagaria o lock alheio.
    private const string ReleaseLockScript = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """;

    // ARGV[1] vazio apaga incondicionalmente. Valor que não é JSON válido também é apagado.
    private const string DeleteTokenScript = """
        local value = redis.call('GET', KEYS[1])
        if not value then
            return 0
        end
        if ARGV[1] == '' then
            return redis.call('DEL', KEYS[1])
        end
        local ok, token = pcall(cjson.decode, value)
        if not ok or type(token) ~= 'table' or token.access_token == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """;

    private readonly IDatabase _database;

    public RedisTokenStore(IDatabase database)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
    }

    public async Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        var value = await _database.StringGetAsync(key).WaitAsync(cancellationToken).ConfigureAwait(false);
        return value.IsNull ? null : (string?)value;
    }

    public async Task SetAsync(string key, string value, long ttlSeconds, CancellationToken cancellationToken = default)
    {
        var ttl = TimeSpan.FromSeconds(Math.Max(1, ttlSeconds));
        await _database.StringSetAsync(key, value, ttl).WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(string key, string? accessToken = null, CancellationToken cancellationToken = default)
    {
        await _database
            .ScriptEvaluateAsync(DeleteTokenScript, new RedisKey[] { key }, new RedisValue[] { accessToken ?? string.Empty })
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> AcquireLockAsync(string key, string owner, long ttlMilliseconds, CancellationToken cancellationToken = default)
    {
        var ttl = TimeSpan.FromMilliseconds(Math.Max(1, ttlMilliseconds));
        return await _database.StringSetAsync(key, owner, ttl, When.NotExists).WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ReleaseLockAsync(string key, string owner, CancellationToken cancellationToken = default)
    {
        await _database
            .ScriptEvaluateAsync(ReleaseLockScript, new RedisKey[] { key }, new RedisValue[] { owner })
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
    }
}
