using Ileva.SdkApiV3.Auth.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;

namespace Ileva.SdkApiV3.Auth;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registra o <see cref="IlevaSdkApiV3Auth"/> como singleton, para um único usuário de API.
    ///
    /// Onde o token fica guardado, nesta ordem: <see cref="IlevaAuthOptions.Store"/> ou
    /// <see cref="IlevaAuthOptions.Redis"/> definidos em <paramref name="configure"/>; um
    /// <see cref="ITokenStore"/> registrado na aplicação; o <see cref="IConnectionMultiplexer"/>
    /// registrado na aplicação, se houver; memória do processo.
    /// </summary>
    public static IServiceCollection AddIlevaAuth(this IServiceCollection services, Action<IlevaAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return services.AddIlevaAuth((_, options) => configure(options));
    }

    /// <inheritdoc cref="AddIlevaAuth(IServiceCollection, Action{IlevaAuthOptions})"/>
    public static IServiceCollection AddIlevaAuth(this IServiceCollection services, Action<IServiceProvider, IlevaAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.TryAddSingleton(provider =>
        {
            var options = new IlevaAuthOptions();
            configure(provider, options);

            if (options.Store is null && options.Redis is null)
            {
                options.Store = provider.GetService<ITokenStore>();
                if (options.Store is null)
                {
                    options.Redis = provider.GetService<IConnectionMultiplexer>()?.GetDatabase();
                }
            }

            return new IlevaSdkApiV3Auth(options);
        });
        return services;
    }
}
