<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth;

/**
 * Token de acesso da API Ileva.
 *
 * O formato serializado (toJson) é o contrato gravado no cache: os SDKs de PHP e Node leem e
 * gravam o mesmo JSON, para que serviços em linguagens diferentes compartilhem o mesmo token.
 */
final class Token
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $tokenType,
        /** Instante de expiração, em segundos Unix. */
        public readonly int $expiresAt,
        /** Obtido com código de autenticação em dois fatores: nunca é devolvido do cache. */
        public readonly bool $twoFactor = false,
    ) {
    }

    /**
     * O token é considerado válido até `$refreshMargin` segundos antes de expirar, para que uma
     * requisição iniciada perto do fim da validade não chegue à API com ele já vencido.
     */
    public function isValid(int $now, int $refreshMargin = 0): bool
    {
        return $now < $this->expiresAt - $refreshMargin;
    }

    public function authorizationHeader(): string
    {
        return $this->tokenType . ' ' . $this->accessToken;
    }

    /**
     * @param string|null $passwordCheck Verificador da senha que gerou o token (veja o contrato do
     *                                   cache). O SDK sempre grava com ele.
     */
    public function toJson(?string $passwordCheck = null): string
    {
        $data = [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_at' => $this->expiresAt,
        ];
        if ($passwordCheck !== null) {
            $data['password_check'] = $passwordCheck;
        }
        if ($this->twoFactor) {
            $data['two_factor'] = true;
        }
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /** Verificador da senha gravado junto do token, ou null se não houver. */
    public static function passwordCheckFromJson(string $json): ?string
    {
        $data = json_decode($json, true);
        return is_array($data) && isset($data['password_check']) && is_string($data['password_check'])
            ? $data['password_check']
            : null;
    }

    /** Devolve null para um valor corrompido ou em outro formato, que é tratado como cache vazio. */
    public static function fromJson(string $json): ?self
    {
        $data = json_decode($json, true);
        if (
            !is_array($data)
            || !isset($data['access_token'], $data['expires_at'])
            || !is_string($data['access_token'])
            || !is_int($data['expires_at'])
        ) {
            return null;
        }

        $tokenType = isset($data['token_type']) && is_string($data['token_type']) ? $data['token_type'] : 'Bearer';

        return new self($data['access_token'], $tokenType, $data['expires_at'], ($data['two_factor'] ?? false) === true);
    }
}
