/**
 * Token de acesso da API Ileva.
 *
 * O formato serializado (toJsonString) é o contrato gravado no cache: os SDKs de PHP e Node leem e
 * gravam o mesmo JSON, para que serviços em linguagens diferentes compartilhem o mesmo token.
 */
export class Token {
  constructor(
    readonly accessToken: string,
    readonly tokenType: string,
    /** Instante de expiração, em segundos Unix. */
    readonly expiresAt: number,
    /** Obtido com código de autenticação em dois fatores: nunca é devolvido do cache. */
    readonly twoFactor = false,
  ) {}

  /**
   * O token é considerado válido até `refreshMarginSeconds` antes de expirar, para que uma
   * requisição iniciada perto do fim da validade não chegue à API com ele já vencido.
   */
  isValid(nowSeconds: number, refreshMarginSeconds = 0): boolean {
    return nowSeconds < this.expiresAt - refreshMarginSeconds;
  }

  authorizationHeader(): string {
    return `${this.tokenType} ${this.accessToken}`;
  }

  /**
   * @param passwordCheck Verificador da senha que gerou o token (veja o contrato do cache). O SDK
   *                      sempre grava com ele.
   */
  toJsonString(passwordCheck?: string): string {
    return JSON.stringify({
      access_token: this.accessToken,
      token_type: this.tokenType,
      expires_at: this.expiresAt,
      ...(passwordCheck !== undefined ? { password_check: passwordCheck } : {}),
      ...(this.twoFactor ? { two_factor: true } : {}),
    });
  }

  /** Verificador da senha gravado junto do token, ou null se não houver. */
  static passwordCheckFromJsonString(json: string): string | null {
    try {
      const data: unknown = JSON.parse(json);
      const check = typeof data === 'object' && data !== null ? (data as Record<string, unknown>).password_check : null;
      return typeof check === 'string' ? check : null;
    } catch {
      return null;
    }
  }

  /** Devolve null para um valor corrompido ou em outro formato, que é tratado como cache vazio. */
  static fromJsonString(json: string): Token | null {
    let data: unknown;
    try {
      data = JSON.parse(json);
    } catch {
      return null;
    }
    if (typeof data !== 'object' || data === null) {
      return null;
    }
    const { access_token, token_type, expires_at, two_factor } = data as Record<string, unknown>;
    if (typeof access_token !== 'string' || !Number.isInteger(expires_at)) {
      return null;
    }
    return new Token(
      access_token,
      typeof token_type === 'string' ? token_type : 'Bearer',
      expires_at as number,
      two_factor === true,
    );
  }
}
