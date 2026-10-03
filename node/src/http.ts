/** Resposta da requisição de token, independente do cliente HTTP usado. */
export interface HttpResponse {
  status: number;
  body: string;
}

/**
 * Envia a requisição de token. Resolve com qualquer status HTTP; rejeita só quando não há resposta
 * (rede, DNS, TLS, cancelamento pelo `signal`).
 */
export type HttpPost = (
  url: string,
  headers: Record<string, string>,
  body: string,
  signal: AbortSignal,
) => Promise<HttpResponse>;

/** Instância do axios (`axios` ou `axios.create()`). Tipo estrutural: o SDK não depende do axios. */
export interface AxiosLike {
  request(config: {
    method: 'post';
    url: string;
    headers: Record<string, string>;
    data: string;
    signal: AbortSignal;
    responseType: 'text';
    transformResponse: ((data: unknown) => unknown)[];
    validateStatus: (status: number) => boolean;
  }): Promise<{ status: number; data: unknown }>;
}

export function fetchPost(fetchImpl: typeof fetch): HttpPost {
  return async (url, headers, body, signal) => {
    const response = await fetchImpl(url, { method: 'POST', headers, body, signal });
    return { status: response.status, body: await response.text() };
  };
}

export function axiosPost(axios: AxiosLike): HttpPost {
  return async (url, headers, body, signal) => {
    try {
      const response = await axios.request({
        method: 'post',
        url,
        headers,
        data: body,
        signal,
        // Texto cru e qualquer status: a interpretação da resposta é a mesma do fetch.
        responseType: 'text',
        transformResponse: [(data) => data],
        validateStatus: () => true,
      });
      return { status: response.status, body: stringify(response.data) };
    } catch (error) {
      // Um interceptor da instância da aplicação ainda pode lançar erro com resposta.
      const response = (error as { response?: { status?: unknown; data?: unknown } }).response;
      if (typeof response?.status === 'number') {
        return { status: response.status, body: stringify(response.data) };
      }
      // O AxiosError carrega o `config` da requisição — com o body, e a senha nele. Por isso ele
      // não é repassado: só a mensagem e o código chegam ao erro do SDK.
      const { message, code } = error as { message?: unknown; code?: unknown };
      throw Object.assign(new Error(typeof message === 'string' ? message : 'Falha na requisição'), {
        code: typeof code === 'string' ? code : undefined,
      });
    }
  };
}

function stringify(data: unknown): string {
  if (typeof data === 'string') {
    return data;
  }
  if (data instanceof Uint8Array) {
    return Buffer.from(data).toString('utf8');
  }
  return data === undefined || data === null ? '' : JSON.stringify(data);
}
