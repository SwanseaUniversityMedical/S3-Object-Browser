import { Api, HttpResponse, FullRequestParams, ApiError } from "./consoleApi";

export function CommonAPIValidation<D, E>(
  res: HttpResponse<D, E>,
): HttpResponse<D, E> {
  const err = res.error as ApiError;
  
  // Handle expired or invalid session - redirect to login
  if (res.status === 401 || (res.status === 403 && err && err.message === "invalid session")) {
    if (window.location.pathname !== "/login") {
      document.location = "/login";
    }
  }
  
  return res;
}

export let api = new Api();
api.baseUrl = `${new URL(document.baseURI).pathname}api/v1`;
const internalRequestFunc = api.request;
api.request = async <T = any, E = any>({
  body,
  secure,
  path,
  type,
  query,
  format,
  baseUrl,
  cancelToken,
  ...params
}: FullRequestParams): Promise<HttpResponse<T, E>> => {
  const internalResp = internalRequestFunc({
    body,
    secure,
    path,
    type,
    query,
    format,
    baseUrl,
    cancelToken,
    ...params,
  });
  return internalResp.then((e) => CommonAPIValidation(e));
};
