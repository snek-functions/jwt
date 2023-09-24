import { AuthenticationInfo } from "./AuthenticationContext";

interface AuthenticationCacheData {
  authHeader: string;
  response: AuthenticationInfo;
  expiresAt: number;
}

export class AuthenticationCache {
  private cache: Map<string, AuthenticationCacheData>;

  constructor() {
    this.cache = new Map();
  }

  storeResponse(authHeader: string, response: AuthenticationInfo) {
    const expiresAt = new Date(response.expiresAt).getTime();

    this.cache.set(authHeader, { authHeader, response, expiresAt });
  }

  getCachedResponse(authHeader: string): AuthenticationInfo | null {
    const cachedData = this.cache.get(authHeader);

    if (cachedData && cachedData.expiresAt > Date.now()) {
      return cachedData.response;
    }
    return null; // Cache miss or expired token
  }
}
